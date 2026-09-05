"""The volatile fixes: WiFi power save / PCIe ASPM, buffer tuning, CAKE.

All appliers are blocking (subprocess + sysfs I/O) - async callers run them
via asyncio.to_thread. On apply they snapshot the machine's real prior state
into settings, and on revert they restore that snapshot instead of assuming
kernel defaults (FUNC-06).
"""

import os

from . import settings as settings_store
from .constants import (
    CAKE_QDISC_ARGS,
    DRIVER_PROFILES,
    MODPROBE_CONF_PATH,
    SYSCTL_DEFAULTS,
    SYSCTL_PARAMS,
    TXQ_CAKE,
    TXQ_DEFAULT,
    TXQ_TUNED,
)
from .deckyshim import decky


class AppliersMixin:
    # When streaming_mode_enabled is on, the volatile fixes are only held
    # active while a detected streaming app is running; outside of that the
    # system stays on stock settings. The gate below is the single source of
    # truth for whether those fixes may currently be applied.
    # Reconnect-triggering settings (BSSID lock, band, DNS, IPv6) are
    # deliberately NOT gated - toggling them mid-session would drop the
    # connection the stream is running on.

    def _volatile_gate_open(self, settings: dict | None = None) -> bool:
        s = settings if settings is not None else settings_store.load_settings()
        return (not s.get("streaming_mode_enabled", False)) or s.get(
            "streaming_active", False
        )

    def _txq_off_value(self, settings: dict) -> str:
        """txqueuelen to restore when tuning/CAKE turn off: the snapshotted
        pre-plugin value if one exists, else the kernel default."""
        snap = (settings.get("txqueuelen_snapshot") or "").strip()
        if snap and snap not in (TXQ_TUNED, TXQ_CAKE):
            return snap
        return TXQ_DEFAULT

    def _apply_driver_fixes(self, enable: bool):
        """Apply or revert driver-specific power save fixes from DRIVER_PROFILES.
        Silently no-ops for drivers with no sysfs paths or modprobe options.
        On apply, current sysfs values are snapshotted so revert restores the
        machine's real prior state instead of assuming module defaults."""
        settings = settings_store.load_settings()
        profile = DRIVER_PROFILES.get(settings.get("driver"), {})
        snap = settings.get("pcie_snapshot") or {}

        if enable:
            entries = {}
            for path in profile.get("sysfs_power_fixes", []):
                try:
                    with open(path, "r") as f:
                        cur = f.read().strip()
                    # Don't snapshot our own target value (e.g. the dispatcher
                    # already applied it) - fall back to module default then.
                    if cur != "Y":
                        entries[path] = cur
                except Exception:
                    pass
            settings_store.merge_snapshot("pcie_snapshot", entries)
        for path in profile.get("sysfs_power_fixes", []):
            val = "Y" if enable else snap.get(path, "N")
            try:
                with open(path, "w") as f:
                    f.write(val)
            except FileNotFoundError:
                pass
            except PermissionError:
                decky.logger.info(f"sysfs path not writable: {path}")

        options = profile.get("modprobe_options", [])
        if enable and options:
            try:
                os.makedirs(os.path.dirname(MODPROBE_CONF_PATH), exist_ok=True)
                with open(MODPROBE_CONF_PATH, "w") as f:
                    f.write("# WiFi Optimizer - driver power save fixes\n")
                    for opt in options:
                        f.write(opt + "\n")
            except Exception as e:
                decky.logger.error(f"Failed to write modprobe config: {e}")
        elif not enable:
            try:
                os.remove(MODPROBE_CONF_PATH)
            except FileNotFoundError:
                pass

    def _apply_pcie_aspm_fix(self, enable: bool):
        """Disable or restore PCIe ASPM for the WiFi device.
        Prevents throughput degradation during sustained streaming.
        Works on all PCIe-attached WiFi adapters. Pre-apply values are
        snapshotted so revert restores what the machine actually had instead
        of hardcoded defaults (FUNC-06)."""
        try:
            # Discover WiFi PCI device path dynamically
            iface = self._get_wifi_interface()
            if not iface:
                return
            device_link = os.path.realpath(f"/sys/class/net/{iface}/device")
            if not os.path.isdir(device_link):
                return

            settings = settings_store.load_settings()
            snap = settings.get("pcie_snapshot") or {}
            aspm_files = ["l0s_aspm", "l1_aspm", "l1_1_aspm", "l1_2_aspm",
                          "l1_1_pcipm", "l1_2_pcipm"]
            link_dir = os.path.join(device_link, "link")
            power_control = os.path.join(device_link, "power", "control")

            if enable:
                entries = {}
                if os.path.isdir(link_dir):
                    for aspm_file in aspm_files:
                        path = os.path.join(link_dir, aspm_file)
                        try:
                            with open(path, "r") as f:
                                cur = f.read().strip()
                            if cur != "0":
                                entries[path] = cur
                        except Exception:
                            pass
                try:
                    with open(power_control, "r") as f:
                        cur = f.read().strip()
                    if cur != "on":
                        entries[power_control] = cur
                except Exception:
                    pass
                settings_store.merge_snapshot("pcie_snapshot", entries)

            # Disable/restore PCIe ASPM L-states
            if os.path.isdir(link_dir):
                for aspm_file in aspm_files:
                    path = os.path.join(link_dir, aspm_file)
                    val = "0" if enable else snap.get(path, "1")
                    try:
                        with open(path, "w") as f:
                            f.write(val)
                    except (FileNotFoundError, PermissionError):
                        pass

            # Disable/restore PCI runtime power management
            try:
                with open(power_control, "w") as f:
                    f.write("on" if enable else snap.get(power_control, "auto"))
            except (FileNotFoundError, PermissionError):
                pass

            if enable:
                decky.logger.info(f"PCIe ASPM disabled for {device_link}")
            else:
                # Snapshot consumed (driver fixes restore before this runs in
                # _apply_power_save_now); clear it so the next apply captures
                # the then-current state fresh.
                settings_store.update_settings_fields(pcie_snapshot={})
                decky.logger.info(f"PCIe ASPM restored for {device_link}")
        except Exception as e:
            decky.logger.error(f"PCIe ASPM fix error: {e}")

    def _apply_power_save_now(self, off: bool) -> dict:
        """Apply (off=True) or revert (off=False) the runtime power save state:
        iw power_save, driver-specific fixes, PCIe ASPM. Does not persist."""
        iface = self._get_wifi_interface()
        if iface:
            state = "off" if off else "on"
            result = self._run_cmd(
                ["/usr/bin/iw", "dev", iface, "set", "power_save", state]
            )
            if not result["success"]:
                return {
                    "success": False,
                    "error": "iw_failed",
                    "message": "Couldn't change WiFi power save",
                    "detail": result["stderr"],
                }
        self._apply_driver_fixes(off)
        self._apply_pcie_aspm_fix(off)
        return {"success": True}

    def _apply_buffer_tuning_now(self, on: bool, settings: dict | None = None):
        """Apply tuned sysctl values and txqueuelen, or restore the
        snapshotted pre-apply values (kernel defaults as fallback). Does not
        persist the feature flag."""
        s = settings if settings is not None else settings_store.load_settings()
        iface = self._get_wifi_interface()
        if on:
            # Snapshot what the system currently runs with, so disabling the
            # feature restores distro/user tuning instead of assuming kernel
            # defaults (FUNC-06). Values already at our tuned target are not
            # snapshotted - they would just re-pin our own values.
            entries = {}
            for key, tuned in SYSCTL_PARAMS.items():
                cur = self._run_cmd(["/usr/bin/sysctl", "-n", key]).get("stdout", "").strip()
                if cur and cur != tuned:
                    entries[key] = cur
            settings_store.merge_snapshot("sysctl_snapshot", entries)
            if iface and not (settings_store.load_settings().get("txqueuelen_snapshot") or "").strip():
                try:
                    with open(f"/sys/class/net/{iface}/tx_queue_len", "r") as f:
                        cur_txq = f.read().strip()
                    if cur_txq and cur_txq not in (TXQ_TUNED, TXQ_CAKE):
                        settings_store.update_settings_fields(txqueuelen_snapshot=cur_txq)
                except Exception:
                    pass
            params = dict(SYSCTL_PARAMS)
        else:
            snap = settings_store.load_settings().get("sysctl_snapshot") or {}
            params = {k: snap.get(k, SYSCTL_DEFAULTS[k]) for k in SYSCTL_PARAMS}
        for key, value in params.items():
            result = self._run_cmd(["/usr/bin/sysctl", "-w", f"{key}={value}"])
            if not result["success"]:
                decky.logger.error(f"sysctl {key}={value} failed: {result['stderr']}")
        if iface:
            # CAKE manages its own queue; keep txqueuelen at 256 while it is
            # active so the two features don't fight over the value.
            cake_active = s.get("cake_enabled") and self._volatile_gate_open(s)
            if cake_active:
                txq = TXQ_CAKE
            else:
                txq = TXQ_TUNED if on else self._txq_off_value(settings_store.load_settings())
            self._run_cmd(["/usr/bin/ip", "link", "set", iface, "txqueuelen", txq])
        if not on:
            # Restored; clear so the next enable snapshots fresh state.
            settings_store.update_settings_fields(sysctl_snapshot={}, txqueuelen_snapshot="")

    def _get_cake_status(self, iface: str) -> bool:
        """Check if CAKE qdisc is active on the interface."""
        result = self._run_cmd(["/usr/bin/tc", "qdisc", "show", "dev", iface])
        return "cake" in result.get("stdout", "")

    def _apply_cake_now(self, on: bool, settings: dict | None = None) -> dict:
        """Install or remove the CAKE qdisc. Does not persist."""
        s = settings if settings is not None else settings_store.load_settings()
        iface = self._get_wifi_interface()
        if not iface:
            return {"success": False, "error": "no_wifi", "message": "Not connected to WiFi."}
        if on:
            modprobe = "/usr/bin/modprobe" if os.path.isfile("/usr/bin/modprobe") else "/usr/sbin/modprobe"
            self._run_cmd([modprobe, "sch_cake"], timeout=5)
            result = self._run_cmd(
                ["/usr/bin/tc", "qdisc", "replace", "dev", iface, "root", *CAKE_QDISC_ARGS]
            )
            if not result["success"]:
                return {
                    "success": False,
                    "error": "unexpected",
                    "message": "Failed to apply CAKE qdisc.",
                    "detail": result.get("stderr", ""),
                }
            self._run_cmd(["/usr/bin/ip", "link", "set", iface, "txqueuelen", TXQ_CAKE])
        else:
            self._run_cmd(["/usr/bin/tc", "qdisc", "del", "dev", iface, "root"])
            buffer_active = s.get("buffer_tuning_enabled") and self._volatile_gate_open(s)
            txq = TXQ_TUNED if buffer_active else self._txq_off_value(s)
            self._run_cmd(["/usr/bin/ip", "link", "set", iface, "txqueuelen", txq])
        return {"success": True}

    def _apply_streaming_profile(self, active: bool):
        """Apply (stream started) or revert (stream ended) every volatile fix
        the user has enabled. Called by the watcher on state transitions and
        by set_streaming_mode when the mode itself is toggled. Blocking
        (many subprocess calls) - callers run it via asyncio.to_thread."""
        settings = settings_store.load_settings()
        if settings.get("buffer_tuning_enabled"):
            self._apply_buffer_tuning_now(active, settings)
        if settings.get("cake_enabled"):
            self._apply_cake_now(active, settings)
        if settings.get("power_save_disabled"):
            self._apply_power_save_now(active)

    def _revert_runtime_state(self):
        """Revert every runtime optimization that is currently enabled,
        restoring snapshotted pre-plugin values where available. Disabled
        features are left untouched so we never stomp on distro or user
        tuning the plugin didn't change (FUNC-06)."""
        settings = settings_store.load_settings()
        if settings.get("cake_enabled"):
            self._apply_cake_now(False, settings)
        if settings.get("buffer_tuning_enabled"):
            # CAKE is gone at this point; don't let its txqueuelen win.
            s2 = dict(settings)
            s2["cake_enabled"] = False
            self._apply_buffer_tuning_now(False, s2)
        if settings.get("power_save_disabled"):
            self._apply_power_save_now(False)
