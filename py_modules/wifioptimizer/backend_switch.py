"""WiFi backend switching (iwd <-> wpa_supplicant).

SteamOS goes through Valve's privileged helper; other distros write the NM
config and drive systemd units directly. Progress is exposed to the UI via a
phase state machine polled through get_backend_switch_status.
"""

import asyncio
import os
import time

from . import settings as settings_store
from .constants import (
    BACKEND_HELPER,
    BAZZITE_IWD_CONF,
    GENERIC_BACKEND_CONF,
    NM_DEFAULT_CONF,
    WIFI_BACKEND_CONF,
)
from .deckyshim import decky


class BackendSwitchMixin:
    def _get_backend_method(self) -> str:
        """Return 'steamos', 'generic', or 'none'.
        SteamOS has a privileged helper. Generic uses NM conf + systemctl
        directly and requires iwd to be installed. Non-SteamOS distros
        always use generic even if the SteamOS helper exists (it may
        behave differently on Bazzite/CachyOS)."""
        settings = settings_store.load_settings()
        distro = settings.get("distro_id", "unknown")
        if distro == "steamos" and os.path.isfile(BACKEND_HELPER) and os.access(BACKEND_HELPER, os.X_OK):
            return "steamos"
        if os.path.isfile("/usr/lib/systemd/system/iwd.service"):
            return "generic"
        return "none"

    def _has_backend_tool(self) -> bool:
        return self._get_backend_method() != "none"

    def _backend_unit_available(self, name: str) -> bool:
        """Check whether a backend's systemd unit exists at all."""
        for base in (
            "/usr/lib/systemd/system",
            "/etc/systemd/system",
            "/lib/systemd/system",
        ):
            if os.path.isfile(os.path.join(base, f"{name}.service")):
                return True
        return False

    def _backend_service_active(self, name: str) -> bool:
        result = self._run_cmd(["/usr/bin/systemctl", "is-active", name], timeout=3)
        return (result.get("stdout") or "").strip() == "active"

    def _get_current_backend(self) -> str | None:
        """Return 'iwd', 'wpa_supplicant', or None if unknown.

        Checks config files in priority order: our own generic conf, Bazzite's
        iwd conf, SteamOS override, SteamOS defaults. Falls back to checking
        which systemd service is active.
        """
        for path in (
            GENERIC_BACKEND_CONF,
            BAZZITE_IWD_CONF,
            WIFI_BACKEND_CONF,
            NM_DEFAULT_CONF,
        ):
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith(";"):
                            continue
                        if line.startswith("wifi.backend"):
                            _, _, val = line.partition("=")
                            val = val.strip()
                            if val in ("iwd", "wpa_supplicant"):
                                return val
            except FileNotFoundError:
                continue
            except Exception:
                continue
        # No config found — check which service is running
        result = self._run_cmd(["/usr/bin/systemctl", "is-active", "iwd"], timeout=3)
        if result.get("stdout", "").strip() == "active":
            return "iwd"
        result = self._run_cmd(
            ["/usr/bin/systemctl", "is-active", "wpa_supplicant"], timeout=3
        )
        if result.get("stdout", "").strip() == "active":
            return "wpa_supplicant"
        return None

    def _ensure_backend_switch_state(self):
        if not hasattr(self, "_backend_switch"):
            self._backend_switch = {
                "in_progress": False,
                "phase": "idle",
                "target": None,
                "started_at": 0,
                "result": None,
            }

    def _friendly_backend_error(self, detail: str) -> str:
        """Rewrite raw stderr into user-friendly guidance for common failures.
        Returns a one-line explanation; callers pass the raw detail separately
        so the technical text is still available to the UI/logs."""
        d = (detail or "").lower()
        if "symbol lookup error" in d or "undefined symbol" in d:
            return "A system-library conflict occurred. Please reboot and try again."
        if "permission denied" in d:
            return "The system denied permission. Try rebooting."
        if "command not found" in d or "no such file" in d:
            return "A required system tool is missing. Your OS version may not be supported."
        if "timed out" in d or "timeout" in d:
            return "The system didn't respond in time. Try again in a moment."
        if "network is unreachable" in d or "connection refused" in d:
            return "Network problem during the switch. Check WiFi and try again."
        return "The WiFi backend switch didn't take effect."

    # ---- Switch execution ----
    #
    # Both switch methods (SteamOS helper vs. generic NM-conf + systemd) share
    # the same frame: phase transitions, the reconnect wait, runtime
    # verification (FUNC-04), result assembly, and the cancel/error handling.
    # _run_backend_switch owns that frame; the per-method `step` coroutine
    # only performs the actual switch and reports what happened via a dict:
    #
    #   {"failed_early": True, "message": ..., "detail": ...}
    #     terminal failure before/while switching - frame records it and stops
    #   {"failed_early": False, "restart_ok": bool, "detail": str,
    #    "recovery_performed": bool, "needs_reboot": bool}
    #     switch commands ran; frame waits for reconnect, verifies, reports

    async def _steamos_switch_step(self, target: str, other: str) -> dict:
        """Switch via Valve's privileged helper, invoked directly (at
        /usr/bin/steamos-polkit-helpers/…) to bypass pkexec, which fails from
        a rootful systemd context with no polkit agent. The helper handles
        wlan0 recovery on ath11k devices internally; we parse its output to
        report whether recovery fired."""
        settings = settings_store.load_settings()
        has_wlan0_quirk = settings.get("driver") == "ath11k_pci"

        # clean_env=True clears LD_LIBRARY_PATH so bash doesn't hit a symbol
        # lookup error against Decky's bundled readline (same class of bug
        # as the curl/OpenSSL conflict).
        decky.logger.info(
            f"backend switch: calling helper write_config target={target} "
            f"(euid={os.geteuid()}, helper={BACKEND_HELPER})"
        )
        write_result = await asyncio.to_thread(
            self._run_cmd, [BACKEND_HELPER, "write_config", target], 5, True
        )
        decky.logger.info(
            f"backend switch: write_config result rc={write_result.get('returncode')} "
            f"stdout={write_result.get('stdout', '')[:200]!r} "
            f"stderr={write_result.get('stderr', '')[:200]!r}"
        )
        if not write_result["success"]:
            detail = (write_result.get("stderr") or write_result.get("stdout") or "")[:200]
            decky.logger.error(
                f"backend switch failed at write_config: rc={write_result.get('returncode')}, "
                f"detail={detail!r}"
            )
            return {
                "failed_early": True,
                "message": self._friendly_backend_error(detail),
                "detail": detail,
            }

        restart_result = await asyncio.to_thread(
            self._run_cmd, [BACKEND_HELPER, "restart_units", other], 45, True
        )
        rs_stdout = restart_result.get("stdout", "")
        rs_stderr = restart_result.get("stderr", "")
        recovery_performed = "missing wlan0" in rs_stdout
        needs_reboot = "wlan0 could not be created" in rs_stderr

        await asyncio.sleep(1)
        if has_wlan0_quirk and target == "wpa_supplicant":
            iface_check = await asyncio.to_thread(self._get_wifi_interface)
            if iface_check != "wlan0":
                needs_reboot = True

        return {
            "failed_early": False,
            "restart_ok": restart_result["success"],
            "detail": rs_stderr[:200] or rs_stdout[:200],
            "recovery_performed": recovery_performed,
            "needs_reboot": needs_reboot,
        }

    async def _generic_switch_step(self, target: str, other: str) -> dict:
        """Switch for non-SteamOS systems (Bazzite, CachyOS, etc.): write the
        NM config directly and manage the systemd services."""
        # Fail fast if the target service doesn't exist on this distro -
        # otherwise we'd write the NM config, kill the working backend,
        # and only find out afterwards (FUNC-04).
        if not await asyncio.to_thread(self._backend_unit_available, target):
            return {
                "failed_early": True,
                "message": f"The {target} service is not installed on this system.",
                "detail": "",
            }

        decky.logger.info(f"generic backend switch: {other} -> {target}")

        os.makedirs(os.path.dirname(GENERIC_BACKEND_CONF), exist_ok=True)
        if target == "iwd":
            with open(GENERIC_BACKEND_CONF, "w") as f:
                f.write("[device]\nwifi.backend=iwd\nwifi.iwd.autoconnect=yes\n")
        else:
            with open(GENERIC_BACKEND_CONF, "w") as f:
                f.write("[device]\nwifi.backend=wpa_supplicant\n")

        # Stop old, enable + start new, restart NM
        for cmd in [
            ["/usr/bin/systemctl", "stop", other],
            ["/usr/bin/systemctl", "disable", other],
            ["/usr/bin/systemctl", "enable", target],
            ["/usr/bin/systemctl", "start", target],
        ]:
            await asyncio.to_thread(self._run_cmd, cmd, 10, True)

        restart = await asyncio.to_thread(
            self._run_cmd,
            ["/usr/bin/systemctl", "restart", "NetworkManager"],
            15,
            True,
        )
        if not restart["success"]:
            detail = restart.get("stderr", "")[:200]
            return {
                "failed_early": True,
                "message": self._friendly_backend_error(detail),
                "detail": detail,
            }

        return {
            "failed_early": False,
            "restart_ok": True,
            "detail": "",
            "recovery_performed": False,
            "needs_reboot": False,
        }

    async def _run_backend_switch(self, target: str, step, method_label: str):
        """Shared frame around a switch step: phases, reconnect wait, runtime
        verification, result assembly, and cancel/error handling."""
        try:
            self._ensure_backend_switch_state()
            other = "iwd" if target == "wpa_supplicant" else "wpa_supplicant"
            self._backend_switch["phase"] = "switching"

            outcome = await step(target, other)
            if outcome.get("failed_early"):
                self._backend_switch["phase"] = "failed"
                result = {
                    "success": False,
                    "target": target,
                    "message": outcome.get("message", "Backend switch failed."),
                }
                if outcome.get("detail"):
                    result["detail"] = outcome["detail"]
                self._backend_switch["result"] = result
                return

            restart_ok = outcome.get("restart_ok", True)
            recovery_performed = outcome.get("recovery_performed", False)
            needs_reboot = outcome.get("needs_reboot", False)
            detail = outcome.get("detail", "")

            # Phase: reconnecting. Poll nmcli at 1-second cadence for up to 15s
            # to confirm WiFi actually comes back. 15s is generous for typical
            # NM reconnect (about 5s on wpa_supplicant, 1-2s on iwd) but not
            # so long that users with dead networks wait forever.
            reconnect_timed_out = False
            if not needs_reboot:
                self._backend_switch["phase"] = "reconnecting"
                reconnected = False
                for _ in range(15):
                    iface = await asyncio.to_thread(self._get_wifi_interface)
                    if iface:
                        uuid = await asyncio.to_thread(self._get_active_connection_uuid)
                        if uuid:
                            reconnected = True
                            break
                    await asyncio.sleep(1)
                reconnect_timed_out = not reconnected

            # Verify final state. _get_current_backend reads the conf the
            # switch just wrote, so alone it would only confirm our own write
            # (FUNC-04); additionally require the target service to actually
            # run, or WiFi to have come back, before calling this a success.
            final_backend = await asyncio.to_thread(self._get_current_backend)
            service_active = await asyncio.to_thread(self._backend_service_active, target)

            if needs_reboot:
                self._backend_switch["phase"] = "failed"
                self._backend_switch["result"] = {
                    "success": False,
                    "backend": final_backend,
                    "target": target,
                    "recovery_performed": False,
                    "needs_reboot": True,
                    "message": "Backend switched but wlan0 didn't come back. Reboot required.",
                }
            elif (
                not restart_ok
                or final_backend != target
                or (reconnect_timed_out and not service_active)
            ):
                if detail:
                    message = self._friendly_backend_error(detail)
                elif final_backend != target:
                    message = f"Expected {target} but got {final_backend}. A reboot may help."
                else:
                    message = (
                        f"Config switched to {target} but its service isn't running. "
                        "A reboot may help."
                    )
                    detail = f"{target} service is not running"
                self._backend_switch["phase"] = "failed"
                self._backend_switch["result"] = {
                    "success": False,
                    "backend": final_backend,
                    "target": target,
                    "recovery_performed": recovery_performed,
                    "needs_reboot": False,
                    "reconnect_timed_out": reconnect_timed_out,
                    "message": message,
                    "detail": detail,
                }
            else:
                self._backend_switch["phase"] = "done"
                self._backend_switch["result"] = {
                    "success": True,
                    "backend": final_backend,
                    "target": target,
                    "recovery_performed": recovery_performed,
                    "needs_reboot": False,
                    "reconnect_timed_out": reconnect_timed_out,
                }
            decky.logger.info(
                f"backend switch ({method_label}): target={target}, final={final_backend}, "
                f"recovery={recovery_performed}, needs_reboot={needs_reboot}, "
                f"reconnect_timed_out={reconnect_timed_out}"
            )
        except asyncio.CancelledError:
            self._backend_switch["phase"] = "failed"
            self._backend_switch["result"] = {
                "success": False,
                "target": target,
                "message": "Backend switch cancelled",
            }
            raise
        except Exception as e:
            decky.logger.error(f"backend switch worker ({method_label}) error: {e}")
            self._backend_switch["phase"] = "failed"
            self._backend_switch["result"] = {
                "success": False,
                "target": target,
                "message": str(e),
            }
        finally:
            self._backend_switch["in_progress"] = False

    async def _backend_switch_worker(self, target: str):
        """Background task: SteamOS switch via the privileged helper."""
        await self._run_backend_switch(target, self._steamos_switch_step, "steamos")

    async def _generic_backend_switch_worker(self, target: str):
        """Background task: generic switch via NM config + systemd units."""
        await self._run_backend_switch(target, self._generic_switch_step, "generic")

    async def start_backend_switch(self, backend: str) -> dict:
        """Kick off a backend switch. Returns immediately; poll get_backend_switch_status for progress."""
        try:
            self._ensure_backend_switch_state()
            if backend not in ("iwd", "wpa_supplicant"):
                return {
                    "accepted": False,
                    "reason": "invalid_backend",
                    "message": "Backend must be 'iwd' or 'wpa_supplicant'.",
                }
            if not self._has_backend_tool():
                return {
                    "accepted": False,
                    "reason": "tool_missing",
                    "message": "WiFi backend switch tool not found on this system.",
                }
            if self._backend_switch.get("in_progress"):
                return {
                    "accepted": False,
                    "reason": "in_progress",
                    "message": "Backend switch already in progress.",
                }
            current = await asyncio.to_thread(self._get_current_backend)
            if current == backend:
                return {
                    "accepted": False,
                    "reason": "already_set",
                    "message": f"Backend is already {backend}.",
                    "backend": current,
                }

            self._backend_switch.update({
                "in_progress": True,
                "phase": "switching",
                "target": backend,
                "started_at": int(time.time()),
                "result": None,
            })
            # Route to the appropriate worker based on backend method
            method = self._get_backend_method()
            if method == "steamos":
                worker = self._backend_switch_worker(backend)
            else:
                worker = self._generic_backend_switch_worker(backend)
            self._backend_switch_task = asyncio.create_task(worker)
            decky.logger.info(f"backend switch started: {current} -> {backend}")
            return {
                "accepted": True,
                "target": backend,
                "from": current,
            }
        except Exception as e:
            decky.logger.error(f"start_backend_switch error: {e}")
            return {
                "accepted": False,
                "reason": "unexpected",
                "message": str(e),
            }

    async def get_backend_switch_status(self) -> dict:
        """Return current phase and, when terminal, the final result."""
        try:
            self._ensure_backend_switch_state()
            return {
                "success": True,
                "in_progress": self._backend_switch["in_progress"],
                "phase": self._backend_switch["phase"],
                "target": self._backend_switch["target"],
                "started_at": self._backend_switch["started_at"],
                "result": self._backend_switch["result"],
            }
        except Exception as e:
            decky.logger.error(f"get_backend_switch_status error: {e}")
            # Return a complete shape so the frontend's poll handler hits the
            # terminal branch cleanly and surfaces the error to the user rather
            # than silently stopping with no feedback.
            return {
                "success": False,
                "in_progress": False,
                "phase": "failed",
                "target": None,
                "started_at": 0,
                "result": {
                    "success": False,
                    "target": "",
                    "message": f"Couldn't read backend switch status: {e}",
                },
                "message": str(e),
            }
