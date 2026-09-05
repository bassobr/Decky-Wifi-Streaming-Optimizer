"""The UI status snapshot and the diagnostics export."""

import asyncio
import json
import os

from . import settings as settings_store
from .constants import DIAGNOSTICS_NAME, DISPATCHER_PATH, ENFORCED_FILE, SYSCTL_PARAMS
from .deckyshim import decky
from .parsing import dns_drifted, parse_iw_channel, parse_iw_link, parse_nmcli_fields


class StatusMixin:
    async def get_diagnostic_info(self) -> dict:
        """Collect system info for remote debugging. No credentials, but the
        report does include network identifiers (SSID, MAC/BSSID via iw)."""
        try:
            info = await self.get_device_info()
            iface = self._get_wifi_interface() or "none"
            iw_dev = self._run_cmd(["/usr/bin/iw", "dev"], timeout=3)
            iw_reg = self._run_cmd(["/usr/bin/iw", "reg", "get"], timeout=3)
            uname = self._run_cmd(["/usr/bin/uname", "-r"], timeout=3)
            os_release = ""
            try:
                with open("/etc/os-release", "r") as f:
                    os_release = f.read()
            except Exception:
                pass
            distro = self._detect_distro()
            return {
                "success": True,
                "device_info": info,
                "wifi_interface": iface,
                "iw_dev": iw_dev.get("stdout", ""),
                "iw_reg": iw_reg.get("stdout", ""),
                "kernel": uname.get("stdout", "").strip(),
                "os_release": os_release,
                "distro_id": distro["id"],
                "distro_name": distro["name"],
                "support_tier": self._get_support_tier(),
            }
        except Exception as e:
            decky.logger.error(f"get_diagnostic_info error: {e}")
            return {"success": False, "error": str(e)}

    async def save_diagnostic_info(self) -> dict:
        """Write diagnostics to a file in the settings directory as a
        fallback when clipboard is unavailable. Note: the report includes
        network identifiers (SSID, interface MAC, AP BSSID)."""
        try:
            info = await self.get_diagnostic_info()
            directory = settings_store.settings_dir()
            settings_store.write_private_file(
                directory, DIAGNOSTICS_NAME, json.dumps(info, indent=2)
            )
            return {"success": True, "path": os.path.join(directory, DIAGNOSTICS_NAME)}
        except Exception as e:
            decky.logger.error(f"save_diagnostic_info error: {e}")
            return {"success": False, "error": str(e)}

    async def get_status(self) -> dict:
        """Status snapshot for the UI. Runs entirely off the event loop: the
        ~10 subprocess probes would otherwise freeze every IPC call whenever
        NetworkManager or iw hang - exactly the post-wake situations this
        plugin exists for (FUNC-02)."""
        try:
            return await asyncio.to_thread(self._get_status_sync)
        except Exception as e:
            decky.logger.error(f"get_status error: {e}")
            return self._unexpected_response(e)

    def _get_status_sync(self) -> dict:
        # Shorter timeout for read-only status queries bounds the worst case
        # when NM is unresponsive (~10 commands x 2s).
        T = 2

        settings = settings_store.load_settings()
        iface = self._get_wifi_interface()
        uuid = self._get_active_connection_uuid()
        connected = iface is not None and uuid is not None
        support_tier = self._get_support_tier()

        status = {
            "success": True,
            "connected": connected,
            "support_tier": support_tier,
            "version": decky.DECKY_PLUGIN_VERSION,
            "settings": settings,
            "live": {},
            "drift": {},
        }

        # Streaming auto mode: expose runtime state and gate drift checks -
        # with the gate closed, stock settings are the DESIRED state and
        # must not be reported as drift.
        gate_open = self._volatile_gate_open(settings)
        status["live"]["streaming_active"] = settings.get("streaming_active", False)
        status["live"]["streaming_detected_app"] = settings.get(
            "streaming_detected_app", ""
        )

        # Backend info is system-wide; populate regardless of connection state
        backend_available = self._has_backend_tool()
        status["live"]["backend_tool_available"] = backend_available
        if backend_available:
            status["live"]["wifi_backend"] = self._get_current_backend() or ""

        if not connected:
            status["live"]["dispatcher_installed"] = os.path.isfile(DISPATCHER_PATH)
            return status

        # Remember UUID and ensure high autoconnect-priority so NM prefers
        # this profile over duplicates on boot (fixes 2.4GHz issue). Writes
        # go through update_settings_fields: this code runs in a worker
        # thread and must not clobber concurrent setter saves.
        if uuid != settings.get("last_connection_uuid"):
            settings = settings_store.update_settings_fields(
                last_connection_uuid=uuid, priority_set=False
            )
        if not settings.get("priority_set"):
            # Bump priority to favor this profile over duplicates on boot.
            self._nmcli_modify(uuid, "connection.autoconnect-priority", "100", timeout=T)
            settings = settings_store.update_settings_fields(priority_set=True)

        # Power save
        ps_result = self._run_cmd(
            ["/usr/bin/iw", "dev", iface, "get", "power_save"], timeout=T
        )
        ps_off = "Power save: off" in ps_result.get("stdout", "")
        status["live"]["power_save_off"] = ps_off
        if settings.get("power_save_disabled") and not ps_off and gate_open:
            status["drift"]["power_save"] = True

        # Link info (signal / bitrate / frequency)
        link_result = self._run_cmd(["/usr/bin/iw", "dev", iface, "link"], timeout=T)
        status["live"].update(parse_iw_link(link_result.get("stdout", "")))

        # Channel info - "36 (80 MHz)"
        info_result = self._run_cmd(["/usr/bin/iw", "dev", iface, "info"], timeout=T)
        channel = parse_iw_channel(info_result.get("stdout", ""))
        if channel is not None:
            status["live"]["channel"] = channel

        # Profile fields (BSSID lock, IPv6 method, band) in one nmcli call
        # instead of three (MAINT-02).
        con_result = self._run_cmd(
            [
                "/usr/bin/nmcli", "-t", "-f",
                "802-11-wireless.bssid,ipv6.method,802-11-wireless.band",
                "con", "show", "uuid", uuid,
            ],
            timeout=T,
        )
        con_fields = parse_nmcli_fields(con_result.get("stdout", ""))
        current_bssid_lock = (con_fields.get("802-11-wireless.bssid") or [""])[0]
        if settings.get("bssid_lock_enabled") and not current_bssid_lock:
            status["drift"]["bssid_lock"] = True

        # Drift is only reported from here on; fixing it is the job of the
        # explicit reapply path. A status poll must not mutate system state
        # (FUNC-01) - the previous auto-heal rewrote the NM profile on disk
        # every 3s tick for as long as the drift persisted.
        live_ipv6 = (con_fields.get("ipv6.method") or [""])[0]
        if settings.get("ipv6_disabled") and live_ipv6 != "disabled":
            status["drift"]["ipv6"] = True

        live_band = (con_fields.get("802-11-wireless.band") or [""])[0]
        expected_band = settings.get("band_preference", "a")
        if settings.get("band_preference_enabled") and live_band != expected_band:
            status["drift"]["band_preference"] = True

        # Device fields (IP address, DNS) in one nmcli call
        dev_result = self._run_cmd(
            ["/usr/bin/nmcli", "-t", "-f", "IP4.ADDRESS,IP4.DNS", "dev", "show", iface],
            timeout=T,
        )
        dev_fields = parse_nmcli_fields(dev_result.get("stdout", ""))
        addresses = dev_fields.get("IP4.ADDRESS") or []
        if addresses:
            status["live"]["ip_address"] = addresses[0].split("/")[0].strip()

        if settings.get("dns_enabled") and dns_drifted(
            settings.get("dns_servers", ""), dev_fields.get("IP4.DNS") or []
        ):
            status["drift"]["dns"] = True

        # Buffer tuning
        sysctl_result = self._run_cmd(
            ["/usr/bin/sysctl", "-n", "net.core.rmem_max"], timeout=T
        )
        current_rmem = sysctl_result.get("stdout", "").strip()
        tuned_rmem = SYSCTL_PARAMS["net.core.rmem_max"]
        status["live"]["buffer_tuning_applied"] = current_rmem == tuned_rmem
        if (
            settings.get("buffer_tuning_enabled")
            and current_rmem != tuned_rmem
            and gate_open
        ):
            status["drift"]["buffer_tuning"] = True

        # CAKE QoS
        cake_active = self._get_cake_status(iface)
        status["live"]["cake_applied"] = cake_active
        if settings.get("cake_enabled") and not cake_active and gate_open:
            status["drift"]["cake"] = True

        # Dispatcher
        status["live"]["dispatcher_installed"] = os.path.isfile(DISPATCHER_PATH)

        # Last enforced by dispatcher
        try:
            with open(ENFORCED_FILE, "r") as f:
                status["live"]["last_enforced"] = int(f.read().strip())
        except Exception:
            status["live"]["last_enforced"] = 0

        return status
