"""Subprocess runner and nmcli/iw primitives shared by every other mixin."""

import os
import subprocess

from . import settings as settings_store


class SystemMixin:
    def _run_cmd(self, cmd: list[str], timeout: int = 5, clean_env: bool = False) -> dict:
        """Run a subprocess and return a result dict.

        clean_env strips LD_LIBRARY_PATH so children use system libraries
        instead of Decky's PyInstaller-bundled ones. Required for curl
        (OpenSSL mismatch) and bash (readline symbol mismatch); without it,
        those binaries fail with cryptic symbol-lookup errors.
        """
        try:
            env = None
            if clean_env:
                env = {k: v for k, v in os.environ.items() if k != "LD_LIBRARY_PATH"}
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=env
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Command timed out",
                "returncode": -1,
            }
        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command not found: {cmd[0]}",
                "returncode": -1,
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
            }

    def _unexpected_response(self, e: Exception) -> dict:
        """Standard error dict for the catch-all exception handler in every
        setter. Callers log the error separately with the setter name."""
        return {"success": False, "error": "unexpected", "message": str(e)}

    def _get_wifi_interface(self) -> str | None:
        result = self._run_cmd(
            ["/usr/bin/nmcli", "-t", "-f", "DEVICE,TYPE", "dev", "status"]
        )
        if not result["success"]:
            return None
        for line in result["stdout"].split("\n"):
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "wifi":
                return parts[0]
        return None

    def _get_active_connection_uuid(self) -> str | None:
        result = self._run_cmd(
            ["/usr/bin/nmcli", "-t", "-f", "UUID,TYPE", "con", "show", "--active"]
        )
        if not result["success"]:
            return None
        for line in result["stdout"].split("\n"):
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "802-11-wireless":
                return parts[0]
        return None

    def _get_connected_bssid(self, iface: str) -> str:
        """Read the currently associated AP BSSID from `iw dev <iface> link`."""
        link_result = self._run_cmd(["/usr/bin/iw", "dev", iface, "link"])
        for line in link_result.get("stdout", "").split("\n"):
            if "Connected to" in line:
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
                break
        return ""

    def _nmcli_modify(self, uuid: str, key: str, value: str, timeout: int = 5) -> dict:
        """Run `nmcli con mod uuid <uuid> <key> <value>`. Returns the
        _run_cmd dict so callers can handle success/failure themselves."""
        return self._run_cmd(
            ["/usr/bin/nmcli", "con", "mod", "uuid", uuid, key, value],
            timeout=timeout,
        )

    def _require_wifi(self) -> tuple:
        iface = self._get_wifi_interface()
        if not iface:
            return None, None, {
                "success": False,
                "error": "no_wifi",
                "message": "Not connected to WiFi",
            }
        uuid = self._get_active_connection_uuid()
        if not uuid:
            return iface, None, {
                "success": False,
                "error": "no_wifi",
                "message": "No active WiFi connection",
            }
        return iface, uuid, None

    def _get_saved_connection_uuid(self) -> str | None:
        """Get connection UUID from settings (for modifying saved profiles when disconnected)."""
        settings = settings_store.load_settings()
        return settings.get("last_connection_uuid") or settings.get("bssid_lock_connection_uuid") or None

    def _resolve_uuid(self, active_required_msg: str | None = None) -> tuple:
        """Resolve a WiFi connection UUID for a setter. Returns (uuid, None)
        on success or (None, error_dict) on failure.

        If active_required_msg is provided and there's no active WiFi
        connection, fails with that specific message (e.g., "Connect to WiFi
        first to disable IPv6"). Otherwise falls back to the most recently
        saved connection UUID so setters can still modify a saved profile
        while disconnected.
        """
        _iface, uuid, _err = self._require_wifi()
        if active_required_msg and not uuid:
            return None, {
                "success": False,
                "error": "no_wifi",
                "message": active_required_msg,
            }
        if not uuid:
            uuid = self._get_saved_connection_uuid()
        if not uuid:
            return None, {
                "success": False,
                "error": "nmcli_failed",
                "message": "No connection UUID found. Connect to WiFi first.",
            }
        return uuid, None

    def _hard_reconnect(self, uuid: str | None = None):
        """Reconnect by cycling WiFi radio to fully reset NM connection state."""
        self._run_cmd(["/usr/bin/nmcli", "radio", "wifi", "off"])
        self._run_cmd(["/usr/bin/nmcli", "radio", "wifi", "on"])
        if uuid:
            self._run_cmd(["/usr/bin/nmcli", "con", "up", "uuid", uuid], timeout=10)
