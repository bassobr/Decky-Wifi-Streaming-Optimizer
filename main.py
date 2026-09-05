"""WiFi Optimizer backend for Decky Loader.

Runs as root inside the plugin_loader process. All public async methods on
the Plugin class are callable from the React frontend via Decky's IPC. State
is persisted to settings.json under DECKY_PLUGIN_SETTINGS_DIR and shared with
the NetworkManager dispatcher script at defaults/dispatcher.sh.tmpl, which
reapplies volatile optimizations (power save, PCIe ASPM, buffer tuning, CAKE
QoS) on every WiFi reconnect independently of Decky.
"""

import os
import re
import copy
import json
import time
import shutil
import asyncio
import hashlib
import tarfile
import zipfile
import tempfile
import threading
import subprocess

try:
    import decky
except ImportError:
    # Local fallback when decky isn't importable (e.g., running outside
    # plugin_loader for static analysis or ad-hoc testing). All runtime
    # paths on a Deck have the real module.
    class decky:  # type: ignore
        DECKY_PLUGIN_SETTINGS_DIR = "/tmp/wifi-optimizer"
        DECKY_PLUGIN_DIR = "/tmp/wifi-optimizer"
        DECKY_PLUGIN_VERSION = "0.0.0"
        class logger:
            @staticmethod
            def info(msg): print(f"[INFO] {msg}")
            @staticmethod
            def error(msg): print(f"[ERROR] {msg}")

DISPATCHER_PATH = "/etc/NetworkManager/dispatcher.d/99-wifi-optimizer"
NM_CONF_PATH = "/etc/NetworkManager/conf.d/99-wifi-optimizer.conf"
MODPROBE_CONF_PATH = "/etc/modprobe.d/99-wifi-optimizer.conf"
BACKEND_HELPER = "/usr/bin/steamos-polkit-helpers/steamos-wifi-set-backend-privileged"
WIFI_BACKEND_CONF = "/etc/NetworkManager/conf.d/99-valve-wifi-backend.conf"
NM_DEFAULT_CONF = "/usr/lib/NetworkManager/conf.d/10-steamos-defaults.conf"
GENERIC_BACKEND_CONF = "/etc/NetworkManager/conf.d/99-wifi-optimizer-backend.conf"
BAZZITE_IWD_CONF = "/etc/NetworkManager/conf.d/iwd.conf"

DRIVER_PROFILES = {
    "rtw88": {
        "chip_label": "WiFi 5 (RTL8822CE)",
        "supports_6ghz": False,
        "sysfs_power_fixes": [
            "/sys/module/rtw88_core/parameters/disable_lps_deep",
            "/sys/module/rtw88_pci/parameters/disable_aspm",
        ],
        "modprobe_options": [
            "options rtw88_core disable_lps_deep=Y",
            "options rtw88_pci disable_aspm=Y",
        ],
    },
    "ath11k_pci": {
        "chip_label": "WiFi 6E (QCA206X)",
        "supports_6ghz": True,
        "sysfs_power_fixes": [],
        "modprobe_options": [],
    },
    "mt7921e": {
        "chip_label": "WiFi 6E (MT7922)",
        "supports_6ghz": True,
        "sysfs_power_fixes": [
            "/sys/module/mt7921e/parameters/disable_aspm",
        ],
        "modprobe_options": [
            "options mt7921e disable_aspm=Y",
        ],
    },
    "iwlwifi": {
        "chip_label": "Intel WiFi",
        "supports_6ghz": True,
        "sysfs_power_fixes": [],
        "modprobe_options": [
            "options iwlwifi power_save=0 uapsd_disable=3",
            "options iwlmvm power_scheme=1",
        ],
    },
}

DMI_DEVICES = {
    "Jupiter": {"family": "deck_lcd", "label": "Steam Deck LCD"},
    "Galileo": {"family": "deck_oled", "label": "Steam Deck OLED"},
    "83E1": {"family": "legion_go", "label": "Legion Go"},
    "83L3": {"family": "legion_go_s", "label": "Legion Go S"},
    "83N6": {"family": "legion_go_s", "label": "Legion Go S"},
    "83Q2": {"family": "legion_go_s", "label": "Legion Go S"},
    "83Q3": {"family": "legion_go_s", "label": "Legion Go S"},
    "83N0": {"family": "legion_go_2", "label": "Legion Go 2"},
    "83N1": {"family": "legion_go_2", "label": "Legion Go 2"},
}

DMI_SUBSTRING_DEVICES = [
    ("ROG Xbox Ally X RC73X", {"family": "rog_xbox_ally_x", "label": "ROG Xbox Ally X"}),
    ("ROG Xbox Ally RC73Y", {"family": "rog_xbox_ally", "label": "ROG Xbox Ally"}),
    ("ROG Ally X RC72LA", {"family": "rog_ally_x", "label": "ROG Ally X"}),
    ("ROG Ally RC71L", {"family": "rog_ally", "label": "ROG Ally"}),
]

# last_enforced lives under /run (root-owned tmpfs): the dispatcher runs as
# root and must never write through paths an unprivileged user could swap for
# a symlink, which the user-writable settings dir would allow (SEC-01). The
# legacy copy inside the settings dir is removed on startup.
ENFORCED_DIR = "/run/wifi-optimizer"
ENFORCED_FILE = os.path.join(ENFORCED_DIR, "last_enforced")
LEGACY_ENFORCED_NAME = "last_enforced"
DIAGNOSTICS_NAME = "diagnostics.json"

try:
    SETTINGS_FILE = os.path.join(decky.DECKY_PLUGIN_SETTINGS_DIR, "settings.json")
except Exception:
    SETTINGS_FILE = "/tmp/wifi-optimizer/settings.json"

DNS_PROVIDERS = {
    "cloudflare": "1.1.1.1 1.0.0.1",
    "google": "8.8.8.8 8.8.4.4",
    "quad9": "9.9.9.9 149.112.112.112",
}

# Known streaming clients, matched as lowercase substrings against
# /proc/<pid>/cmdline. Patterns are chosen to hit the flatpak/app binary or a
# characteristic launch argument (GeForce NOW runs as a Chromium app pointed
# at play.geforcenow.com), so detection works no matter whether the app was
# launched as a Steam shortcut, from desktop mode, or via a browser kiosk.
STREAMING_APPS = {
    "moonlight": {"label": "Moonlight", "patterns": ["moonlight"]},
    # GFN on the Deck is the com.nvidia.geforcenow flatpak (NVIDIA's launcher
    # script wraps `flatpak run`); the URL pattern covers browser/kiosk use.
    # The full flatpak ID avoids false positives from unrelated command lines
    # that merely mention "geforcenow".
    "geforce_now": {"label": "GeForce NOW", "patterns": ["com.nvidia.geforcenow", "play.geforcenow.com"]},
    "chiaki": {"label": "Chiaki (PS Remote Play)", "patterns": ["chiaki"]},
    "steam_link": {"label": "Steam Link", "patterns": ["steamlink"]},
    "greenlight": {"label": "Greenlight (Xbox)", "patterns": ["greenlight"]},
    "parsec": {"label": "Parsec", "patterns": ["parsecd"]},
    "xbox_cloud": {"label": "Xbox Cloud Gaming", "patterns": ["xbox.com/play"]},
}

STREAMING_POLL_INTERVAL = 5
# Consecutive empty scans before reverting to standard settings; bridges app
# restarts and brief process churn without flapping the WiFi config.
STREAMING_MISS_THRESHOLD = 2

# Tuned values for game streaming: larger socket buffers absorb bursty UDP
# traffic, higher netdev backlog/budget lets the kernel process more packets
# per NAPI cycle, and disabling tcp_slow_start_after_idle keeps TCP congestion
# window from resetting after idle pauses (matters for control-plane TCP).
# Values match commonly cited streaming presets rather than being
# exhaustively tuned.
SYSCTL_PARAMS = {
    "net.core.rmem_max": "16777216",
    "net.core.wmem_max": "16777216",
    "net.core.rmem_default": "1048576",
    "net.core.wmem_default": "1048576",
    "net.core.netdev_max_backlog": "5000",
    "net.core.netdev_budget": "600",
    "net.core.netdev_budget_usecs": "8000",
    "net.ipv4.tcp_slow_start_after_idle": "0",
}

# Kernel defaults, used as fallback when no pre-apply snapshot exists.
SYSCTL_DEFAULTS = {
    "net.core.rmem_max": "212992",
    "net.core.wmem_max": "212992",
    "net.core.rmem_default": "212992",
    "net.core.wmem_default": "212992",
    "net.core.netdev_max_backlog": "1000",
    "net.core.netdev_budget": "300",
    "net.core.netdev_budget_usecs": "2000",
    "net.ipv4.tcp_slow_start_after_idle": "1",
}

# txqueuelen values and the CAKE qdisc arguments are shared between the
# Python appliers and the rendered dispatcher script (single source of
# truth - see _render_dispatcher_script).
TXQ_TUNED = "2000"
TXQ_DEFAULT = "1000"
TXQ_CAKE = "256"
CAKE_QDISC_ARGS = ["cake", "unlimited", "diffserv4", "nat", "ack-filter"]

# Custom streaming patterns shorter than this match half of every process
# list ("a" matches almost anything) and would silently pin the streaming
# gate open, so they are rejected on save and skipped on scan.
MIN_PATTERN_LEN = 3

# Version strings arriving from the GitHub API are embedded in download URLs
# and exported to a root shell via the environment; allow plain version
# characters only.
VERSION_RE = re.compile(r"^[0-9A-Za-z._-]{1,64}$")

DEFAULT_SETTINGS = {
    "model": "unknown",
    "driver": "unknown",
    "device_family": "unknown",
    "device_label": "Unknown Device",
    "chip_label": "unknown",
    "supports_6ghz": False,
    "power_save_disabled": True,
    "auto_fix_on_wake": True,
    "bssid_lock_enabled": False,
    "bssid_lock_value": "",
    "bssid_lock_connection_uuid": "",
    "band_preference": "a",
    "band_preference_enabled": False,
    "dns_provider": "cloudflare",
    "dns_servers": "1.1.1.1 1.0.0.1",
    "dns_enabled": False,
    "ipv6_disabled": False,
    "buffer_tuning_enabled": False,
    "cake_enabled": False,
    "streaming_mode_enabled": False,
    "streaming_apps": {app_id: True for app_id in STREAMING_APPS},
    "streaming_custom_patterns": "",
    "streaming_active": False,
    "streaming_detected_app": "",
    "last_connection_uuid": "",
    "priority_set": False,
    "distro_id": "unknown",
    "distro_name": "Unknown",
    "update_channel": "stable",
    "last_applied": 0,
}


# In-memory settings cache keyed on the file's (mtime_ns, size). Only this
# process writes settings.json, so the stat check exists purely to catch
# external edits/deletion; the steady-state win is that the 5s watcher poll
# and the 3s UI status poll stop hitting the disk. Callers get a deep copy -
# they mutate the result before saving, which must never leak into the cache.
_settings_cache: dict = {"stat": None, "data": None}

# Settings are now also read/written from worker threads (get_status and the
# volatile-fix appliers run in asyncio.to_thread); the RLock keeps cache and
# file writes coherent across threads. Read-modify-write cycles that must be
# atomic go through Plugin._update_settings_fields, which holds the lock for
# the whole cycle.
_settings_lock = threading.RLock()
_last_settings_error_log = 0.0

_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def _open_private_dir(directory: str) -> int:
    """Open a directory fd, refusing symlinks. All root-owned file operations
    inside user-writable directories go through this fd so a user swapping
    the directory (or planting symlinks) between check and use cannot
    redirect root's writes elsewhere (SEC-01)."""
    return os.open(directory, os.O_RDONLY | _O_DIRECTORY | os.O_NOFOLLOW)


def _write_private_file(directory: str, name: str, content: str):
    """Symlink-safe write of a root-created file into a possibly
    user-writable directory: never follow symlinks, never reuse a
    pre-created file (SEC-01)."""
    dfd = _open_private_dir(directory)
    try:
        try:
            os.remove(name, dir_fd=dfd)
        except FileNotFoundError:
            pass
        fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd
        )
        with os.fdopen(fd, "w") as f:
            f.write(content)
    finally:
        os.close(dfd)


def _remove_private_file(directory: str, name: str):
    """Symlink-safe removal of a file inside a possibly user-writable dir."""
    try:
        dfd = _open_private_dir(directory)
    except OSError:
        return
    try:
        try:
            os.remove(name, dir_fd=dfd)
        except FileNotFoundError:
            pass
    finally:
        os.close(dfd)


def _load_settings() -> dict:
    global _last_settings_error_log
    with _settings_lock:
        try:
            st = os.stat(SETTINGS_FILE)
            cache_key = (st.st_mtime_ns, st.st_size)
            if _settings_cache["stat"] == cache_key and _settings_cache["data"] is not None:
                return copy.deepcopy(_settings_cache["data"])
            with open(SETTINGS_FILE, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("settings root is not a JSON object")
        except FileNotFoundError:
            return copy.deepcopy(DEFAULT_SETTINGS)
        except (json.JSONDecodeError, ValueError) as e:
            # A corrupt file would otherwise be silently replaced with
            # defaults on the next save - keep the evidence and log it
            # instead of losing the user's settings without a trace.
            decky.logger.error(
                f"settings.json is corrupt ({e}); backing up to settings.json.corrupt"
            )
            try:
                os.replace(SETTINGS_FILE, SETTINGS_FILE + ".corrupt")
            except Exception:
                pass
            return copy.deepcopy(DEFAULT_SETTINGS)
        except Exception as e:
            # Rate-limited: a persistent read failure (e.g. permissions)
            # would otherwise log on every 3s status poll.
            now = time.monotonic()
            if now - _last_settings_error_log > 300:
                _last_settings_error_log = now
                decky.logger.error(f"Failed to read settings: {e}")
            return copy.deepcopy(DEFAULT_SETTINGS)
        # Merge with defaults (adds new keys), then strip stale keys
        merged = {**DEFAULT_SETTINGS, **data}
        # streaming_apps merges per-app so newly added presets default to
        # enabled without clobbering the user's existing choices.
        saved_apps = data.get("streaming_apps") or {}
        merged["streaming_apps"] = {
            app_id: bool(saved_apps.get(app_id, True)) for app_id in STREAMING_APPS
        }
        result = {k: v for k, v in merged.items() if k in DEFAULT_SETTINGS}
        _settings_cache["stat"] = cache_key
        _settings_cache["data"] = copy.deepcopy(result)
        return result


def _save_settings(data: dict):
    settings_dir = os.path.dirname(SETTINGS_FILE)
    base = os.path.basename(SETTINGS_FILE)
    tmp_name = base + ".tmp"
    with _settings_lock:
        os.makedirs(settings_dir, exist_ok=True)
        # Atomic write (tmp + rename), pinned to the real directory via
        # dir_fd and with O_EXCL|O_NOFOLLOW so a pre-created file or symlink
        # in the user-writable settings dir is refused instead of followed
        # by this root process (SEC-01).
        dfd = _open_private_dir(settings_dir)
        try:
            try:
                os.remove(tmp_name, dir_fd=dfd)
            except FileNotFoundError:
                pass
            fd = os.open(
                tmp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o644,
                dir_fd=dfd,
            )
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_name, base, src_dir_fd=dfd, dst_dir_fd=dfd)
        finally:
            os.close(dfd)
        try:
            st = os.stat(SETTINGS_FILE)
            _settings_cache["stat"] = (st.st_mtime_ns, st.st_size)
            _settings_cache["data"] = copy.deepcopy(data)
        except Exception:
            _settings_cache["stat"] = None
            _settings_cache["data"] = None


def _save_settings_with_timestamp(data: dict):
    """Save settings and update last_applied timestamp in one write."""
    data["last_applied"] = int(time.time())
    _save_settings(data)


def _verify_sha256(sums_text: str, filename: str, path: str) -> tuple[bool, str]:
    """Check `path` against the entry for `filename` in a sha256sum-format
    SHA256SUMS document. Returns (ok, detail)."""
    expected = None
    for line in sums_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == filename:
            expected = parts[0].lower()
            break
    if not expected:
        return False, f"no entry for {filename} in SHA256SUMS"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected:
        return False, f"sha256 mismatch: expected {expected}, got {actual}"
    return True, ""


def _safe_extract_zip(zip_path: str, dest: str):
    """Extract a zip, rejecting members that would escape dest."""
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            p = os.path.normpath(name)
            if p.startswith("..") or os.path.isabs(p):
                raise ValueError(f"unsafe zip member: {name}")
        z.extractall(dest)


def _safe_extract_tar(tar_path: str, dest: str):
    """Extract a .tar.gz, rejecting traversal, links, and absolute paths."""
    with tarfile.open(tar_path, "r:gz") as t:
        try:
            t.extractall(dest, filter="data")
        except TypeError:
            # Python without extraction-filter support: validate manually.
            for m in t.getmembers():
                name = os.path.normpath(m.name)
                if name.startswith("..") or os.path.isabs(name) or m.islnk() or m.issym():
                    raise ValueError(f"unsafe tar member: {m.name}")
            t.extractall(dest)


class Plugin:
    """Root plugin instance. Decky exposes every async method here as a
    callable from the frontend. Synchronous helpers prefixed with `_` are
    for internal use only."""

    # ---- Helpers ----

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

    def _get_backend_method(self) -> str:
        """Return 'steamos', 'generic', or 'none'.
        SteamOS has a privileged helper. Generic uses NM conf + systemctl
        directly and requires iwd to be installed. Non-SteamOS distros
        always use generic even if the SteamOS helper exists (it may
        behave differently on Bazzite/CachyOS)."""
        settings = _load_settings()
        distro = settings.get("distro_id", "unknown")
        if distro == "steamos" and os.path.isfile(BACKEND_HELPER) and os.access(BACKEND_HELPER, os.X_OK):
            return "steamos"
        if os.path.isfile("/usr/lib/systemd/system/iwd.service"):
            return "generic"
        return "none"

    def _has_backend_tool(self) -> bool:
        return self._get_backend_method() != "none"

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
        settings = _load_settings()
        return settings.get("last_connection_uuid") or settings.get("bssid_lock_connection_uuid") or None

    def _hard_reconnect(self, uuid: str | None = None):
        """Reconnect by cycling WiFi radio to fully reset NM connection state."""
        self._run_cmd(["/usr/bin/nmcli", "radio", "wifi", "off"])
        self._run_cmd(["/usr/bin/nmcli", "radio", "wifi", "on"])
        if uuid:
            self._run_cmd(["/usr/bin/nmcli", "con", "up", "uuid", uuid], timeout=10)

    def _apply_driver_fixes(self, enable: bool):
        """Apply or revert driver-specific power save fixes from DRIVER_PROFILES.
        Silently no-ops for drivers with no sysfs paths or modprobe options."""
        settings = _load_settings()
        profile = DRIVER_PROFILES.get(settings.get("driver"), {})

        val = "Y" if enable else "N"
        for path in profile.get("sysfs_power_fixes", []):
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
        Works on all PCIe-attached WiFi adapters."""
        try:
            # Discover WiFi PCI device path dynamically
            iface = self._get_wifi_interface()
            if not iface:
                return
            device_link = os.path.realpath(f"/sys/class/net/{iface}/device")
            if not os.path.isdir(device_link):
                return

            # Disable/restore PCIe ASPM L-states
            link_dir = os.path.join(device_link, "link")
            if os.path.isdir(link_dir):
                val = "0" if enable else "1"
                for aspm_file in ["l0s_aspm", "l1_aspm", "l1_1_aspm", "l1_2_aspm",
                                   "l1_1_pcipm", "l1_2_pcipm"]:
                    path = os.path.join(link_dir, aspm_file)
                    try:
                        with open(path, "w") as f:
                            f.write(val)
                    except (FileNotFoundError, PermissionError):
                        pass

            # Disable/restore PCI runtime power management
            power_control = os.path.join(device_link, "power", "control")
            try:
                with open(power_control, "w") as f:
                    f.write("on" if enable else "auto")
            except (FileNotFoundError, PermissionError):
                pass

            if enable:
                decky.logger.info(f"PCIe ASPM disabled for {device_link}")
            else:
                decky.logger.info(f"PCIe ASPM restored for {device_link}")
        except Exception as e:
            decky.logger.error(f"PCIe ASPM fix error: {e}")

    # ---- Streaming auto mode ----
    #
    # When streaming_mode_enabled is on, the volatile fixes (power save/ASPM,
    # buffer tuning, CAKE) are only held active while a detected streaming app
    # is running; outside of that the system stays on stock settings. The
    # "gate" below is the single source of truth for whether those fixes may
    # currently be applied. Reconnect-triggering settings (BSSID lock, band,
    # DNS, IPv6) are deliberately NOT gated - toggling them mid-session would
    # drop the connection the stream is running on.

    def _volatile_gate_open(self, settings: dict | None = None) -> bool:
        s = settings if settings is not None else _load_settings()
        return (not s.get("streaming_mode_enabled", False)) or s.get(
            "streaming_active", False
        )

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
        """Apply tuned or default sysctl values and txqueuelen. Does not persist."""
        s = settings if settings is not None else _load_settings()
        params = SYSCTL_PARAMS if on else SYSCTL_DEFAULTS
        for key, value in params.items():
            result = self._run_cmd(["/usr/bin/sysctl", "-w", f"{key}={value}"])
            if not result["success"]:
                decky.logger.error(f"sysctl {key}={value} failed: {result['stderr']}")
        iface = self._get_wifi_interface()
        if iface:
            # CAKE manages its own queue; keep txqueuelen at 256 while it is
            # active so the two features don't fight over the value.
            cake_active = s.get("cake_enabled") and self._volatile_gate_open(s)
            if cake_active:
                txq = "256"
            else:
                txq = "2000" if on else "1000"
            self._run_cmd(["/usr/bin/ip", "link", "set", iface, "txqueuelen", txq])

    def _apply_cake_now(self, on: bool, settings: dict | None = None) -> dict:
        """Install or remove the CAKE qdisc. Does not persist."""
        s = settings if settings is not None else _load_settings()
        iface = self._get_wifi_interface()
        if not iface:
            return {"success": False, "error": "no_wifi", "message": "Not connected to WiFi."}
        if on:
            modprobe = "/usr/bin/modprobe" if os.path.isfile("/usr/bin/modprobe") else "/usr/sbin/modprobe"
            self._run_cmd([modprobe, "sch_cake"], timeout=5)
            result = self._run_cmd([
                "/usr/bin/tc", "qdisc", "replace", "dev", iface, "root",
                "cake", "unlimited", "diffserv4", "nat", "ack-filter",
            ])
            if not result["success"]:
                return {
                    "success": False,
                    "error": "unexpected",
                    "message": "Failed to apply CAKE qdisc.",
                    "detail": result.get("stderr", ""),
                }
            self._run_cmd(["/usr/bin/ip", "link", "set", iface, "txqueuelen", "256"])
        else:
            self._run_cmd(["/usr/bin/tc", "qdisc", "del", "dev", iface, "root"])
            buffer_active = s.get("buffer_tuning_enabled") and self._volatile_gate_open(s)
            txq = "2000" if buffer_active else "1000"
            self._run_cmd(["/usr/bin/ip", "link", "set", iface, "txqueuelen", txq])
        return {"success": True}

    async def _apply_streaming_profile(self, active: bool):
        """Apply (stream started) or revert (stream ended) every volatile fix
        the user has enabled. Called by the watcher on state transitions and
        by set_streaming_mode when the mode itself is toggled."""
        settings = _load_settings()
        if settings.get("buffer_tuning_enabled"):
            self._apply_buffer_tuning_now(active, settings)
        if settings.get("cake_enabled"):
            self._apply_cake_now(active, settings)
        if settings.get("power_save_disabled"):
            self._apply_power_save_now(active)

    def _detect_streaming_app(self, settings: dict) -> str | None:
        """Scan /proc for a running streaming client. Returns the app label of
        the first match or None. Matches lowercase substrings against each
        process's full command line."""
        patterns: list[tuple[str, str]] = []
        apps_enabled = settings.get("streaming_apps", {})
        for app_id, info in STREAMING_APPS.items():
            if apps_enabled.get(app_id, True):
                for p in info["patterns"]:
                    patterns.append((p, info["label"]))
        custom = settings.get("streaming_custom_patterns", "") or ""
        for p in custom.replace(",", " ").split():
            patterns.append((p.lower(), p))
        if not patterns:
            return None

        own_pid = str(os.getpid())
        try:
            pids = os.listdir("/proc")
        except Exception:
            return None
        for pid in pids:
            if not pid.isdigit() or pid == own_pid:
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = f.read().replace(b"\0", b" ").decode("utf-8", "ignore").lower()
            except Exception:
                continue
            if not cmd:
                continue
            for pattern, label in patterns:
                if pattern in cmd:
                    return label
        return None

    def _ensure_streaming_state(self):
        """Lazy init so IPC-driven passes work even if _main hasn't run yet."""
        if not hasattr(self, "_detect_lock"):
            self._detect_lock = asyncio.Lock()
            self._streaming_misses = 0

    async def _run_detection_pass(self, settle_immediately: bool = False):
        """One detection pass. The watcher loop calls this with hysteresis
        (STREAMING_MISS_THRESHOLD empty scans before reverting); event-driven
        callers (game launch/exit notification, app-list edits) pass
        settle_immediately=True since their trigger already signals a state
        change. The lock serializes concurrent passes."""
        self._ensure_streaming_state()
        async with self._detect_lock:
            settings = _load_settings()
            if not settings.get("streaming_mode_enabled"):
                return
            detected = await asyncio.to_thread(self._detect_streaming_app, settings)
            # Reload after the await: a setter may have written settings while
            # the scan ran in the thread; mutating that stale copy would
            # silently undo the user's change. Only the two runtime fields
            # below are touched on the fresh copy.
            settings = _load_settings()
            if not settings.get("streaming_mode_enabled"):
                return
            was_active = settings.get("streaming_active", False)
            if detected:
                self._streaming_misses = 0
                if not was_active:
                    settings["streaming_active"] = True
                    settings["streaming_detected_app"] = detected
                    _save_settings(settings)
                    decky.logger.info(
                        f"Streaming app detected: {detected} - applying fixes"
                    )
                    await self._apply_streaming_profile(True)
                elif detected != settings.get("streaming_detected_app"):
                    settings["streaming_detected_app"] = detected
                    _save_settings(settings)
            elif was_active:
                self._streaming_misses += 1
                if settle_immediately or self._streaming_misses >= STREAMING_MISS_THRESHOLD:
                    self._streaming_misses = 0
                    settings["streaming_active"] = False
                    settings["streaming_detected_app"] = ""
                    _save_settings(settings)
                    decky.logger.info(
                        "Streaming app exited - reverting to standard settings"
                    )
                    await self._apply_streaming_profile(False)
            else:
                self._streaming_misses = 0

    async def _streaming_watcher(self):
        """Background task: polls /proc and flips the volatile fixes when a
        monitored streaming app starts or exits."""
        last_error_logged = 0.0
        while True:
            try:
                await self._run_detection_pass()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                # Rate-limit: a persistent failure (e.g. corrupt settings)
                # would otherwise log the same error every poll.
                now = time.monotonic()
                if now - last_error_logged > 300:
                    last_error_logged = now
                    decky.logger.error(f"streaming watcher error: {e}")
            await asyncio.sleep(STREAMING_POLL_INTERVAL)

    async def poke_detection(self) -> dict:
        """Run one immediate detection pass. Called by the frontend on game
        launch/exit notifications so fixes apply/revert without waiting for
        the next watcher poll. Harmless no-op when auto mode is off."""
        try:
            await self._run_detection_pass(settle_immediately=True)
            settings = _load_settings()
            return {
                "success": True,
                "streaming_active": settings.get("streaming_active", False),
                "streaming_detected_app": settings.get("streaming_detected_app", ""),
            }
        except Exception as e:
            decky.logger.error(f"poke_detection error: {e}")
            return self._unexpected_response(e)

    def _render_dispatcher_script(self, template: str) -> str:
        """Render the dispatcher template. All tuning values (sysctl set,
        driver sysfs fixes, CAKE args, txqueuelen) are injected from the
        constants in this module so the plugin and the dispatcher can never
        disagree about what gets applied."""
        sysctl_lines = "\n".join(
            f"    /usr/bin/sysctl -w {k}={v} >/dev/null 2>&1"
            for k, v in SYSCTL_PARAMS.items()
        )
        driver_blocks = []
        for name, profile in DRIVER_PROFILES.items():
            fixes = profile.get("sysfs_power_fixes", [])
            if not fixes:
                continue
            lines = [f'    if [ "$DRIVER" = "{name}" ]; then']
            lines += [f"        echo Y > {path} 2>/dev/null" for path in fixes]
            lines.append("    fi")
            driver_blocks.append("\n".join(lines))
        replacements = {
            "__SETTINGS_PATH__": SETTINGS_FILE,
            "__PLUGIN_DIR__": decky.DECKY_PLUGIN_DIR,
            "__ENFORCED_DIR__": ENFORCED_DIR,
            "__SYSCTL_CMDS__": sysctl_lines,
            "__DRIVER_FIXES__": "\n".join(driver_blocks) if driver_blocks else "    :",
            "__CAKE_ARGS__": " ".join(CAKE_QDISC_ARGS),
            "__TXQ_TUNED__": TXQ_TUNED,
            "__TXQ_CAKE__": TXQ_CAKE,
        }
        script = template
        for placeholder, value in replacements.items():
            script = script.replace(placeholder, value)
        return script

    def _install_dispatcher(self):
        try:
            template_path = os.path.join(
                decky.DECKY_PLUGIN_DIR, "defaults", "dispatcher.sh.tmpl"
            )
            with open(template_path, "r") as f:
                template = f.read()
            script = self._render_dispatcher_script(template)
            # /etc/NetworkManager/dispatcher.d is root-owned; plain write is fine.
            with open(DISPATCHER_PATH, "w") as f:
                f.write(script)
            os.chmod(DISPATCHER_PATH, 0o755)
            decky.logger.info("Dispatcher script installed")
        except Exception as e:
            decky.logger.error(f"Failed to install dispatcher: {e}")

    def _remove_dispatcher(self):
        try:
            os.remove(DISPATCHER_PATH)
            decky.logger.info("Dispatcher script removed")
        except FileNotFoundError:
            pass
        except Exception as e:
            decky.logger.error(f"Failed to remove dispatcher: {e}")

    def _rotate_logs(self, keep: int = 10):
        """Prune old log files on plugin startup. Decky does not rotate plugin
        logs automatically; each plugin load creates a new timestamped file in
        DECKY_PLUGIN_LOG_DIR, so without pruning they accumulate forever.
        Keep the newest `keep` files (typical size ~2-3 KB each, so bounded at
        roughly 30 KB total).
        """
        try:
            log_dir = getattr(decky, "DECKY_PLUGIN_LOG_DIR", None)
            if not log_dir or not os.path.isdir(log_dir):
                return
            files = [
                os.path.join(log_dir, f)
                for f in os.listdir(log_dir)
                if f.endswith(".log")
            ]
            if len(files) <= keep:
                return
            files.sort(key=os.path.getmtime, reverse=True)
            current_log = getattr(decky, "DECKY_PLUGIN_LOG", None)
            removed = 0
            for path in files[keep:]:
                # Paranoia: never delete the file we're currently writing to.
                if current_log and os.path.realpath(path) == os.path.realpath(current_log):
                    continue
                try:
                    os.remove(path)
                    removed += 1
                except Exception:
                    pass
            if removed:
                decky.logger.info(f"Rotated logs: removed {removed} old file(s), kept {keep} newest")
        except Exception as e:
            decky.logger.error(f"Log rotation error: {e}")

    # ---- Lifecycle ----

    async def _main(self):
        try:
            decky.logger.info("WiFi Optimizer starting")
            self._rotate_logs()
            # last_enforced moved to root-owned /run (SEC-01); drop the legacy
            # copy from the user-writable settings dir.
            _remove_private_file(os.path.dirname(SETTINGS_FILE), LEGACY_ENFORCED_NAME)
            self._ensure_backend_switch_state()
            info = await self.get_device_info()
            settings = _load_settings()
            settings["model"] = info.get("model", "unknown")
            settings["driver"] = info.get("driver", "unknown")
            settings["device_family"] = info.get("device_family", "unknown")
            settings["device_label"] = info.get("device_label", "Unknown Device")
            settings["chip_label"] = info.get("chip_label", "unknown")
            settings["supports_6ghz"] = info.get("supports_6ghz", False)
            distro = self._detect_distro()
            settings["distro_id"] = distro["id"]
            settings["distro_name"] = distro["name"]
            # streaming_active is runtime state; never trust a stale value
            # from before a crash/reboot. The watcher re-detects within one
            # poll interval.
            settings["streaming_active"] = False
            settings["streaming_detected_app"] = ""
            _save_settings(settings)

            if settings.get("auto_fix_on_wake", True):
                self._install_dispatcher()

            self._ensure_streaming_state()
            self._streaming_watcher_task = asyncio.create_task(
                self._streaming_watcher()
            )

            # Apply volatile settings that may have been lost on reboot.
            # The dispatcher handles reconnects, but on a fresh boot WiFi
            # connects before the plugin starts, so we apply here too.
            # Order: buffer tuning first (sets txqueuelen), then CAKE
            # (overrides txqueuelen to 256), then power_save last (sticks
            # after any reconnects the dispatcher might trigger).
            # With streaming auto mode on, the gate is closed at boot and the
            # watcher applies these when it detects a streaming app instead.
            iface = self._get_wifi_interface()
            if iface and self._volatile_gate_open(settings):
                if settings.get("buffer_tuning_enabled"):
                    try:
                        await self.set_buffer_tuning(True)
                    except Exception as e:
                        decky.logger.error(f"Startup buffer tuning failed: {e}")
                if settings.get("cake_enabled"):
                    try:
                        await self.set_cake(True)
                    except Exception as e:
                        decky.logger.error(f"Startup CAKE apply failed: {e}")
                if settings.get("power_save_disabled"):
                    try:
                        await self.set_power_save(True)
                    except Exception as e:
                        decky.logger.error(f"Startup power save failed: {e}")

            # Sanity check: does the conf-declared backend match what's actually
            # running? Divergence would indicate a previous switch got interrupted
            # (plugin_loader crash, external tool, etc.). Log only; user can
            # re-toggle to resolve.
            if self._get_backend_method() != "none":
                conf_backend = self._get_current_backend()
                if conf_backend:
                    active = self._run_cmd(
                        ["/usr/bin/systemctl", "is-active", conf_backend], timeout=3
                    )
                    state = (active.get("stdout") or "").strip()
                    if state and state != "active":
                        decky.logger.error(
                            f"Backend inconsistency: conf says '{conf_backend}' "
                            f"but systemd reports '{state}'. Likely an interrupted "
                            f"backend switch - user can retry via the UI."
                        )

            decky.logger.info(
                f"WiFi Optimizer ready: device={info.get('device_label')}, "
                f"family={info.get('device_family')}, driver={info.get('driver')}, "
                f"chip={info.get('chip_label')}, distro={distro['id']}"
            )
        except Exception as e:
            decky.logger.error(f"WiFi Optimizer _main error: {e}")

    async def _unload(self):
        try:
            decky.logger.info("WiFi Optimizer unloading")
            task = getattr(self, "_backend_switch_task", None)
            if task and not task.done():
                task.cancel()
            watcher = getattr(self, "_streaming_watcher_task", None)
            if watcher and not watcher.done():
                watcher.cancel()
        except Exception as e:
            decky.logger.error(f"_unload error: {e}")

    async def _uninstall(self):
        try:
            decky.logger.info("WiFi Optimizer uninstalling")
            self._remove_dispatcher()
            self._apply_driver_fixes(False)
            self._apply_pcie_aspm_fix(False)
            for key, value in SYSCTL_DEFAULTS.items():
                self._run_cmd(["/usr/bin/sysctl", "-w", f"{key}={value}"])
            iface = self._get_wifi_interface()
            if iface:
                self._run_cmd(["/usr/bin/ip", "link", "set", iface, "txqueuelen", "1000"])
                self._run_cmd(["/usr/bin/tc", "qdisc", "del", "dev", iface, "root"])
            for path in [NM_CONF_PATH, MODPROBE_CONF_PATH, GENERIC_BACKEND_CONF,
                         SETTINGS_FILE, ENFORCED_FILE]:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
        except Exception as e:
            decky.logger.error(f"_uninstall error: {e}")

    async def _migration(self):
        pass

    # ---- Hardware detection ----

    def _detect_device_family(self) -> tuple[str, str, str]:
        """Read DMI product_name and return (raw_product, family_id, display_label)."""
        try:
            with open("/sys/devices/virtual/dmi/id/product_name", "r") as f:
                product = f.read().strip()
        except Exception:
            return ("unknown", "unknown", "Unknown Device")

        if product in DMI_DEVICES:
            info = DMI_DEVICES[product]
            return (product, info["family"], info["label"])

        for prefix, info in DMI_SUBSTRING_DEVICES:
            if product.startswith(prefix):
                return (product, info["family"], info["label"])

        return (product, "unknown", "Unknown Device")

    def _detect_wifi_driver(self) -> str:
        """Detect the kernel driver of the active WiFi interface via sysfs.
        Normalizes sub-module names (e.g. rtw88_pci) to the canonical
        DRIVER_PROFILES key (rtw88)."""
        iface = self._get_wifi_interface()
        if not iface:
            return "unknown"
        try:
            driver_path = os.path.realpath(f"/sys/class/net/{iface}/device/driver/module")
            module = os.path.basename(driver_path)
            if module in DRIVER_PROFILES:
                return module
            for key in DRIVER_PROFILES:
                if module.startswith(key):
                    return key
            return module
        except Exception:
            return "unknown"

    def _detect_distro(self) -> dict:
        """Detect OS from /etc/os-release. Returns {id, name}."""
        info = {"id": "unknown", "name": "Unknown"}
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("ID="):
                        info["id"] = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("PRETTY_NAME="):
                        info["name"] = line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
        return info

    async def get_device_info(self) -> dict:
        try:
            product, device_family, device_label = self._detect_device_family()
            driver = self._detect_wifi_driver()
            profile = DRIVER_PROFILES.get(driver, {})

            chip_label = profile.get("chip_label", "unknown")
            supports_6ghz = profile.get("supports_6ghz", False)

            model = "unknown"
            if device_family == "deck_lcd":
                model = "lcd"
            elif device_family == "deck_oled":
                model = "oled"

            return {
                "success": True,
                "model": model,
                "driver": driver,
                "device_family": device_family,
                "device_label": device_label,
                "chip_label": chip_label,
                "supports_6ghz": supports_6ghz,
            }
        except Exception as e:
            decky.logger.error(f"get_device_info error: {e}")
            return {
                "success": True,
                "model": "unknown",
                "driver": "unknown",
                "device_family": "unknown",
                "device_label": "Unknown Device",
                "chip_label": "unknown",
                "supports_6ghz": False,
            }

    def _get_support_tier(self) -> int:
        """Return 1 (full), 2 (partial), or 3 (generic) based on detection.
        Tier 1: recognized device + recognized driver.
        Tier 2: unknown device + recognized driver.
        Tier 3: unknown device + unknown driver."""
        settings = _load_settings()
        driver = settings.get("driver", "unknown")
        device_family = settings.get("device_family", "unknown")
        if driver in DRIVER_PROFILES and device_family != "unknown":
            return 1
        if driver in DRIVER_PROFILES:
            return 2
        return 3

    def _unexpected_response(self, e: Exception) -> dict:
        """Standard error dict for the catch-all exception handler in every
        setter. Callers log the error separately with the setter name."""
        return {"success": False, "error": "unexpected", "message": str(e)}

    def _nmcli_modify(self, uuid: str, key: str, value: str, timeout: int = 5) -> dict:
        """Run `nmcli con mod uuid <uuid> <key> <value>`. Returns the
        _run_cmd dict so callers can handle success/failure themselves."""
        return self._run_cmd(
            ["/usr/bin/nmcli", "con", "mod", "uuid", uuid, key, value],
            timeout=timeout,
        )

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

    # ---- Diagnostics ----

    async def get_diagnostic_info(self) -> dict:
        """Collect system info for remote debugging. Sanitized (no passwords)."""
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
            settings_dir = os.path.dirname(SETTINGS_FILE)
            _write_private_file(
                settings_dir, DIAGNOSTICS_NAME, json.dumps(info, indent=2)
            )
            return {"success": True, "path": os.path.join(settings_dir, DIAGNOSTICS_NAME)}
        except Exception as e:
            decky.logger.error(f"save_diagnostic_info error: {e}")
            return {"success": False, "error": str(e)}

    # ---- Status ----

    async def get_status(self) -> dict:
        # Use shorter timeout for read-only status queries to avoid blocking
        # the event loop if NM is unresponsive (~10 commands × 2s = 20s worst case)
        T = 2

        try:
            settings = _load_settings()
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
                status["live"]["dispatcher_installed"] = os.path.isfile(
                    DISPATCHER_PATH
                )
                return status

            # Remember UUID and ensure high autoconnect-priority so NM
            # prefers this profile over duplicates on boot (fixes 2.4GHz issue)
            if uuid and uuid != settings.get("last_connection_uuid"):
                settings["last_connection_uuid"] = uuid
                settings["priority_set"] = False
                _save_settings(settings)

            if uuid and not settings.get("priority_set"):
                # Bump priority to favor this profile over duplicates on boot.
                self._nmcli_modify(
                    uuid, "connection.autoconnect-priority", "100", timeout=T
                )
                settings["priority_set"] = True
                _save_settings(settings)

            # Power save
            ps_result = self._run_cmd(
                ["/usr/bin/iw", "dev", iface, "get", "power_save"], timeout=T
            )
            ps_off = "Power save: off" in ps_result.get("stdout", "")
            status["live"]["power_save_off"] = ps_off
            if settings.get("power_save_disabled") and not ps_off and gate_open:
                status["drift"]["power_save"] = True

            # Link info
            link_result = self._run_cmd(
                ["/usr/bin/iw", "dev", iface, "link"], timeout=T
            )
            link_out = link_result.get("stdout", "")
            for line in link_out.split("\n"):
                line = line.strip()
                if line.startswith("signal:"):
                    status["live"]["signal_dbm"] = line.split(":", 1)[1].strip()
                elif "tx bitrate:" in line:
                    status["live"]["tx_bitrate"] = line.split("tx bitrate:", 1)[
                        1
                    ].strip()
                elif line.startswith("freq:"):
                    status["live"]["frequency"] = line.split(":", 1)[1].strip()
                elif "Connected to" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        status["live"]["connected_bssid"] = parts[2]

            # Channel info - parse to "36 (80 MHz)" format
            info_result = self._run_cmd(
                ["/usr/bin/iw", "dev", iface, "info"], timeout=T
            )
            for line in info_result.get("stdout", "").split("\n"):
                line = line.strip()
                if line.startswith("channel"):
                    # Raw: "channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz"
                    parts = line.split(",")
                    chan_num = ""
                    width = ""
                    if parts:
                        tokens = parts[0].split()
                        if len(tokens) >= 2:
                            chan_num = tokens[1]
                    for part in parts:
                        part = part.strip()
                        if part.startswith("width:"):
                            width = part.split(":", 1)[1].strip()
                    if chan_num and width:
                        status["live"]["channel"] = f"{chan_num} ({width})"
                    elif chan_num:
                        status["live"]["channel"] = chan_num
                    else:
                        status["live"]["channel"] = line

            # BSSID lock
            bssid_result = self._run_cmd(
                [
                    "/usr/bin/nmcli",
                    "-t",
                    "-f",
                    "802-11-wireless.bssid",
                    "con",
                    "show",
                    "uuid",
                    uuid,
                ],
                timeout=T,
            )
            bssid_out = bssid_result.get("stdout", "")
            current_bssid_lock = ""
            if ":" in bssid_out:
                # Format: 802-11-wireless.bssid:AA\:BB\:CC\:DD\:EE\:FF
                parts = bssid_out.split(":", 1)
                if len(parts) == 2:
                    current_bssid_lock = parts[1].replace("\\", "").strip()
            status["live"]["bssid_lock"] = current_bssid_lock
            if settings.get("bssid_lock_enabled") and not current_bssid_lock:
                status["drift"]["bssid_lock"] = True

            # IP address
            ip_result = self._run_cmd(
                ["/usr/bin/nmcli", "-t", "-f", "IP4.ADDRESS", "dev", "show", iface],
                timeout=T,
            )
            ip_out = ip_result.get("stdout", "")
            # Format: IP4.ADDRESS[1]:192.168.1.100/24
            if ":" in ip_out:
                ip_addr = ip_out.split(":", 1)[1].split("/")[0].strip()
                status["live"]["ip_address"] = ip_addr

            # DNS
            dns_result = self._run_cmd(
                ["/usr/bin/nmcli", "-t", "-f", "IP4.DNS", "dev", "show", iface],
                timeout=T,
            )
            status["live"]["dns"] = dns_result.get("stdout", "")

            # IPv6
            ipv6_result = self._run_cmd(
                [
                    "/usr/bin/nmcli",
                    "-t",
                    "-f",
                    "ipv6.method",
                    "con",
                    "show",
                    "uuid",
                    uuid,
                ],
                timeout=T,
            )
            ipv6_out = ipv6_result.get("stdout", "")
            live_ipv6 = ipv6_out.split(":", 1)[1].strip() if ":" in ipv6_out else ""
            status["live"]["ipv6_method"] = live_ipv6
            if settings.get("ipv6_disabled") and live_ipv6 != "disabled":
                status["drift"]["ipv6"] = True
                self._nmcli_modify(uuid, "ipv6.method", "disabled", timeout=T)

            # Band preference
            band_result = self._run_cmd(
                [
                    "/usr/bin/nmcli",
                    "-t",
                    "-f",
                    "802-11-wireless.band",
                    "con",
                    "show",
                    "uuid",
                    uuid,
                ],
                timeout=T,
            )
            band_out = band_result.get("stdout", "")
            live_band = band_out.split(":", 1)[1].strip() if ":" in band_out else ""
            status["live"]["band"] = live_band
            expected_band = settings.get("band_preference", "a")
            if settings.get("band_preference_enabled") and live_band != expected_band:
                status["drift"]["band_preference"] = True
                self._nmcli_modify(uuid, "802-11-wireless.band", expected_band, timeout=T)

            # Buffer tuning
            sysctl_result = self._run_cmd(
                ["/usr/bin/sysctl", "-n", "net.core.rmem_max"], timeout=T
            )
            current_rmem = sysctl_result.get("stdout", "").strip()
            status["live"]["buffer_tuning_applied"] = current_rmem == "16777216"
            if (
                settings.get("buffer_tuning_enabled")
                and current_rmem != "16777216"
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
        except Exception as e:
            decky.logger.error(f"get_status error: {e}")
            return self._unexpected_response(e)

    # ---- Optimization setters ----

    async def set_power_save(self, disabled: bool) -> dict:
        try:
            settings = _load_settings()
            streaming_mode = settings.get("streaming_mode_enabled", False)
            # With streaming auto mode on and no stream running, enabling the
            # fix only records intent; the watcher applies it on detection.
            # Disabling always reverts the runtime state immediately.
            effective = disabled and self._volatile_gate_open(settings)

            result = self._apply_power_save_now(effective)
            if not result["success"]:
                return result

            # NM config is the persistent layer read by NetworkManager on
            # every reconnect. In streaming mode we skip it - it would force
            # power save off around the clock; the dispatcher and watcher
            # handle reconnects instead.
            if disabled and not streaming_mode:
                os.makedirs(os.path.dirname(NM_CONF_PATH), exist_ok=True)
                with open(NM_CONF_PATH, "w") as f:
                    f.write("[connection]\nwifi.powersave = 2\n")
            else:
                try:
                    os.remove(NM_CONF_PATH)
                except FileNotFoundError:
                    pass

            # Save settings only after success
            settings = _load_settings()
            settings["power_save_disabled"] = disabled
            _save_settings_with_timestamp(settings)

            return {"success": True, "power_save_off": disabled}
        except Exception as e:
            decky.logger.error(f"set_power_save error: {e}")
            return self._unexpected_response(e)

    async def set_auto_fix(self, enabled: bool) -> dict:
        try:

            settings = _load_settings()
            settings["auto_fix_on_wake"] = enabled

            if enabled:
                self._install_dispatcher()
            else:
                self._remove_dispatcher()

            _save_settings_with_timestamp(settings)
            return {
                "success": True,
                "dispatcher_installed": os.path.isfile(DISPATCHER_PATH),
            }
        except Exception as e:
            decky.logger.error(f"set_auto_fix error: {e}")
            return {"success": False, "error": "write_failed", "message": str(e)}

    async def set_bssid_lock(self, enabled: bool) -> dict:
        try:

            if enabled:
                # Enabling requires active WiFi to read current BSSID
                iface, uuid, err = self._require_wifi()
                if err:
                    return err

                link_result = self._run_cmd(["/usr/bin/iw", "dev", iface, "link"])
                link_out = link_result.get("stdout", "")
                bssid = ""
                for line in link_out.split("\n"):
                    if "Connected to" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            bssid = parts[2]
                        break

                if not bssid:
                    return {
                        "success": False,
                        "error": "no_wifi",
                        "message": "Could not determine current BSSID",
                    }

                result = self._nmcli_modify(uuid, "802-11-wireless.bssid", bssid)
                if not result["success"]:
                    return {
                        "success": False,
                        "error": "nmcli_failed",
                        "message": "Couldn't lock BSSID",
                        "detail": result["stderr"],
                    }

                settings = _load_settings()
                settings["bssid_lock_enabled"] = True
                settings["bssid_lock_value"] = bssid
                settings["bssid_lock_connection_uuid"] = uuid
                _save_settings_with_timestamp(settings)
                self._hard_reconnect(uuid)
            else:
                # Disabling works on saved profiles - no active WiFi needed
                iface, uuid, _ = self._require_wifi()
                if not uuid:
                    uuid = self._get_saved_connection_uuid()
                if not uuid:
                    return {
                        "success": False,
                        "error": "nmcli_failed",
                        "message": "No connection UUID found. Connect to WiFi first.",
                    }

                result = self._nmcli_modify(uuid, "802-11-wireless.bssid", "")
                if not result["success"]:
                    return {
                        "success": False,
                        "error": "nmcli_failed",
                        "message": "Couldn't unlock BSSID",
                        "detail": result["stderr"],
                    }

                settings = _load_settings()
                settings["bssid_lock_enabled"] = False
                settings["bssid_lock_value"] = ""
                settings["bssid_lock_connection_uuid"] = ""
                _save_settings_with_timestamp(settings)
                self._hard_reconnect(uuid)

            return {"success": True, "bssid_locked": enabled, "reconnected": True}
        except Exception as e:
            decky.logger.error(f"set_bssid_lock error: {e}")
            return self._unexpected_response(e)

    async def set_band_preference(self, enabled: bool, band: str = "a") -> dict:
        try:

            if enabled and band not in ("a", "bg"):
                return {
                    "success": False,
                    "error": "nmcli_failed",
                    "message": f"Invalid band '{band}'. Must be 'a' (5 GHz) or 'bg' (2.4 GHz).",
                }

            uuid, err = self._resolve_uuid(
                "Connect to WiFi first to set band preference" if enabled else None
            )
            if err:
                return err

            value = band if enabled else ""
            result = self._nmcli_modify(uuid, "802-11-wireless.band", value)
            if not result["success"]:
                return {
                    "success": False,
                    "error": "nmcli_failed",
                    "message": "Couldn't update band preference",
                    "detail": result["stderr"],
                }

            # Temporarily clear BSSID lock so NM can find an AP on the
            # requested band. Re-lock to the new BSSID after reconnect.
            settings = _load_settings()
            had_bssid_lock = settings.get("bssid_lock_enabled", False)
            if enabled and had_bssid_lock:
                self._nmcli_modify(uuid, "802-11-wireless.bssid", "")

            settings["band_preference_enabled"] = enabled
            settings["band_preference"] = band
            _save_settings_with_timestamp(settings)

            self._hard_reconnect(uuid)

            # Re-lock BSSID to whatever AP NM picked on the new band
            if enabled and had_bssid_lock:
                time.sleep(3)
                iface = self._get_wifi_interface()
                if iface:
                    link_result = self._run_cmd(["/usr/bin/iw", "dev", iface, "link"])
                    for line in link_result.get("stdout", "").split("\n"):
                        if "Connected to" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                new_bssid = parts[2]
                                self._nmcli_modify(uuid, "802-11-wireless.bssid", new_bssid)
                                settings = _load_settings()
                                settings["bssid_lock_value"] = new_bssid
                                _save_settings(settings)
                                decky.logger.info(f"Re-locked BSSID to {new_bssid} after band change")
                            break

            return {"success": True, "band": value, "reconnected": True}
        except Exception as e:
            decky.logger.error(f"set_band_preference error: {e}")
            return self._unexpected_response(e)

    async def set_dns(
        self, enabled: bool, provider: str = "cloudflare", custom_servers: str = ""
    ) -> dict:
        try:

            uuid, err = self._resolve_uuid(
                "Connect to WiFi first to set DNS" if enabled else None
            )
            if err:
                return err

            if enabled:
                if provider == "custom":
                    if not custom_servers or not custom_servers.strip():
                        return {
                            "success": False,
                            "error": "nmcli_failed",
                            "message": "Custom DNS servers cannot be empty",
                        }
                    servers = custom_servers.strip()
                elif provider in DNS_PROVIDERS:
                    servers = DNS_PROVIDERS[provider]
                else:
                    return {
                        "success": False,
                        "error": "nmcli_failed",
                        "message": f"Unknown DNS provider '{provider}'",
                    }

                result = self._nmcli_modify(uuid, "ipv4.dns", servers)
                if not result["success"]:
                    return {
                        "success": False,
                        "error": "nmcli_failed",
                        "message": "Couldn't set DNS",
                        "detail": result["stderr"],
                    }

                result2 = self._nmcli_modify(uuid, "ipv4.ignore-auto-dns", "yes")
                if not result2["success"]:
                    return {
                        "success": False,
                        "error": "nmcli_failed",
                        "message": "Couldn't set ignore-auto-dns",
                        "detail": result2["stderr"],
                    }
            else:
                self._nmcli_modify(uuid, "ipv4.dns", "")
                self._nmcli_modify(uuid, "ipv4.ignore-auto-dns", "no")
                servers = ""

            settings = _load_settings()
            settings["dns_enabled"] = enabled
            settings["dns_provider"] = provider
            settings["dns_servers"] = servers
            _save_settings_with_timestamp(settings)

            self._hard_reconnect(uuid)
            return {"success": True, "dns_set": enabled, "reconnected": True}
        except Exception as e:
            decky.logger.error(f"set_dns error: {e}")
            return self._unexpected_response(e)

    async def set_ipv6(self, disabled: bool) -> dict:
        try:

            uuid, err = self._resolve_uuid(
                "Connect to WiFi first to disable IPv6" if disabled else None
            )
            if err:
                return err

            method = "disabled" if disabled else "auto"
            result = self._nmcli_modify(uuid, "ipv6.method", method)
            if not result["success"]:
                return {
                    "success": False,
                    "error": "nmcli_failed",
                    "message": "Couldn't update IPv6 setting",
                    "detail": result["stderr"],
                }

            settings = _load_settings()
            settings["ipv6_disabled"] = disabled
            _save_settings_with_timestamp(settings)

            self._hard_reconnect(uuid)
            return {"success": True, "ipv6_disabled": disabled, "reconnected": True}
        except Exception as e:
            decky.logger.error(f"set_ipv6 error: {e}")
            return self._unexpected_response(e)

    async def set_buffer_tuning(self, enabled: bool) -> dict:
        try:
            settings = _load_settings()
            # In streaming auto mode with no stream running, only record
            # intent; the watcher applies the tuning on detection.
            effective = enabled and self._volatile_gate_open(settings)
            self._apply_buffer_tuning_now(effective, settings)

            settings["buffer_tuning_enabled"] = enabled
            _save_settings_with_timestamp(settings)
            return {"success": True, "buffer_tuning": enabled}
        except Exception as e:
            decky.logger.error(f"set_buffer_tuning error: {e}")
            return self._unexpected_response(e)

    def _get_cake_status(self, iface: str) -> bool:
        """Check if CAKE qdisc is active on the interface."""
        result = self._run_cmd(["/usr/bin/tc", "qdisc", "show", "dev", iface])
        return "cake" in result.get("stdout", "")

    async def set_cake(self, enabled: bool) -> dict:
        """Enable or disable CAKE QoS (unlimited mode: FQ + AQM + ack-filter, no bandwidth shaper)."""
        try:
            settings = _load_settings()
            iface = self._get_wifi_interface()
            if not iface:
                if enabled:
                    return {"success": False, "error": "no_wifi", "message": "Not connected to WiFi."}
                settings["cake_enabled"] = False
                _save_settings_with_timestamp(settings)
                return {"success": True, "cake": False}

            # In streaming auto mode with no stream running, only record
            # intent; the watcher installs the qdisc on detection.
            effective = enabled and self._volatile_gate_open(settings)
            result = self._apply_cake_now(effective, settings)
            if enabled and effective and not result["success"]:
                return result
            decky.logger.info(
                f"CAKE {'enabled (unlimited)' if effective else 'disabled'} on {iface}"
            )

            settings = _load_settings()
            settings["cake_enabled"] = enabled
            _save_settings_with_timestamp(settings)
            return {"success": True, "cake": enabled}
        except Exception as e:
            decky.logger.error(f"set_cake error: {e}")
            return self._unexpected_response(e)

    async def set_streaming_mode(self, enabled: bool) -> dict:
        """Master toggle for streaming auto mode. When turning it on, run one
        immediate detection pass so an already-running stream is picked up
        without waiting for the watcher; when turning it off, fall back to the
        global toggles (apply immediately if any are enabled)."""
        try:
            self._ensure_streaming_state()
            self._streaming_misses = 0
            settings = _load_settings()
            settings["streaming_mode_enabled"] = enabled

            if enabled:
                detected = await asyncio.to_thread(
                    self._detect_streaming_app, settings
                )
                settings["streaming_active"] = bool(detected)
                settings["streaming_detected_app"] = detected or ""
                _save_settings_with_timestamp(settings)
                # NM conf would force power save off around the clock; the
                # watcher/dispatcher own that now.
                try:
                    os.remove(NM_CONF_PATH)
                except FileNotFoundError:
                    pass
                await self._apply_streaming_profile(bool(detected))
                decky.logger.info(
                    f"Streaming auto mode enabled (detected: {detected or 'none'})"
                )
            else:
                settings["streaming_active"] = False
                settings["streaming_detected_app"] = ""
                _save_settings_with_timestamp(settings)
                # Restore the persistent NM layer if the user wants power
                # save off globally.
                if settings.get("power_save_disabled"):
                    os.makedirs(os.path.dirname(NM_CONF_PATH), exist_ok=True)
                    with open(NM_CONF_PATH, "w") as f:
                        f.write("[connection]\nwifi.powersave = 2\n")
                await self._apply_streaming_profile(True)
                decky.logger.info("Streaming auto mode disabled - global toggles active")

            settings = _load_settings()
            return {
                "success": True,
                "streaming_mode_enabled": enabled,
                "streaming_active": settings.get("streaming_active", False),
                "streaming_detected_app": settings.get("streaming_detected_app", ""),
            }
        except Exception as e:
            decky.logger.error(f"set_streaming_mode error: {e}")
            return self._unexpected_response(e)

    async def set_streaming_app(self, app_id: str, enabled: bool) -> dict:
        """Enable/disable detection for one preset streaming app."""
        try:
            if app_id not in STREAMING_APPS:
                return {
                    "success": False,
                    "error": "unexpected",
                    "message": f"Unknown streaming app '{app_id}'",
                }
            settings = _load_settings()
            apps = dict(settings.get("streaming_apps", {}))
            apps[app_id] = enabled
            settings["streaming_apps"] = apps
            _save_settings(settings)
            # Re-detect immediately so e.g. disabling the currently-detected
            # app takes effect now instead of on the next watcher poll.
            await self._run_detection_pass(settle_immediately=True)
            return {"success": True, "app_id": app_id, "enabled": enabled}
        except Exception as e:
            decky.logger.error(f"set_streaming_app error: {e}")
            return self._unexpected_response(e)

    async def set_streaming_custom_patterns(self, patterns: str) -> dict:
        """Store user-defined process patterns (space/comma separated)."""
        try:
            settings = _load_settings()
            settings["streaming_custom_patterns"] = (patterns or "").strip()
            _save_settings(settings)
            await self._run_detection_pass(settle_immediately=True)
            return {"success": True, "patterns": settings["streaming_custom_patterns"]}
        except Exception as e:
            decky.logger.error(f"set_streaming_custom_patterns error: {e}")
            return self._unexpected_response(e)

    async def get_streaming_apps(self) -> dict:
        """Return the preset app catalog for the UI (labels + ids)."""
        return {
            "success": True,
            "apps": [
                {"id": app_id, "label": info["label"]}
                for app_id, info in STREAMING_APPS.items()
            ],
        }

    async def optimize_safe(self) -> dict:
        """Apply universally-safe optimizations: power save, BSSID lock, auto-fix, buffer tuning."""
        try:

            results = {}
            applied = 0
            total = 4

            # Order matters: BSSID lock reconnects WiFi which resets power_save.
            # Apply auto-fix and buffer tuning first (no reconnect), then BSSID
            # lock (reconnects - dispatcher reapplies settings), then power_save
            # last to ensure it sticks.
            r = await self.set_auto_fix(True)
            results["auto_fix"] = r
            if r.get("success"):
                applied += 1

            r = await self.set_buffer_tuning(True)
            results["buffer_tuning"] = r
            if r.get("success"):
                applied += 1

            r = await self.set_bssid_lock(True)
            results["bssid_lock"] = r
            if r.get("success"):
                applied += 1

            r = await self.set_power_save(True)
            results["power_save"] = r
            if r.get("success"):
                applied += 1

            settings = _load_settings()
            settings["last_applied"] = int(time.time())
            _save_settings(settings)

            return {
                "success": True,
                "total": total,
                "applied": applied,
                "results": results,
                "reconnected": True,
            }
        except Exception as e:
            decky.logger.error(f"optimize_safe error: {e}")
            return self._unexpected_response(e)

    async def reapply_volatile(self) -> dict:
        """Reapply volatile (non-reconnecting) settings. Safe to call mid-stream."""
        try:
            settings = _load_settings()
            if not self._volatile_gate_open(settings):
                # Streaming auto mode with no stream running: standard
                # settings are the desired state, nothing to reapply.
                return {"success": True, "applied": 0, "total": 0, "gated": True}
            applied = 0
            total = 0

            if settings.get("power_save_disabled"):
                total += 1
                r = await self.set_power_save(True)
                if r.get("success"):
                    applied += 1

            if settings.get("buffer_tuning_enabled"):
                total += 1
                r = await self.set_buffer_tuning(True)
                if r.get("success"):
                    applied += 1

            if settings.get("cake_enabled"):
                total += 1
                r = await self.set_cake(True)
                if r.get("success"):
                    applied += 1

            if total > 0:
                decky.logger.info(f"reapply_volatile: {applied}/{total} applied")

            return {"success": True, "applied": applied, "total": total}
        except Exception as e:
            decky.logger.error(f"reapply_volatile error: {e}")
            return self._unexpected_response(e)

    async def reapply_all(self) -> dict:
        """Force reapply all enabled optimizations."""
        try:

            settings = _load_settings()
            results = {}
            applied = 0
            total = 0
            did_reconnect = False

            # Non-reconnecting first
            if settings.get("auto_fix_on_wake"):
                total += 1
                r = await self.set_auto_fix(True)
                results["auto_fix"] = r
                if r.get("success"):
                    applied += 1

            if settings.get("buffer_tuning_enabled"):
                total += 1
                r = await self.set_buffer_tuning(True)
                results["buffer_tuning"] = r
                if r.get("success"):
                    applied += 1

            if settings.get("cake_enabled"):
                total += 1
                r = await self.set_cake(True)
                results["cake"] = r
                if r.get("success"):
                    applied += 1

            # Reconnecting (each does hard_reconnect)
            if settings.get("bssid_lock_enabled"):
                total += 1
                r = await self.set_bssid_lock(True)
                results["bssid_lock"] = r
                if r.get("success"):
                    applied += 1
                did_reconnect = True

            if settings.get("band_preference_enabled"):
                total += 1
                r = await self.set_band_preference(
                    True, settings.get("band_preference", "a")
                )
                results["band_preference"] = r
                if r.get("success"):
                    applied += 1
                did_reconnect = True

            if settings.get("dns_enabled"):
                total += 1
                r = await self.set_dns(
                    True,
                    settings.get("dns_provider", "cloudflare"),
                    settings.get("dns_servers", ""),
                )
                results["dns"] = r
                if r.get("success"):
                    applied += 1
                did_reconnect = True

            if settings.get("ipv6_disabled"):
                total += 1
                r = await self.set_ipv6(True)
                results["ipv6"] = r
                if r.get("success"):
                    applied += 1
                did_reconnect = True

            # Power save last (sticks after any reconnects, dispatcher also reapplies)
            if settings.get("power_save_disabled"):
                total += 1
                r = await self.set_power_save(True)
                results["power_save"] = r
                if r.get("success"):
                    applied += 1

            if total == 0:
                return {
                    "success": True,
                    "total": 0,
                    "applied": 0,
                    "results": {},
                    "message": "No optimizations enabled",
                }

            result = {
                "success": True,
                "total": total,
                "applied": applied,
                "results": results,
            }
            if did_reconnect:
                result["reconnected"] = True
            return result
        except Exception as e:
            decky.logger.error(f"reapply_all error: {e}")
            return self._unexpected_response(e)

    async def reset_settings(self) -> dict:
        """Delete settings and revert to defaults."""
        try:
            # Revert runtime state
            self._apply_driver_fixes(False)
            self._apply_pcie_aspm_fix(False)
            for key, value in SYSCTL_DEFAULTS.items():
                self._run_cmd(["/usr/bin/sysctl", "-w", f"{key}={value}"])
            iface = self._get_wifi_interface()
            if iface:
                self._run_cmd(["/usr/bin/ip", "link", "set", iface, "txqueuelen", "1000"])
                self._run_cmd(["/usr/bin/tc", "qdisc", "del", "dev", iface, "root"])
            try:
                os.remove(NM_CONF_PATH)
            except FileNotFoundError:
                pass
            try:
                os.remove(MODPROBE_CONF_PATH)
            except FileNotFoundError:
                pass
            try:
                os.remove(SETTINGS_FILE)
            except FileNotFoundError:
                pass
            try:
                os.remove(ENFORCED_FILE)
            except FileNotFoundError:
                pass
            try:
                os.remove(GENERIC_BACKEND_CONF)
            except FileNotFoundError:
                pass

            # Repopulate model/driver so the plugin doesn't show as "UNKNOWN /
            # Unsupported device" until the next plugin reload. Mirrors the
            # hardware detection _main does on startup.
            info = await self.get_device_info()
            fresh = dict(DEFAULT_SETTINGS)
            fresh["model"] = info.get("model", "unknown")
            fresh["driver"] = info.get("driver", "unknown")
            fresh["device_family"] = info.get("device_family", "unknown")
            fresh["device_label"] = info.get("device_label", "Unknown Device")
            fresh["chip_label"] = info.get("chip_label", "unknown")
            fresh["supports_6ghz"] = info.get("supports_6ghz", False)
            distro = self._detect_distro()
            fresh["distro_id"] = distro["id"]
            fresh["distro_name"] = distro["name"]
            _save_settings(fresh)

            decky.logger.info("Settings reset to defaults")
            return {"success": True, "message": "Settings reset to defaults"}
        except Exception as e:
            decky.logger.error(f"reset_settings error: {e}")
            return self._unexpected_response(e)

    # ---- Updates ----

    async def set_update_channel(self, channel: str) -> dict:
        """Set the update channel to 'stable' or 'beta'."""
        try:
            if channel not in ("stable", "beta"):
                return {"success": False, "message": "Channel must be 'stable' or 'beta'"}
            settings = _load_settings()
            settings["update_channel"] = channel
            _save_settings(settings)
            decky.logger.info(f"Update channel set to {channel}")
            return {"success": True, "channel": channel}
        except Exception as e:
            decky.logger.error(f"set_update_channel error: {e}")
            return self._unexpected_response(e)

    # Fork note: self-update pulls from this repo, not upstream
    # (ArcadaLabs-Jason/WifiOptimizer), so upstream releases can't overwrite
    # the streaming-mode changes. Empty string disables self-update entirely.
    UPDATE_REPO = "bassobr/Decky-Wifi-Streaming-Optimizer"

    async def check_for_update(self) -> dict:
        """Check GitHub for a newer version (stable release or beta branch)."""
        try:
            if not self.UPDATE_REPO:
                return {
                    "success": True,
                    "current_version": decky.DECKY_PLUGIN_VERSION,
                    "update_available": False,
                    "channel": "stable",
                    "message": "Updates disabled in this fork",
                }
            current = decky.DECKY_PLUGIN_VERSION
            settings = _load_settings()
            channel = settings.get("update_channel", "stable")
            decky.logger.info(f"Update check: current={current}, channel={channel}")

            if channel == "beta":
                result = await asyncio.to_thread(
                    self._run_cmd,
                    [
                        "/usr/bin/curl", "-sL", "--connect-timeout", "3", "--max-time", "10",
                        "-H", "Accept: application/vnd.github.raw+json",
                        f"https://api.github.com/repos/{self.UPDATE_REPO}/contents/package.json?ref=beta",
                    ],
                    15,
                    True,
                )
            else:
                result = await asyncio.to_thread(
                    self._run_cmd,
                    [
                        "/usr/bin/curl", "-sL", "--connect-timeout", "3", "--max-time", "10",
                        "-H", "Accept: application/vnd.github.v3+json",
                        f"https://api.github.com/repos/{self.UPDATE_REPO}/releases/latest",
                    ],
                    15,
                    True,
                )

            if not result["success"] or not result["stdout"]:
                decky.logger.error(f"Update check: curl failed - rc={result.get('returncode')}, stderr={result.get('stderr', '')[:200]}")
                return {
                    "success": False,
                    "current_version": current,
                    "update_available": False,
                    "channel": channel,
                    "message": "Couldn't reach GitHub",
                }

            data = json.loads(result["stdout"])

            if channel == "beta":
                latest = data.get("version", "")
            else:
                tag = data.get("tag_name", "")
                latest = tag.lstrip("v")

            if not latest:
                msg = data.get("message", "couldn't parse version")
                decky.logger.error(f"Update check: no version - {msg}")
                return {
                    "success": False,
                    "current_version": current,
                    "update_available": False,
                    "channel": channel,
                    "message": msg,
                }

            # Beta: update if versions differ (allows downgrade back to stable)
            # Stable: update only if newer (strip -beta suffix for comparison)
            if channel == "beta":
                update_available = latest != current
            else:
                current_clean = current.split("-")[0]
                latest_clean = latest.split("-")[0]
                current_tuple = tuple(int(x) for x in current_clean.split("."))
                latest_tuple = tuple(int(x) for x in latest_clean.split("."))
                update_available = latest_tuple > current_tuple or (
                    "-beta" in current and latest_tuple >= current_tuple
                )

            decky.logger.info(f"Update check: current={current}, latest={latest}, channel={channel}, update={update_available}")

            return {
                "success": True,
                "current_version": current,
                "latest_version": latest,
                "update_available": update_available,
                "channel": channel,
            }
        except Exception as e:
            decky.logger.error(f"check_for_update error: {e}")
            return {
                "success": False,
                "current_version": decky.DECKY_PLUGIN_VERSION,
                "update_available": False,
                "message": str(e),
            }

    def _download_file(self, url: str, dest: str, timeout: int = 60) -> dict:
        """Download url to dest with curl. -f makes HTTP errors fail the
        command instead of saving an error page."""
        return self._run_cmd(
            [
                "/usr/bin/curl", "-fsSL", "--connect-timeout", "5",
                "--max-time", str(timeout), "-o", dest, url,
            ],
            timeout=timeout + 5,
            clean_env=True,
        )

    # The detached hand-off script is fixed text: every variable it needs
    # (paths, label) arrives via the environment, never via interpolation
    # into shell code, and it reaches bash through stdin so there is no
    # on-disk script file an unprivileged user could pre-create or swap
    # under root (SEC-02). It only copies from the root-owned staging dir.
    _UPDATE_HANDOFF_SCRIPT = """#!/bin/bash
sleep 1
ok=1
for f in plugin.json package.json main.py decky.pyi; do
    cp "$WIFIOPT_SRC/$f" "$WIFIOPT_PLUGIN_DIR/" || ok=0
done
mkdir -p "$WIFIOPT_PLUGIN_DIR/dist" "$WIFIOPT_PLUGIN_DIR/defaults" "$WIFIOPT_PLUGIN_DIR/py_modules"
cp "$WIFIOPT_SRC/dist/index.js" "$WIFIOPT_PLUGIN_DIR/dist/" || ok=0
cp "$WIFIOPT_SRC/dist/index.js.map" "$WIFIOPT_PLUGIN_DIR/dist/" 2>/dev/null || true
cp "$WIFIOPT_SRC/defaults/dispatcher.sh.tmpl" "$WIFIOPT_PLUGIN_DIR/defaults/" || ok=0
if [ "$ok" = "1" ]; then
    logger -t wifi-optimizer "Updated to $WIFIOPT_LABEL, restarting plugin_loader"
else
    logger -t wifi-optimizer "Update to $WIFIOPT_LABEL failed while copying files"
fi
rm -rf "$WIFIOPT_STAGE"
systemctl restart plugin_loader 2>/dev/null || true
"""

    async def apply_update(self) -> dict:
        """Download, verify, and install an update from the selected channel,
        then restart Decky. Stable installs the CI-built release zip and
        checks it against the release's SHA256SUMS; beta installs the branch
        tarball (no release artifact exists to verify against)."""
        try:
            if not self.UPDATE_REPO:
                return {"success": False, "message": "Updates disabled in this fork."}
            if getattr(self, "_update_in_progress", False):
                return {"success": False, "message": "An update is already in progress."}
            self._update_in_progress = True
            try:
                return await self._apply_update_inner()
            finally:
                self._update_in_progress = False
        except Exception as e:
            decky.logger.error(f"apply_update error: {e}")
            return self._unexpected_response(e)

    async def _apply_update_inner(self) -> dict:
        info = await self.check_for_update()
        if not info.get("update_available"):
            return {"success": False, "message": "No update available."}
        channel = info.get("channel", "stable")
        latest = str(info.get("latest_version", ""))
        if not VERSION_RE.match(latest):
            return {
                "success": False,
                "message": f"Refusing update: unexpected version string {latest!r}",
            }
        repo_name = self.UPDATE_REPO.split("/")[1]

        # Root-owned staging with an unpredictable name (mkdtemp = mode
        # 0700): nothing under it can be pre-created or swapped by an
        # unprivileged user before the hand-off script copies from it.
        stage_root = tempfile.mkdtemp(prefix="wifi-optimizer-update-")
        handed_off = False
        try:
            extract_dir = os.path.join(stage_root, "src")
            if channel == "beta":
                # Beta has no release artifact to verify against; this path
                # stays TLS/repo trust only, matching the channel's purpose.
                url = f"https://github.com/{self.UPDATE_REPO}/archive/refs/heads/beta.tar.gz"
                tar_path = os.path.join(stage_root, "update.tar.gz")
                r = await asyncio.to_thread(self._download_file, url, tar_path)
                if not r["success"]:
                    return {
                        "success": False,
                        "message": "Couldn't download the beta update.",
                        "detail": r.get("stderr", "")[:200],
                    }
                await asyncio.to_thread(_safe_extract_tar, tar_path, extract_dir)
                src = os.path.join(extract_dir, f"{repo_name}-beta")
                label = f"beta v{latest}"
                decky.logger.info(
                    "apply_update: beta channel has no checksum artifact; TLS/repo trust only"
                )
            else:
                tag = f"v{latest}"
                zip_name = f"wifi-optimizer-streaming-{latest}.zip"
                base = f"https://github.com/{self.UPDATE_REPO}/releases/download/{tag}"
                zip_path = os.path.join(stage_root, zip_name)
                sums_path = os.path.join(stage_root, "SHA256SUMS")
                r = await asyncio.to_thread(
                    self._download_file, f"{base}/{zip_name}", zip_path
                )
                if not r["success"]:
                    return {
                        "success": False,
                        "message": f"Couldn't download release asset {zip_name}.",
                        "detail": r.get("stderr", "")[:200],
                    }
                r = await asyncio.to_thread(
                    self._download_file, f"{base}/SHA256SUMS", sums_path, 15
                )
                if not r["success"]:
                    return {
                        "success": False,
                        "message": "Couldn't download SHA256SUMS for verification.",
                        "detail": r.get("stderr", "")[:200],
                    }
                with open(sums_path, "r") as f:
                    sums_text = f.read()
                ok, detail = _verify_sha256(sums_text, zip_name, zip_path)
                if not ok:
                    decky.logger.error(f"apply_update: checksum verification failed: {detail}")
                    return {
                        "success": False,
                        "message": "Checksum verification failed - update aborted.",
                        "detail": detail,
                    }
                await asyncio.to_thread(_safe_extract_zip, zip_path, extract_dir)
                src = os.path.join(extract_dir, "WiFi Optimizer Streaming")
                label = f"v{latest}"

            if not os.path.isfile(os.path.join(src, "plugin.json")):
                return {
                    "success": False,
                    "message": "Update package has an unexpected layout - aborted.",
                }

            # Detached hand-off: the copy + plugin_loader restart must survive
            # this process being killed by that restart.
            env = {k: v for k, v in os.environ.items() if k != "LD_LIBRARY_PATH"}
            env.update({
                "WIFIOPT_SRC": src,
                "WIFIOPT_PLUGIN_DIR": decky.DECKY_PLUGIN_DIR,
                "WIFIOPT_STAGE": stage_root,
                "WIFIOPT_LABEL": label,
            })
            proc = subprocess.Popen(
                ["/bin/bash", "-s"],
                stdin=subprocess.PIPE,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
            proc.stdin.write(self._UPDATE_HANDOFF_SCRIPT.encode())
            proc.stdin.close()
            handed_off = True

            verified = "yes" if channel != "beta" else "no (beta)"
            decky.logger.info(
                f"Update to {label} initiated (channel={channel}, checksum verified={verified})"
            )
            return {"success": True, "message": f"Updating to {label}..."}
        finally:
            if not handed_off:
                shutil.rmtree(stage_root, ignore_errors=True)

    # ---- WiFi backend switch (iwd / wpa_supplicant) ----

    async def _backend_switch_worker(self, target: str):
        """Background task that switches the WiFi backend with phase transitions.

        Invokes the privileged helper directly (at /usr/bin/steamos-polkit-helpers/…)
        to bypass pkexec, which fails from a rootful systemd context with no polkit
        agent. The helper handles wlan0 recovery on ath11k devices internally; we parse its
        output to report whether recovery fired.
        """
        try:
            settings = _load_settings()
            has_wlan0_quirk = settings.get("driver") == "ath11k_pci"
            other = "iwd" if target == "wpa_supplicant" else "wpa_supplicant"

            # Phase: switching - write config then restart services.
            # clean_env=True clears LD_LIBRARY_PATH so bash doesn't hit a symbol
            # lookup error against Decky's bundled readline (same class of bug
            # as the curl/OpenSSL conflict).
            self._backend_switch["phase"] = "switching"
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
                self._backend_switch["phase"] = "failed"
                self._backend_switch["result"] = {
                    "success": False,
                    "target": target,
                    "message": self._friendly_backend_error(detail),
                    "detail": detail,
                }
                decky.logger.error(
                    f"backend switch failed at write_config: rc={write_result.get('returncode')}, "
                    f"detail={detail!r}"
                )
                return

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

            # Phase: reconnecting. Poll nmcli at 1-second cadence for up to 15s
            # to confirm WiFi actually comes back. 15s is generous for typical
            # NM reconnect (about 5s on wpa_supplicant, 1-2s on iwd) but not
            # so long that users with dead networks wait forever.
            reconnect_timed_out = False
            if not needs_reboot:
                self._backend_switch["phase"] = "reconnecting"
                elapsed = 0
                reconnected = False
                while elapsed < 15:
                    iface = await asyncio.to_thread(self._get_wifi_interface)
                    uuid = None
                    if iface:
                        uuid = await asyncio.to_thread(self._get_active_connection_uuid)
                    if iface and uuid:
                        reconnected = True
                        break
                    await asyncio.sleep(1)
                    elapsed += 1
                reconnect_timed_out = not reconnected

            # Verify final system state
            final_backend = await asyncio.to_thread(self._get_current_backend)

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
            elif not restart_result["success"] or final_backend != target:
                detail = rs_stderr[:200] or rs_stdout[:200]
                self._backend_switch["phase"] = "failed"
                self._backend_switch["result"] = {
                    "success": False,
                    "backend": final_backend,
                    "target": target,
                    "recovery_performed": recovery_performed,
                    "needs_reboot": False,
                    "reconnect_timed_out": reconnect_timed_out,
                    "message": self._friendly_backend_error(detail),
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
                f"backend switch: target={target}, final={final_backend}, "
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
            decky.logger.error(f"_backend_switch_worker error: {e}")
            self._backend_switch["phase"] = "failed"
            self._backend_switch["result"] = {
                "success": False,
                "target": target,
                "message": str(e),
            }
        finally:
            self._backend_switch["in_progress"] = False

    async def _generic_backend_switch_worker(self, target: str):
        """Backend switch for non-SteamOS systems (Bazzite, CachyOS, etc.).
        Writes NM config directly and manages systemd services."""
        try:
            other = "iwd" if target == "wpa_supplicant" else "wpa_supplicant"

            self._backend_switch["phase"] = "switching"
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
                self._backend_switch["phase"] = "failed"
                self._backend_switch["result"] = {
                    "success": False,
                    "target": target,
                    "message": self._friendly_backend_error(detail),
                    "detail": detail,
                }
                return

            # Phase: reconnecting
            self._backend_switch["phase"] = "reconnecting"
            reconnect_timed_out = True
            for _ in range(15):
                await asyncio.sleep(1)
                iface = await asyncio.to_thread(self._get_wifi_interface)
                if iface:
                    uuid = await asyncio.to_thread(self._get_active_connection_uuid)
                    if uuid:
                        reconnect_timed_out = False
                        break

            final_backend = await asyncio.to_thread(self._get_current_backend)

            if final_backend == target:
                self._backend_switch["phase"] = "done"
                self._backend_switch["result"] = {
                    "success": True,
                    "backend": final_backend,
                    "target": target,
                    "recovery_performed": False,
                    "needs_reboot": False,
                    "reconnect_timed_out": reconnect_timed_out,
                }
            else:
                self._backend_switch["phase"] = "failed"
                self._backend_switch["result"] = {
                    "success": False,
                    "backend": final_backend,
                    "target": target,
                    "recovery_performed": False,
                    "needs_reboot": False,
                    "reconnect_timed_out": reconnect_timed_out,
                    "message": f"Expected {target} but got {final_backend}. A reboot may help.",
                }

            decky.logger.info(
                f"generic backend switch: target={target}, final={final_backend}, "
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
            decky.logger.error(f"_generic_backend_switch_worker error: {e}")
            self._backend_switch["phase"] = "failed"
            self._backend_switch["result"] = {
                "success": False,
                "target": target,
                "message": str(e),
            }
        finally:
            self._backend_switch["in_progress"] = False

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
