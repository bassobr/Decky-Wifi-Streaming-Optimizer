"""WiFi Optimizer backend for Decky Loader - entry point.

Runs as root inside the plugin_loader process. Decky requires the Plugin
class to live in main.py; the implementation is modularized under
py_modules/wifioptimizer (one module per domain - see that package's
__init__ docstring). This file only composes the Plugin class from those
mixins and owns the plugin lifecycle (_main/_unload/_uninstall).

State is persisted to settings.json under DECKY_PLUGIN_SETTINGS_DIR and
shared with the NetworkManager dispatcher script rendered from
defaults/dispatcher.sh.tmpl, which reapplies volatile optimizations (power
save, PCIe ASPM, buffer tuning, CAKE QoS) on every WiFi reconnect
independently of Decky.
"""

import os
import sys

_PLUGIN_ROOT = os.path.dirname(os.path.abspath(__file__))
_PY_MODULES = os.path.join(_PLUGIN_ROOT, "py_modules")
# Decky Loader puts py_modules/ on sys.path before loading main.py; insert it
# defensively anyway so tests and ad-hoc runs outside the loader work too.
if _PY_MODULES not in sys.path:
    sys.path.insert(0, _PY_MODULES)


def _self_heal_py_modules() -> bool:
    """Migration shim: updaters shipped before the modularization (<= v0.13.0)
    copied a fixed file list and dropped py_modules/ content, which would
    leave this main.py without its wifioptimizer package after an in-app
    update. Recover the package from this version's own release zip, verified
    against the release's SHA256SUMS. Checksum-only by design: the minisign
    verifier lives in the very package this shim restores, so it can't be
    used here; the shim only ever re-fetches the same already-installed
    version. Remove once pre-0.14 installs are extinct."""
    import hashlib
    import json
    import shutil
    import subprocess
    import tempfile
    import zipfile

    try:
        with open(os.path.join(_PLUGIN_ROOT, "package.json")) as f:
            version = json.load(f)["version"]
        repo = "bassobr/Decky-Wifi-Streaming-Optimizer"
        base = f"https://github.com/{repo}/releases/download/v{version}"
        zip_name = f"wifi-optimizer-streaming-{version}.zip"
        stage = tempfile.mkdtemp(prefix="wifi-optimizer-selfheal-")
        try:
            env = {k: v for k, v in os.environ.items() if k != "LD_LIBRARY_PATH"}
            for name in (zip_name, "SHA256SUMS"):
                subprocess.run(
                    [
                        "/usr/bin/curl", "-fsSL", "--connect-timeout", "5",
                        "--max-time", "60", "-o", os.path.join(stage, name),
                        f"{base}/{name}",
                    ],
                    check=True, env=env, timeout=70,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            expected = None
            with open(os.path.join(stage, "SHA256SUMS")) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[-1].lstrip("*") == zip_name:
                        expected = parts[0].lower()
            h = hashlib.sha256()
            with open(os.path.join(stage, zip_name), "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            if not expected or h.hexdigest() != expected:
                return False
            prefix = "WiFi Optimizer Streaming/py_modules/"
            with zipfile.ZipFile(os.path.join(stage, zip_name)) as z:
                for member in z.namelist():
                    norm = os.path.normpath(member)
                    if norm.startswith("..") or os.path.isabs(norm):
                        return False
                for member in z.namelist():
                    if not member.startswith(prefix) or member.endswith("/"):
                        continue
                    rel = member[len(prefix):]
                    dest = os.path.join(_PY_MODULES, rel)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with z.open(member) as src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
            import importlib
            importlib.invalidate_caches()
            return True
        finally:
            shutil.rmtree(stage, ignore_errors=True)
    except Exception:
        return False


_healed_py_modules = False
try:
    import wifioptimizer  # noqa: F401  (probe only - the package must exist)
except ImportError:
    _healed_py_modules = _self_heal_py_modules()
    # If healing failed, the imports below raise with a clear traceback and
    # Decky marks the plugin as failed; reinstalling via install.sh fixes it.

import asyncio

from wifioptimizer.appliers import AppliersMixin
from wifioptimizer.backend_switch import BackendSwitchMixin
from wifioptimizer.constants import LEGACY_ENFORCED_NAME
from wifioptimizer.deckyshim import decky
from wifioptimizer.dispatcher import DispatcherMixin
from wifioptimizer.hardware import HardwareMixin
from wifioptimizer.setters import SettersMixin
from wifioptimizer.status import StatusMixin
from wifioptimizer.streaming import StreamingMixin
from wifioptimizer.system import SystemMixin
from wifioptimizer.updates import UpdatesMixin
from wifioptimizer import settings as settings_store


class Plugin(
    SystemMixin,
    HardwareMixin,
    AppliersMixin,
    DispatcherMixin,
    StreamingMixin,
    StatusMixin,
    SettersMixin,
    UpdatesMixin,
    BackendSwitchMixin,
):
    """Root plugin instance. Decky exposes every async method (including the
    inherited mixin methods) as a callable from the React frontend.
    Synchronous helpers prefixed with `_` are for internal use only."""

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
            if _healed_py_modules:
                decky.logger.info(
                    "py_modules package was missing (update from a pre-0.14 "
                    "installer) and has been restored from the release zip"
                )
            self._rotate_logs()
            # last_enforced moved to root-owned /run (SEC-01); drop the legacy
            # copy from the user-writable settings dir.
            settings_store.remove_private_file(
                settings_store.settings_dir(), LEGACY_ENFORCED_NAME
            )
            self._ensure_backend_switch_state()
            info = await self.get_device_info()
            settings = settings_store.load_settings()
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
            stale_streaming_active = settings.get("streaming_active", False)
            settings["streaming_active"] = False
            settings["streaming_detected_app"] = ""
            settings_store.save_settings(settings)

            if settings.get("streaming_mode_enabled") and stale_streaming_active:
                # A crash or hard poweroff mid-stream left streaming_active
                # behind; if WiFi reconnected before this plugin started, the
                # dispatcher saw the open gate and applied the volatile fixes.
                # Revert to stock now - the watcher re-applies within one poll
                # if a stream really is running (FUNC-05).
                try:
                    await asyncio.to_thread(self._apply_streaming_profile, False)
                except Exception as e:
                    decky.logger.error(f"Startup streaming revert failed: {e}")

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
            await asyncio.to_thread(self._revert_runtime_state)
            self._remove_plugin_files()
        except Exception as e:
            decky.logger.error(f"_uninstall error: {e}")

    async def _migration(self):
        pass
