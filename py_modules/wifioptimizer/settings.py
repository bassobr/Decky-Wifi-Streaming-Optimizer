"""settings.json persistence.

Symlink-safe against the user-writable settings directory (the plugin runs as
root, SEC-01), thread-safe (get_status and the volatile-fix appliers run in
asyncio.to_thread workers), and cached on the file's (mtime_ns, size).
"""

import copy
import json
import os
import threading
import time

from .constants import DEFAULT_SETTINGS, STREAMING_APPS
from .deckyshim import decky

try:
    SETTINGS_FILE = os.path.join(decky.DECKY_PLUGIN_SETTINGS_DIR, "settings.json")
except Exception:
    SETTINGS_FILE = "/tmp/wifi-optimizer/settings.json"

# In-memory settings cache keyed on the file's (mtime_ns, size). Only this
# process writes settings.json, so the stat check exists purely to catch
# external edits/deletion; the steady-state win is that the 5s watcher poll
# and the 3s UI status poll stop hitting the disk. Callers get a deep copy -
# they mutate the result before saving, which must never leak into the cache.
_settings_cache: dict = {"stat": None, "data": None}

# The RLock keeps cache and file writes coherent across threads.
# Read-modify-write cycles that must be atomic go through
# update_settings_fields, which holds the lock for the whole cycle.
_settings_lock = threading.RLock()
_last_settings_error_log = 0.0

_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def settings_dir() -> str:
    return os.path.dirname(SETTINGS_FILE)


def open_private_dir(directory: str) -> int:
    """Open a directory fd, refusing symlinks. All root-owned file operations
    inside user-writable directories go through this fd so a user swapping
    the directory (or planting symlinks) between check and use cannot
    redirect root's writes elsewhere (SEC-01)."""
    return os.open(directory, os.O_RDONLY | _O_DIRECTORY | os.O_NOFOLLOW)


def write_private_file(directory: str, name: str, content: str):
    """Symlink-safe write of a root-created file into a possibly
    user-writable directory: never follow symlinks, never reuse a
    pre-created file (SEC-01)."""
    dfd = open_private_dir(directory)
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


def remove_private_file(directory: str, name: str):
    """Symlink-safe removal of a file inside a possibly user-writable dir."""
    try:
        dfd = open_private_dir(directory)
    except OSError:
        return
    try:
        try:
            os.remove(name, dir_fd=dfd)
        except FileNotFoundError:
            pass
    finally:
        os.close(dfd)


def load_settings() -> dict:
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


def save_settings(data: dict):
    directory = settings_dir()
    base = os.path.basename(SETTINGS_FILE)
    tmp_name = base + ".tmp"
    with _settings_lock:
        os.makedirs(directory, exist_ok=True)
        # Atomic write (tmp + rename), pinned to the real directory via
        # dir_fd and with O_EXCL|O_NOFOLLOW so a pre-created file or symlink
        # in the user-writable settings dir is refused instead of followed
        # by this root process (SEC-01).
        dfd = open_private_dir(directory)
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


def save_settings_with_timestamp(data: dict):
    """Save settings and update last_applied timestamp in one write."""
    data["last_applied"] = int(time.time())
    save_settings(data)


def update_settings_fields(**fields) -> dict:
    """Atomically load-set-save isolated settings fields. Safe from worker
    threads: the whole read-modify-write cycle holds the settings lock, so
    it can't clobber a concurrent save from the event loop."""
    with _settings_lock:
        settings = load_settings()
        settings.update(fields)
        save_settings(settings)
        return settings


def merge_snapshot(field: str, entries: dict):
    """Record pre-apply system values (sysctl, sysfs) without overwriting
    entries captured earlier; restores use them so reverting a fix brings
    back the machine's real prior state (FUNC-06)."""
    if not entries:
        return
    with _settings_lock:
        settings = load_settings()
        snap = dict(settings.get(field) or {})
        added = {k: v for k, v in entries.items() if k not in snap}
        if added:
            snap.update(added)
            settings[field] = snap
            save_settings(settings)
