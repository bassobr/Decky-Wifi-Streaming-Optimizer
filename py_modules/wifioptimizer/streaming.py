"""Streaming auto mode: process watcher, detection passes, and its setters.

With streaming_mode_enabled on, the volatile fixes are only held active while
a detected streaming app runs; the gate logic itself lives in appliers.py
(_volatile_gate_open), the fix application in _apply_streaming_profile.
"""

import asyncio
import os
import time

from . import settings as settings_store
from .constants import (
    MIN_PATTERN_LEN,
    NM_CONF_PATH,
    STREAMING_APPS,
    STREAMING_MISS_THRESHOLD,
    STREAMING_POLL_INTERVAL,
)
from .deckyshim import decky
from .parsing import build_patterns


class StreamingMixin:
    def _detect_streaming_app(self, settings: dict) -> str | None:
        """Scan /proc for a running streaming client. Returns the app label of
        the first match or None. Matches lowercase substrings against each
        process's full command line."""
        patterns = build_patterns(settings)
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
            settings = settings_store.load_settings()
            if not settings.get("streaming_mode_enabled"):
                return
            detected = await asyncio.to_thread(self._detect_streaming_app, settings)
            # Reload after the await: a setter may have written settings while
            # the scan ran in the thread; mutating that stale copy would
            # silently undo the user's change. Only the two runtime fields
            # below are touched on the fresh copy.
            settings = settings_store.load_settings()
            if not settings.get("streaming_mode_enabled"):
                return
            was_active = settings.get("streaming_active", False)
            if detected:
                self._streaming_misses = 0
                if not was_active:
                    settings["streaming_active"] = True
                    settings["streaming_detected_app"] = detected
                    settings_store.save_settings(settings)
                    decky.logger.info(
                        f"Streaming app detected: {detected} - applying fixes"
                    )
                    await asyncio.to_thread(self._apply_streaming_profile, True)
                elif detected != settings.get("streaming_detected_app"):
                    settings["streaming_detected_app"] = detected
                    settings_store.save_settings(settings)
            elif was_active:
                self._streaming_misses += 1
                if settle_immediately or self._streaming_misses >= STREAMING_MISS_THRESHOLD:
                    self._streaming_misses = 0
                    settings["streaming_active"] = False
                    settings["streaming_detected_app"] = ""
                    settings_store.save_settings(settings)
                    decky.logger.info(
                        "Streaming app exited - reverting to standard settings"
                    )
                    await asyncio.to_thread(self._apply_streaming_profile, False)
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
            settings = settings_store.load_settings()
            return {
                "success": True,
                "streaming_active": settings.get("streaming_active", False),
                "streaming_detected_app": settings.get("streaming_detected_app", ""),
            }
        except Exception as e:
            decky.logger.error(f"poke_detection error: {e}")
            return self._unexpected_response(e)

    async def set_streaming_mode(self, enabled: bool) -> dict:
        """Master toggle for streaming auto mode. When turning it on, run one
        immediate detection pass so an already-running stream is picked up
        without waiting for the watcher; when turning it off, fall back to the
        global toggles (apply immediately if any are enabled)."""
        try:
            self._ensure_streaming_state()
            self._streaming_misses = 0
            settings = settings_store.load_settings()
            settings["streaming_mode_enabled"] = enabled

            if enabled:
                detected = await asyncio.to_thread(
                    self._detect_streaming_app, settings
                )
                settings["streaming_active"] = bool(detected)
                settings["streaming_detected_app"] = detected or ""
                settings_store.save_settings_with_timestamp(settings)
                # NM conf would force power save off around the clock; the
                # watcher/dispatcher own that now.
                try:
                    os.remove(NM_CONF_PATH)
                except FileNotFoundError:
                    pass
                await asyncio.to_thread(self._apply_streaming_profile, bool(detected))
                decky.logger.info(
                    f"Streaming auto mode enabled (detected: {detected or 'none'})"
                )
            else:
                settings["streaming_active"] = False
                settings["streaming_detected_app"] = ""
                settings_store.save_settings_with_timestamp(settings)
                # Restore the persistent NM layer if the user wants power
                # save off globally.
                if settings.get("power_save_disabled"):
                    os.makedirs(os.path.dirname(NM_CONF_PATH), exist_ok=True)
                    with open(NM_CONF_PATH, "w") as f:
                        f.write("[connection]\nwifi.powersave = 2\n")
                await asyncio.to_thread(self._apply_streaming_profile, True)
                decky.logger.info("Streaming auto mode disabled - global toggles active")

            settings = settings_store.load_settings()
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
            settings = settings_store.load_settings()
            apps = dict(settings.get("streaming_apps", {}))
            apps[app_id] = enabled
            settings["streaming_apps"] = apps
            settings_store.save_settings(settings)
            # Re-detect immediately so e.g. disabling the currently-detected
            # app takes effect now instead of on the next watcher poll.
            await self._run_detection_pass(settle_immediately=True)
            return {"success": True, "app_id": app_id, "enabled": enabled}
        except Exception as e:
            decky.logger.error(f"set_streaming_app error: {e}")
            return self._unexpected_response(e)

    async def set_streaming_custom_patterns(self, patterns: str) -> dict:
        """Store user-defined process patterns (space/comma separated).
        Rejects tokens shorter than MIN_PATTERN_LEN - "a" would match half
        of /proc and silently pin the streaming gate open (FUNC-11)."""
        try:
            cleaned = (patterns or "").strip()
            too_short = [
                t for t in cleaned.replace(",", " ").split() if len(t) < MIN_PATTERN_LEN
            ]
            if too_short:
                return {
                    "success": False,
                    "error": "invalid_pattern",
                    "message": (
                        f"Patterns need at least {MIN_PATTERN_LEN} characters: "
                        + ", ".join(too_short)
                    ),
                }
            settings = settings_store.load_settings()
            settings["streaming_custom_patterns"] = cleaned
            settings_store.save_settings(settings)
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
