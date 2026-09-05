"""Persistent optimization setters and the bulk actions built on them."""

import asyncio
import copy
import os
import time

from . import settings as settings_store
from .constants import (
    DEFAULT_SETTINGS,
    DIAGNOSTICS_NAME,
    DISPATCHER_PATH,
    DNS_PROVIDERS,
    ENFORCED_FILE,
    GENERIC_BACKEND_CONF,
    LEGACY_ENFORCED_NAME,
    MODPROBE_CONF_PATH,
    NM_CONF_PATH,
)
from .deckyshim import decky


class SettersMixin:
    async def set_power_save(self, disabled: bool) -> dict:
        try:
            settings = settings_store.load_settings()
            streaming_mode = settings.get("streaming_mode_enabled", False)
            # With streaming auto mode on and no stream running, enabling the
            # fix only records intent; the watcher applies it on detection.
            # Disabling always reverts the runtime state immediately.
            effective = disabled and self._volatile_gate_open(settings)

            result = await asyncio.to_thread(self._apply_power_save_now, effective)
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
            settings = settings_store.load_settings()
            settings["power_save_disabled"] = disabled
            settings_store.save_settings_with_timestamp(settings)

            return {"success": True, "power_save_off": disabled}
        except Exception as e:
            decky.logger.error(f"set_power_save error: {e}")
            return self._unexpected_response(e)

    async def set_auto_fix(self, enabled: bool) -> dict:
        try:

            settings = settings_store.load_settings()
            settings["auto_fix_on_wake"] = enabled

            if enabled:
                self._install_dispatcher()
            else:
                self._remove_dispatcher()

            settings_store.save_settings_with_timestamp(settings)
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

                bssid = await asyncio.to_thread(self._get_connected_bssid, iface)

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

                settings = settings_store.load_settings()
                settings["bssid_lock_enabled"] = True
                settings["bssid_lock_value"] = bssid
                settings["bssid_lock_connection_uuid"] = uuid
                settings_store.save_settings_with_timestamp(settings)
                await asyncio.to_thread(self._hard_reconnect, uuid)
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

                settings = settings_store.load_settings()
                settings["bssid_lock_enabled"] = False
                settings["bssid_lock_value"] = ""
                settings["bssid_lock_connection_uuid"] = ""
                settings_store.save_settings_with_timestamp(settings)
                await asyncio.to_thread(self._hard_reconnect, uuid)

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
            settings = settings_store.load_settings()
            had_bssid_lock = settings.get("bssid_lock_enabled", False)
            if enabled and had_bssid_lock:
                self._nmcli_modify(uuid, "802-11-wireless.bssid", "")

            settings["band_preference_enabled"] = enabled
            settings["band_preference"] = band
            settings_store.save_settings_with_timestamp(settings)

            await asyncio.to_thread(self._hard_reconnect, uuid)

            # Re-lock BSSID to whatever AP NM picked on the new band
            if enabled and had_bssid_lock:
                # await, not time.sleep: a blocking sleep would freeze every
                # IPC call for 3s (FUNC-02).
                await asyncio.sleep(3)

                def _relock() -> str:
                    iface = self._get_wifi_interface()
                    if not iface:
                        return ""
                    new_bssid = self._get_connected_bssid(iface)
                    if new_bssid:
                        self._nmcli_modify(uuid, "802-11-wireless.bssid", new_bssid)
                    return new_bssid

                new_bssid = await asyncio.to_thread(_relock)
                if new_bssid:
                    # Reload after the awaits - another writer may have
                    # saved settings in the meantime.
                    settings = settings_store.load_settings()
                    settings["bssid_lock_value"] = new_bssid
                    settings_store.save_settings(settings)
                    decky.logger.info(f"Re-locked BSSID to {new_bssid} after band change")

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
                # Check results like the enable path does - a failed revert
                # would otherwise leave the override active while the UI
                # says DNS is off (FUNC-08).
                result = self._nmcli_modify(uuid, "ipv4.dns", "")
                if not result["success"]:
                    return {
                        "success": False,
                        "error": "nmcli_failed",
                        "message": "Couldn't clear DNS override",
                        "detail": result["stderr"],
                    }
                result2 = self._nmcli_modify(uuid, "ipv4.ignore-auto-dns", "no")
                if not result2["success"]:
                    return {
                        "success": False,
                        "error": "nmcli_failed",
                        "message": "Couldn't restore automatic DNS",
                        "detail": result2["stderr"],
                    }
                servers = ""

            settings = settings_store.load_settings()
            settings["dns_enabled"] = enabled
            settings["dns_provider"] = provider
            settings["dns_servers"] = servers
            settings_store.save_settings_with_timestamp(settings)

            await asyncio.to_thread(self._hard_reconnect, uuid)
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

            settings = settings_store.load_settings()
            settings["ipv6_disabled"] = disabled
            settings_store.save_settings_with_timestamp(settings)

            await asyncio.to_thread(self._hard_reconnect, uuid)
            return {"success": True, "ipv6_disabled": disabled, "reconnected": True}
        except Exception as e:
            decky.logger.error(f"set_ipv6 error: {e}")
            return self._unexpected_response(e)

    async def set_buffer_tuning(self, enabled: bool) -> dict:
        try:
            settings = settings_store.load_settings()
            # In streaming auto mode with no stream running, only record
            # intent; the watcher applies the tuning on detection.
            effective = enabled and self._volatile_gate_open(settings)
            await asyncio.to_thread(self._apply_buffer_tuning_now, effective, settings)

            # Reload after the await: the applier snapshots values and other
            # writers may have saved; mutating the stale copy would undo that.
            settings = settings_store.load_settings()
            settings["buffer_tuning_enabled"] = enabled
            settings_store.save_settings_with_timestamp(settings)
            return {"success": True, "buffer_tuning": enabled}
        except Exception as e:
            decky.logger.error(f"set_buffer_tuning error: {e}")
            return self._unexpected_response(e)

    async def set_cake(self, enabled: bool) -> dict:
        """Enable or disable CAKE QoS (unlimited mode: FQ + AQM + ack-filter, no bandwidth shaper)."""
        try:
            settings = settings_store.load_settings()
            iface = self._get_wifi_interface()
            if not iface:
                if enabled:
                    return {"success": False, "error": "no_wifi", "message": "Not connected to WiFi."}
                settings["cake_enabled"] = False
                settings_store.save_settings_with_timestamp(settings)
                return {"success": True, "cake": False}

            # In streaming auto mode with no stream running, only record
            # intent; the watcher installs the qdisc on detection.
            effective = enabled and self._volatile_gate_open(settings)
            result = await asyncio.to_thread(self._apply_cake_now, effective, settings)
            if enabled and effective and not result["success"]:
                return result
            decky.logger.info(
                f"CAKE {'enabled (unlimited)' if effective else 'disabled'} on {iface}"
            )

            settings = settings_store.load_settings()
            settings["cake_enabled"] = enabled
            settings_store.save_settings_with_timestamp(settings)
            return {"success": True, "cake": enabled}
        except Exception as e:
            decky.logger.error(f"set_cake error: {e}")
            return self._unexpected_response(e)

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

            settings = settings_store.load_settings()
            settings["last_applied"] = int(time.time())
            settings_store.save_settings(settings)

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
            settings = settings_store.load_settings()
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

            settings = settings_store.load_settings()
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

    def _remove_plugin_files(self):
        """Delete the plugin's own state files (config, settings, runtime)."""
        for path in [NM_CONF_PATH, MODPROBE_CONF_PATH, GENERIC_BACKEND_CONF, ENFORCED_FILE]:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        directory = settings_store.settings_dir()
        base = os.path.basename(settings_store.SETTINGS_FILE)
        for name in [base, base + ".corrupt", base + ".tmp",
                     DIAGNOSTICS_NAME, LEGACY_ENFORCED_NAME]:
            settings_store.remove_private_file(directory, name)

    async def reset_settings(self) -> dict:
        """Delete settings and revert to defaults."""
        try:
            await asyncio.to_thread(self._revert_runtime_state)
            self._remove_plugin_files()

            # Repopulate model/driver so the plugin doesn't show as "UNKNOWN /
            # Unsupported device" until the next plugin reload. Mirrors the
            # hardware detection _main does on startup. deepcopy: a shallow
            # copy would share the nested streaming_apps dict with the module
            # constant (FUNC-09).
            info = await self.get_device_info()
            fresh = copy.deepcopy(DEFAULT_SETTINGS)
            fresh["model"] = info.get("model", "unknown")
            fresh["driver"] = info.get("driver", "unknown")
            fresh["device_family"] = info.get("device_family", "unknown")
            fresh["device_label"] = info.get("device_label", "Unknown Device")
            fresh["chip_label"] = info.get("chip_label", "unknown")
            fresh["supports_6ghz"] = info.get("supports_6ghz", False)
            distro = self._detect_distro()
            fresh["distro_id"] = distro["id"]
            fresh["distro_name"] = distro["name"]
            settings_store.save_settings(fresh)

            decky.logger.info("Settings reset to defaults")
            return {"success": True, "message": "Settings reset to defaults"}
        except Exception as e:
            decky.logger.error(f"reset_settings error: {e}")
            return self._unexpected_response(e)
