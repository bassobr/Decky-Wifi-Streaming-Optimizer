"""NetworkManager dispatcher script: rendering and (de)installation.

The dispatcher reapplies volatile optimizations on every WiFi reconnect,
independently of Decky. All tuning values are injected from constants.py so
plugin and dispatcher can never disagree.
"""

import os

from . import settings as settings_store
from .constants import (
    CAKE_QDISC_ARGS,
    DISPATCHER_PATH,
    DRIVER_PROFILES,
    ENFORCED_DIR,
    SYSCTL_PARAMS,
    TXQ_CAKE,
    TXQ_TUNED,
)
from .deckyshim import decky


class DispatcherMixin:
    def _render_dispatcher_script(self, template: str) -> str:
        """Render the dispatcher template. All tuning values (sysctl set,
        driver sysfs fixes, CAKE args, txqueuelen) are injected from the
        constants module so the plugin and the dispatcher can never disagree
        about what gets applied."""
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
            "__SETTINGS_PATH__": settings_store.SETTINGS_FILE,
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
