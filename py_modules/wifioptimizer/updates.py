"""Self-update: version check plus verified download and install.

Stable installs the CI-built release zip and checks it against the release's
SHA256SUMS; beta installs the branch tarball (no release artifact exists to
verify against). The final copy + plugin_loader restart is handed to a
detached bash reading fixed script text from stdin (SEC-02) - the updater
copies py_modules/ too, so the modularized backend survives updates.
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile

from . import settings as settings_store
from .archives import safe_extract_tar, safe_extract_zip, verify_sha256
from .constants import VERSION_RE
from .deckyshim import decky


class UpdatesMixin:
    # Fork note: self-update pulls from this repo, not upstream
    # (ArcadaLabs-Jason/WifiOptimizer), so upstream releases can't overwrite
    # the streaming-mode changes. Empty string disables self-update entirely.
    UPDATE_REPO = "bassobr/Decky-Wifi-Streaming-Optimizer"

    async def set_update_channel(self, channel: str) -> dict:
        """Set the update channel to 'stable' or 'beta'."""
        try:
            if channel not in ("stable", "beta"):
                return {"success": False, "message": "Channel must be 'stable' or 'beta'"}
            settings = settings_store.load_settings()
            settings["update_channel"] = channel
            settings_store.save_settings(settings)
            decky.logger.info(f"Update channel set to {channel}")
            return {"success": True, "channel": channel}
        except Exception as e:
            decky.logger.error(f"set_update_channel error: {e}")
            return self._unexpected_response(e)

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
            settings = settings_store.load_settings()
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
cp -r "$WIFIOPT_SRC/py_modules/." "$WIFIOPT_PLUGIN_DIR/py_modules/" || ok=0
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
                await asyncio.to_thread(safe_extract_tar, tar_path, extract_dir)
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
                ok, detail = verify_sha256(sums_text, zip_name, zip_path)
                if not ok:
                    decky.logger.error(f"apply_update: checksum verification failed: {detail}")
                    return {
                        "success": False,
                        "message": "Checksum verification failed - update aborted.",
                        "detail": detail,
                    }
                await asyncio.to_thread(safe_extract_zip, zip_path, extract_dir)
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
