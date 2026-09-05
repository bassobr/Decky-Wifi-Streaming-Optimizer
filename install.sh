#!/bin/bash
# WiFi Optimizer Streaming - Decky Plugin Installer
# Usage: curl -sL https://github.com/bassobr/Decky-Wifi-Streaming-Optimizer/raw/main/install.sh -o /tmp/wifi-opt-streaming-install.sh && sudo bash /tmp/wifi-opt-streaming-install.sh

set -e

PLUGIN_NAME="WiFi Optimizer Streaming"
REPO="bassobr/Decky-Wifi-Streaming-Optimizer"

# Check for root (needed to write to plugin dir and restart service)
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run with sudo."
    echo "Run: sudo bash $0"
    exit 1
fi

# Resolve the real user's home directory (same method as Decky's own installer)
DECK_USER="${SUDO_USER:-$(logname 2>/dev/null || echo deck)}"
USER_HOME="$(getent passwd "$DECK_USER" | cut -d: -f6)"
if [ -z "$USER_HOME" ]; then
    USER_HOME="/home/$DECK_USER"
fi

PLUGIN_BASE="$USER_HOME/homebrew/plugins"
PLUGIN_DIR="$PLUGIN_BASE/$PLUGIN_NAME"

# Check Decky is installed
if [ ! -d "$PLUGIN_BASE" ]; then
    echo "Error: Decky Loader not found at $PLUGIN_BASE"
    echo "Install it first: https://decky.xyz"
    exit 1
fi

TMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

extract_zip() {
    # SteamOS/Bazzite don't reliably ship unzip; bsdtar or python3 do the job.
    if command -v bsdtar >/dev/null 2>&1; then
        bsdtar -xf "$1" -C "$2"
    else
        python3 - "$1" "$2" <<'PYEOF'
import sys, zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
PYEOF
    fi
}

# Fetch latest release tag from GitHub
echo "Checking for latest release..."
RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true)
LATEST_TAG=$(printf '%s' "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

SRC=""
if [ -n "$LATEST_TAG" ]; then
    echo "Latest release: $LATEST_TAG"
    VERSION="${LATEST_TAG#v}"
    ZIP_NAME="wifi-optimizer-streaming-${VERSION}.zip"
    ASSET_BASE="https://github.com/$REPO/releases/download/${LATEST_TAG}"

    # Preferred path: the CI-built release zip, verified against the
    # release's SHA256SUMS. The source tarball below is only a fallback.
    if curl -fsSL -o "$TMP_DIR/$ZIP_NAME" "$ASSET_BASE/$ZIP_NAME" 2>/dev/null; then
        echo "Downloaded release build."
        if curl -fsSL -o "$TMP_DIR/SHA256SUMS" "$ASSET_BASE/SHA256SUMS" 2>/dev/null; then
            echo "Verifying checksum..."
            if ! (cd "$TMP_DIR" && sha256sum --check --ignore-missing SHA256SUMS); then
                echo "Error: checksum verification failed - aborting."
                exit 1
            fi
        else
            echo "Warning: no SHA256SUMS published for $LATEST_TAG - installing unverified."
        fi
        mkdir -p "$TMP_DIR/zip"
        extract_zip "$TMP_DIR/$ZIP_NAME" "$TMP_DIR/zip"
        SRC="$TMP_DIR/zip/$PLUGIN_NAME"
    else
        echo "Warning: release build asset missing, falling back to source tarball (unverified)."
    fi
fi

if [ -z "$SRC" ] || [ ! -f "$SRC/plugin.json" ]; then
    if [ -n "$LATEST_TAG" ]; then
        REPO_URL="https://github.com/$REPO/archive/refs/tags/${LATEST_TAG}.tar.gz"
        DIR_NAME="Decky-Wifi-Streaming-Optimizer-${LATEST_TAG#v}"
    else
        echo "Warning: couldn't fetch latest release, falling back to main branch (unverified)"
        REPO_URL="https://github.com/$REPO/archive/refs/heads/main.tar.gz"
        DIR_NAME="Decky-Wifi-Streaming-Optimizer-main"
    fi
    echo "Downloading..."
    curl -fsSL "$REPO_URL" -o "$TMP_DIR/plugin.tar.gz"
    tar xzf "$TMP_DIR/plugin.tar.gz" -C "$TMP_DIR"
    SRC="$TMP_DIR/$DIR_NAME"
fi

if [ ! -f "$SRC/plugin.json" ]; then
    echo "Error: Download failed or repo structure changed."
    exit 1
fi

echo "Installing $PLUGIN_NAME..."

# Install
if [ -d "$PLUGIN_DIR" ]; then
    echo "Upgrading existing installation..."
    UPGRADING=true
else
    echo "Installing to $PLUGIN_DIR..."
    UPGRADING=false
fi
rm -rf "$PLUGIN_DIR"
mkdir -p "$PLUGIN_DIR/dist" "$PLUGIN_DIR/defaults" "$PLUGIN_DIR/py_modules"

cp "$SRC/plugin.json" "$PLUGIN_DIR/"
cp "$SRC/package.json" "$PLUGIN_DIR/"
cp "$SRC/main.py" "$PLUGIN_DIR/"
cp "$SRC/decky.pyi" "$PLUGIN_DIR/"
cp "$SRC/dist/index.js" "$PLUGIN_DIR/dist/"
cp "$SRC/dist/index.js.map" "$PLUGIN_DIR/dist/" 2>/dev/null || true
cp "$SRC/defaults/dispatcher.sh.tmpl" "$PLUGIN_DIR/defaults/"
# The backend is modularized under py_modules/wifioptimizer - main.py cannot
# run without it.
cp -r "$SRC/py_modules/." "$PLUGIN_DIR/py_modules/"

# Restart Decky
echo "Restarting Decky Loader..."
systemctl restart plugin_loader 2>/dev/null || true

echo ""
if [ "$UPGRADING" = true ]; then
    echo "WiFi Optimizer Streaming updated! Your settings have been preserved."
else
    echo "WiFi Optimizer Streaming installed! Open the Quick Access Menu to configure."
fi
