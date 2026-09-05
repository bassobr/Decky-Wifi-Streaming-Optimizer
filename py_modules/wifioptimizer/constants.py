"""All tuning values, lookup tables, and system paths.

Single source of truth: the dispatcher script is rendered from these values
(see dispatcher.py), so plugin and dispatcher can never disagree.
"""

import re

DISPATCHER_PATH = "/etc/NetworkManager/dispatcher.d/99-wifi-optimizer"
NM_CONF_PATH = "/etc/NetworkManager/conf.d/99-wifi-optimizer.conf"
MODPROBE_CONF_PATH = "/etc/modprobe.d/99-wifi-optimizer.conf"
BACKEND_HELPER = "/usr/bin/steamos-polkit-helpers/steamos-wifi-set-backend-privileged"
WIFI_BACKEND_CONF = "/etc/NetworkManager/conf.d/99-valve-wifi-backend.conf"
NM_DEFAULT_CONF = "/usr/lib/NetworkManager/conf.d/10-steamos-defaults.conf"
GENERIC_BACKEND_CONF = "/etc/NetworkManager/conf.d/99-wifi-optimizer-backend.conf"
BAZZITE_IWD_CONF = "/etc/NetworkManager/conf.d/iwd.conf"

# last_enforced lives under /run (root-owned tmpfs): the dispatcher runs as
# root and must never write through paths an unprivileged user could swap for
# a symlink, which the user-writable settings dir would allow (SEC-01). The
# legacy copy inside the settings dir is removed on startup.
ENFORCED_DIR = "/run/wifi-optimizer"
ENFORCED_FILE = ENFORCED_DIR + "/last_enforced"
LEGACY_ENFORCED_NAME = "last_enforced"
DIAGNOSTICS_NAME = "diagnostics.json"

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
# truth - see dispatcher.render_dispatcher_script).
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
    # Pre-apply system state, captured when a volatile fix is first applied
    # and restored (then cleared) when it is reverted - so disabling a fix
    # brings back the machine's real prior tuning instead of assumed kernel
    # defaults (FUNC-06).
    "sysctl_snapshot": {},
    "txqueuelen_snapshot": "",
    "pcie_snapshot": {},
    "distro_id": "unknown",
    "distro_name": "Unknown",
    "update_channel": "stable",
    "last_applied": 0,
}
