"""Pure parsers - no I/O, fully unit-testable."""

from .constants import MIN_PATTERN_LEN, STREAMING_APPS


def build_patterns(settings: dict) -> list[tuple[str, str]]:
    """Build the (pattern, label) match list for streaming detection from the
    preset app toggles plus the user's custom patterns. Custom tokens shorter
    than MIN_PATTERN_LEN are skipped - they would match half of /proc and pin
    the streaming gate open."""
    patterns: list[tuple[str, str]] = []
    apps_enabled = settings.get("streaming_apps", {})
    for app_id, info in STREAMING_APPS.items():
        if apps_enabled.get(app_id, True):
            for p in info["patterns"]:
                patterns.append((p, info["label"]))
    custom = settings.get("streaming_custom_patterns", "") or ""
    for p in custom.replace(",", " ").split():
        if len(p) >= MIN_PATTERN_LEN:
            patterns.append((p.lower(), p))
    return patterns


def parse_iw_link(out: str) -> dict:
    """Extract signal/bitrate/frequency from `iw dev <iface> link` output."""
    info: dict = {}
    for line in out.split("\n"):
        line = line.strip()
        if line.startswith("signal:"):
            info["signal_dbm"] = line.split(":", 1)[1].strip()
        elif "tx bitrate:" in line:
            info["tx_bitrate"] = line.split("tx bitrate:", 1)[1].strip()
        elif line.startswith("freq:"):
            info["frequency"] = line.split(":", 1)[1].strip()
    return info


def parse_iw_channel(out: str) -> str | None:
    """Parse `iw dev <iface> info` output into "36 (80 MHz)" form."""
    for line in out.split("\n"):
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
                return f"{chan_num} ({width})"
            if chan_num:
                return chan_num
            return line
    return None


def parse_nmcli_fields(out: str) -> dict:
    """Parse `nmcli -t -f ...` output into {field: [values]}. Indexed fields
    like IP4.DNS[1] collapse onto their bare name; escaped colons in values
    (nmcli writes MACs as AA\\:BB\\:...) are unescaped."""
    fields: dict = {}
    for line in out.split("\n"):
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.split("[", 1)[0].strip()
        if not key:
            continue
        fields.setdefault(key, []).append(value.replace("\\:", ":").strip())
    return fields


def dns_drifted(expected_servers: str, live_dns: list[str]) -> bool:
    """True when a configured DNS override is missing from the live values."""
    expected = expected_servers.split()
    if not expected:
        return False
    live = set(live_dns)
    return any(server not in live for server in expected)
