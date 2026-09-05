"""decky import with a local fallback.

Every module gets decky through this shim so the whole package shares one
object - tests monkeypatch attributes on it and see consistent state.
"""

try:
    import decky
except ImportError:
    # Local fallback when decky isn't importable (e.g., running outside
    # plugin_loader for static analysis or tests). All runtime paths on a
    # Deck have the real module.
    class decky:  # type: ignore
        DECKY_PLUGIN_SETTINGS_DIR = "/tmp/wifi-optimizer"
        DECKY_PLUGIN_DIR = "/tmp/wifi-optimizer"
        DECKY_PLUGIN_VERSION = "0.0.0"

        class logger:
            @staticmethod
            def info(msg):
                print(f"[INFO] {msg}")

            @staticmethod
            def error(msg):
                print(f"[ERROR] {msg}")
