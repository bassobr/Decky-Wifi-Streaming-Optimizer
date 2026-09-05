"""WiFi Optimizer backend package.

Decky Loader puts the plugin's py_modules/ directory on sys.path, which makes
this package importable from main.py. main.py stays the thin entry point that
composes the Plugin class from the mixins defined here; each module owns one
domain:

- deckyshim       decky import with a local fallback stub
- constants       all tuning values, tables, and system paths
- settings        settings.json persistence (symlink-safe, thread-safe)
- parsing         pure parsers for iw/nmcli output and detection patterns
- archives        checksum verification and traversal-safe extraction
- system          subprocess runner and nmcli/iw primitives
- hardware        device/driver/distro detection
- appliers        the volatile fixes (power save, buffers, CAKE) + revert
- dispatcher      NetworkManager dispatcher rendering/installation
- streaming       streaming auto mode: detection watcher and its setters
- status          the UI status snapshot and diagnostics
- setters         persistent optimization setters and bulk actions
- updates         self-update (verified release zip / beta tarball)
- backend_switch  iwd <-> wpa_supplicant switching

Keep this file free of imports: main.py probes `import wifioptimizer` to
decide whether the package needs self-healing, and that probe must not drag
in half the package.
"""
