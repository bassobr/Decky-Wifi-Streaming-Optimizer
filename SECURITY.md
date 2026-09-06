# Security Policy

This Decky Loader plugin runs with **root privileges** on end-user devices
and ships a NetworkManager dispatcher script that also runs as root. Security
reports are taken seriously.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting**:

https://github.com/bassobr/Decky-Wifi-Streaming-Optimizer/security/advisories/new

Do **not** open public issues for security problems. This is a solo-maintained
project - reports are handled on a best-effort basis, typically within a week.

## Supported versions

Only the **latest release** receives security fixes. The in-app updater moves
installations forward automatically; if you are on an old version, update via
the plugin or reinstall with `install.sh`.

## Release integrity

- Stable releases are built by CI and ship `SHA256SUMS` plus a minisign
  signature (`SHA256SUMS.minisig`).
- The self-updater verifies the signature against the public key pinned in
  the plugin ([`minisign.pub`](minisign.pub), key ID `72A411FD74FD614A`)
  before trusting any checksum, and refuses unsigned releases.
- To verify a release manually:
  `minisign -Vm SHA256SUMS -p minisign.pub`
- The beta channel installs from the `beta` branch without signatures and is
  intended for testing only.

## Scope notes for researchers

Particularly interesting areas: the root-privileged backend
(`py_modules/wifioptimizer/`, entry `main.py`), the NetworkManager dispatcher
template (`defaults/dispatcher.sh.tmpl`), the update pipeline
(`updates.py`, `archives.py`, `minisign.py`, `ed25519.py`), and file handling
around the user-writable settings directory (symlink/TOCTOU hardening in
`settings.py`). A prior full audit lives in [`CODE_REVIEW.md`](CODE_REVIEW.md).
