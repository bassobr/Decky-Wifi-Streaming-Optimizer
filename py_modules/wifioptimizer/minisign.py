"""minisign-compatible signing and verification (pure Python).

Implements the documented minisign file formats (jedisct1/minisign) on top of
the vendored ed25519 module, so releases can be signed in CI and verified on
the device without the minisign binary or any third-party library. Signatures
produced here verify with the official `minisign -Vm <file> -p minisign.pub`.

Formats:
  public key file:
      untrusted comment: <text>
      base64("Ed" || key_id[8] || public_key[32])
  signature file (.minisig):
      untrusted comment: <text>
      base64(sig_alg[2] || key_id[8] || signature[64])
      trusted comment: <text>
      base64(global_signature[64])
  sig_alg "ED": signature over BLAKE2b-512(file)  (prehashed, the default)
  sig_alg "Ed": signature over the raw file content (legacy)
  global_signature: ed25519 over (signature || trusted_comment)

CLI (used by the release workflow and for key setup):
  PYTHONPATH=py_modules python3 -m wifioptimizer.minisign \
      sign <file> <pubkey_file> [--trusted-comment TEXT]   # seed from $MINISIGN_SEED
      verify <file> <sig_file> <pubkey_file>
      keygen <pubkey_out> <seed_out>
"""

import base64
import hashlib
import os
import secrets as _secrets
import sys

from . import ed25519

UNTRUSTED_PREFIX = "untrusted comment: "
TRUSTED_PREFIX = "trusted comment: "
SEED_ENV = "MINISIGN_SEED"


def _b64decode(line: str) -> bytes:
    return base64.standard_b64decode(line.strip().encode())


def _prehash(content: bytes) -> bytes:
    return hashlib.blake2b(content, digest_size=64).digest()


def parse_public_key(text: str) -> tuple[bytes, bytes]:
    """Return (key_id[8], public_key[32]) from a minisign public-key text."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(UNTRUSTED_PREFIX):
            continue
        blob = _b64decode(line)
        if len(blob) != 42 or blob[:2] != b"Ed":
            raise ValueError("not a minisign Ed25519 public key")
        return blob[2:10], blob[10:42]
    raise ValueError("no key data found in public key text")


def parse_signature(text: str) -> dict:
    """Parse a .minisig document into its parts."""
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) != 4 or not lines[0].startswith(UNTRUSTED_PREFIX) \
            or not lines[2].startswith(TRUSTED_PREFIX):
        raise ValueError("malformed minisign signature")
    blob = _b64decode(lines[1])
    if len(blob) != 74 or blob[:2] not in (b"ED", b"Ed"):
        raise ValueError("unsupported signature algorithm")
    global_sig = _b64decode(lines[3])
    if len(global_sig) != 64:
        raise ValueError("malformed global signature")
    return {
        "sig_alg": blob[:2],
        "key_id": blob[2:10],
        "signature": blob[10:74],
        "trusted_comment": lines[2][len(TRUSTED_PREFIX):],
        "global_signature": global_sig,
    }


def verify_file(file_path: str, sig_text: str, pubkey_text: str) -> tuple[bool, str]:
    """Verify a file against a .minisig document and a public key.
    Returns (ok, detail)."""
    try:
        key_id, public = parse_public_key(pubkey_text)
        sig = parse_signature(sig_text)
    except Exception as e:
        return False, f"malformed signature material: {e}"
    if sig["key_id"] != key_id:
        return False, (
            f"key ID mismatch: signature {sig['key_id'].hex()}, "
            f"expected {key_id.hex()}"
        )
    with open(file_path, "rb") as f:
        content = f.read()
    msg = _prehash(content) if sig["sig_alg"] == b"ED" else content
    if not ed25519.verify(public, msg, sig["signature"]):
        return False, "invalid signature"
    if not ed25519.verify(
        public, sig["signature"] + sig["trusted_comment"].encode(), sig["global_signature"]
    ):
        return False, "invalid trusted-comment signature"
    return True, ""


def sign_file(
    file_path: str,
    seed: bytes,
    key_id: bytes,
    trusted_comment: str,
    untrusted_comment: str = "signature from wifi-optimizer-streaming CI",
) -> str:
    """Produce a .minisig document (prehashed mode) for file_path."""
    with open(file_path, "rb") as f:
        content = f.read()
    signature = ed25519.sign(seed, _prehash(content))
    global_sig = ed25519.sign(seed, signature + trusted_comment.encode())
    return (
        f"{UNTRUSTED_PREFIX}{untrusted_comment}\n"
        f"{base64.standard_b64encode(b'ED' + key_id + signature).decode()}\n"
        f"{TRUSTED_PREFIX}{trusted_comment}\n"
        f"{base64.standard_b64encode(global_sig).decode()}\n"
    )


def make_public_key_text(key_id: bytes, public: bytes) -> str:
    return (
        f"{UNTRUSTED_PREFIX}minisign public key {key_id.hex().upper()}\n"
        f"{base64.standard_b64encode(b'Ed' + key_id + public).decode()}\n"
    )


def _cli_sign(args: list[str]) -> int:
    trusted_comment = None
    if "--trusted-comment" in args:
        i = args.index("--trusted-comment")
        trusted_comment = args[i + 1]
        args = args[:i] + args[i + 2:]
    file_path, pubkey_path = args
    seed_b64 = os.environ.get(SEED_ENV, "")
    if not seed_b64:
        print(f"error: {SEED_ENV} is not set", file=sys.stderr)
        return 1
    seed = base64.standard_b64decode(seed_b64.strip())
    with open(pubkey_path) as f:
        key_id, public = parse_public_key(f.read())
    # Refuse to sign with a seed that doesn't match the committed public key -
    # clients pin that key, a mismatched signature would brick every update.
    if ed25519.secret_to_public(seed) != public:
        print("error: seed does not match the committed public key", file=sys.stderr)
        return 1
    if trusted_comment is None:
        trusted_comment = f"file:{os.path.basename(file_path)}"
    sig_text = sign_file(file_path, seed, key_id, trusted_comment)
    with open(file_path + ".minisig", "w") as f:
        f.write(sig_text)
    print(f"signed {file_path} -> {file_path}.minisig")
    return 0


def _cli_verify(args: list[str]) -> int:
    file_path, sig_path, pubkey_path = args
    with open(sig_path) as f:
        sig_text = f.read()
    with open(pubkey_path) as f:
        pubkey_text = f.read()
    ok, detail = verify_file(file_path, sig_text, pubkey_text)
    if ok:
        print(f"verified {file_path}: signature valid")
        return 0
    print(f"verification FAILED for {file_path}: {detail}", file=sys.stderr)
    return 1


def _cli_keygen(args: list[str]) -> int:
    pubkey_out, seed_out = args
    seed = _secrets.token_bytes(32)
    key_id = _secrets.token_bytes(8)
    public = ed25519.secret_to_public(seed)
    fd = os.open(seed_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.standard_b64encode(seed).decode() + "\n")
    with open(pubkey_out, "w") as f:
        f.write(make_public_key_text(key_id, public))
    print(f"wrote public key to {pubkey_out} and seed (base64, keep secret!) to {seed_out}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "sign":
        return _cli_sign(argv[1:])
    if len(argv) == 4 and argv[0] == "verify":
        return _cli_verify(argv[1:])
    if len(argv) == 3 and argv[0] == "keygen":
        return _cli_keygen(argv[1:])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
