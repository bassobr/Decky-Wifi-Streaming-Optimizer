"""Checksum verification and traversal-safe archive extraction for updates."""

import hashlib
import os
import tarfile
import zipfile


def verify_sha256(sums_text: str, filename: str, path: str) -> tuple[bool, str]:
    """Check `path` against the entry for `filename` in a sha256sum-format
    SHA256SUMS document. Returns (ok, detail)."""
    expected = None
    for line in sums_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == filename:
            expected = parts[0].lower()
            break
    if not expected:
        return False, f"no entry for {filename} in SHA256SUMS"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected:
        return False, f"sha256 mismatch: expected {expected}, got {actual}"
    return True, ""


def safe_extract_zip(zip_path: str, dest: str):
    """Extract a zip, rejecting members that would escape dest."""
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            p = os.path.normpath(name)
            if p.startswith("..") or os.path.isabs(p):
                raise ValueError(f"unsafe zip member: {name}")
        z.extractall(dest)


def safe_extract_tar(tar_path: str, dest: str):
    """Extract a .tar.gz, rejecting traversal, links, and absolute paths."""
    with tarfile.open(tar_path, "r:gz") as t:
        try:
            t.extractall(dest, filter="data")
        except TypeError:
            # Python without extraction-filter support: validate manually.
            for m in t.getmembers():
                name = os.path.normpath(m.name)
                if name.startswith("..") or os.path.isabs(name) or m.islnk() or m.issym():
                    raise ValueError(f"unsafe tar member: {m.name}")
            t.extractall(dest)
