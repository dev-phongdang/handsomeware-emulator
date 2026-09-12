"""
utils/hashing.py — Shared SHA-256 file hashing utility.

Extracted from file_encryptor and cleanup so both modules share a single
implementation with no duplication and no circular dependency.
"""

import hashlib
from pathlib import Path

_CHUNK_SIZE = 65_536  # 64 KiB — keeps memory flat for large files


def sha256_file(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()
