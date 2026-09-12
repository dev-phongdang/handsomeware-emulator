"""
utils/hashing.py
Shared hashing utilities used by both file_encryptor and cleanup.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK_SIZE = 65536  # 64 KiB — balances memory use vs. syscall overhead


def sha256_file(path: Path) -> str:
    """Return the hex-encoded SHA-256 digest of a file's contents.

    Reads in chunks so large files don't need to be loaded into memory.

    Args:
        path: Path to the file to hash. Must exist and be readable.

    Returns:
        Lowercase hex string, e.g. "a3f1...".

    Raises:
        FileNotFoundError: if *path* does not exist.
        PermissionError:   if the file cannot be read.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()
