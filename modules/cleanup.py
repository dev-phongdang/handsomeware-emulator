"""
modules/cleanup.py — AES-256-GCM decryption and integrity verification.

Design notes
------------
* EncryptedFileRecord is a typing.Protocol — any object with the three
  required attributes satisfies it.  No import of EncryptionResult needed;
  no circular dependency between encryptor ↔ cleanup.
* __init__ accepts log_file from the caller (orchestrator supplies config.LOG_FILE).
  The logger is instance-level, not module-level, so test code can inject a
  custom path without touching the global logger registry.
* sha256_file() imported from utils.hashing (shared with file_encryptor).
* On-disk format expected: [12 B nonce][ciphertext][16 B GCM auth-tag]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Protocol, Sequence, runtime_checkable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import config
from utils.hashing import sha256_file
from utils.validator import is_within_sandbox
from utils.logger import get_logger


# ---------------------------------------------------------------------------
# Structural contract for encrypted file records (duck-typed, no import of
# EncryptionResult required → no circular dependency)
# ---------------------------------------------------------------------------
@runtime_checkable
class EncryptedFileRecord(Protocol):
    success:        bool
    encrypted_path: str
    sha256_before:  str   # SHA-256 of the original plaintext


# ---------------------------------------------------------------------------
# Result type — decryption only
# ---------------------------------------------------------------------------
@dataclass
class DecryptionResult:
    encrypted_path:  str
    decrypted_path:  str
    sha256_before:   str   # expected (stored from encryption time)
    sha256_after:    str   # computed after decryption
    hash_match:      bool  # sha256_before == sha256_after
    success:         bool
    error:           str = ""


# ---------------------------------------------------------------------------
# Cleanup (decryptor)
# ---------------------------------------------------------------------------
class Cleanup:
    """
    Decrypts .locked files back to their originals and verifies integrity.

    Parameters
    ----------
    key:      32-byte AES-256 key (same key used during encryption)
    sandbox:  Path to the sandbox directory
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
    # Single-file decryption
    # ------------------------------------------------------------------
    def decrypt_file(self, enc_path: Path, sha256_expected: str) -> DecryptionResult:
        """
        Decrypt *enc_path* → original filename, then verify SHA-256 integrity.
        """
        if not is_within_sandbox(enc_path, self._sandbox):
            msg = f"Path '{enc_path}' is outside the sandbox — skipped."
            self._logger.warning(msg)
            return DecryptionResult(
                encrypted_path=str(enc_path),
                decrypted_path="",
                sha256_before=sha256_expected,
                sha256_after="",
                hash_match=False,
                success=False,
                error=msg,
            )

        try:
            raw       = enc_path.read_bytes()
            nonce     = raw[:config.NONCE_SIZE]
            # remaining bytes = ciphertext + 16-byte GCM tag (handled by AESGCM)
            ciphertext = raw[config.NONCE_SIZE:]

            plaintext  = self._aesgcm.decrypt(nonce, ciphertext, None)

            # Restore original extension (strip .locked)
            dec_path   = enc_path.with_suffix("")
            dec_path.write_bytes(plaintext)

            sha_after  = sha256_file(dec_path)
            hash_match = sha_after == sha256_expected

            if hash_match:
                self._logger.debug(
                    "Decrypted OK (integrity verified): %s", dec_path.name
                )
            else:
                self._logger.error(
                    "Integrity FAIL for '%s': expected %s, got %s",
                    dec_path.name, sha256_expected, sha_after,
                )

            # Remove encrypted blob
            try:
                enc_path.unlink()
            except PermissionError:
                self._logger.warning(
                    "Could not delete '%s' (read-only mount).", enc_path
                )

            return DecryptionResult(
                encrypted_path=str(enc_path),
                decrypted_path=str(dec_path),
                sha256_before=sha256_expected,
                sha256_after=sha_after,
                hash_match=hash_match,
                success=True,
            )

        except InvalidTag:
            msg = f"GCM auth-tag verification failed for '{enc_path}' — wrong key or tampered file."
            self._logger.error(msg)
            return DecryptionResult(
                encrypted_path=str(enc_path),
                decrypted_path="",
                sha256_before=sha256_expected,
                sha256_after="",
                hash_match=False,
                success=False,
                error=msg,
            )
        except Exception as exc:  # noqa: BLE001
            self._logger.error("Failed to decrypt '%s': %s", enc_path, exc)
            return DecryptionResult(
                encrypted_path=str(enc_path),
                decrypted_path="",
                sha256_before=sha256_expected,
                sha256_after="",
                hash_match=False,
                success=False,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Batch decryption
    # ------------------------------------------------------------------
    def decrypt_all(self, enc_results: Sequence[EncryptedFileRecord]) -> List[DecryptionResult]:  # Sequence is covariant; list[_SessionRecord] satisfies this
        """
        Decrypt every successfully-encrypted file from *enc_results*.

        Parameters
        ----------
        enc_results: list of objects satisfying EncryptedFileRecord Protocol
                     (i.e. EncryptionResult instances from file_encryptor)
        """
        results: List[DecryptionResult] = []

        for record in enc_results:
            if not record.success:
                self._logger.debug(
                    "Skipping record (encryption had failed): %s",
                    record.encrypted_path,
                )
                continue

            enc_path = Path(record.encrypted_path)
            result   = self.decrypt_file(enc_path, sha256_expected=record.sha256_before)
            results.append(result)

        ok = sum(1 for r in results if r.success and r.hash_match)
        self._logger.info(
            "Decryption complete: %d/%d files restored with integrity verified.",
            ok, len(results),
        )
        return results
