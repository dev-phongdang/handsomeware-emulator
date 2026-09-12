"""
modules/cleanup.py
Decrypts all .locked files and verifies integrity via SHA-256.

Coupling note
─────────────
decrypt_all() consumes a list of EncryptedFileRecord — a Protocol that
declares only the three attributes this module actually reads from an
EncryptionResult. This breaks the implicit tight coupling with
file_encryptor.py: no import of EncryptionResult is needed, any object
that satisfies the protocol is accepted, and type-checkers can verify
the contract statically.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Protocol, runtime_checkable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from utils.logger import get_logger
from utils.validator import is_within_sandbox


# ── Protocol — explicit contract for what decrypt_all() needs ─────────────────
@runtime_checkable
class EncryptedFileRecord(Protocol):
    """
    Structural interface consumed by Cleanup.decrypt_all().

    Any object with these three attributes satisfies this protocol —
    no inheritance required (duck typing). EncryptionResult from
    file_encryptor.py happens to satisfy it, but cleanup.py never
    imports that class directly.

    Attributes:
        success:        Whether the encryption succeeded.
        encrypted_path: Absolute path of the .locked file on disk.
        sha256_before:  SHA-256 hex digest of the original plaintext,
                        used to verify the decrypted output.
    """
    success:        bool
    encrypted_path: str
    sha256_before:  str


# ── Result dataclass ──────────────────────────────────────────────────────────
@dataclass
class DecryptionResult:
    locked_path:    str
    restored_path:  str  = ""
    sha256_expected: str = ""
    sha256_actual:  str  = ""
    hash_match:     bool = False
    success:        bool = False
    locked_removed: bool = False
    error:          str  = ""


# ── Main class ────────────────────────────────────────────────────────────────
class Cleanup:
    """Reverses encryption and verifies restored file integrity."""

    def __init__(
        self,
        key:      bytes,
        sandbox:  Path,
        log_file: Path | None = None,   # caller supplies; no hardcoded config path
    ) -> None:
        """
        Args:
            key:      AES-256 key (must be exactly config.KEY_SIZE bytes).
            sandbox:  Directory scope — every file operation is checked
                      against this root by is_within_sandbox().
            log_file: Optional path for the DEBUG-level file handler.
                      Pass config.LOG_FILE from the orchestrator; omit in
                      unit tests to keep output console-only.
        """
        if len(key) != config.KEY_SIZE:
            raise ValueError(
                f"AES-{config.KEY_SIZE * 8} requires a {config.KEY_SIZE}-byte key."
            )
        self._aesgcm = AESGCM(key)
        self.sandbox = sandbox
        self._logger: logging.Logger = get_logger(__name__, log_file=log_file)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    # ── Single-file decryption ────────────────────────────────────────────────

    def decrypt_file(
        self,
        locked_path:     Path,
        expected_sha256: str,
    ) -> DecryptionResult:
        """Decrypt one .locked file and verify its SHA-256 digest."""
        result = DecryptionResult(
            locked_path=str(locked_path),
            sha256_expected=expected_sha256,
        )

        if not is_within_sandbox(locked_path, self.sandbox):
            result.error = "Path outside sandbox — skipped."
            return result

        if not locked_path.name.endswith(config.ENCRYPTED_EXT):
            result.error = "File does not have expected encrypted extension."
            return result

        # file.txt.locked → file.txt
        original_name = locked_path.name[: -len(config.ENCRYPTED_EXT)]
        restored_path = locked_path.with_name(original_name)

        try:
            raw = locked_path.read_bytes()
            nonce      = raw[: config.NONCE_SIZE]
            ciphertext = raw[config.NONCE_SIZE :]          # includes GCM tag
            plaintext  = self._aesgcm.decrypt(nonce, ciphertext, None)
            restored_path.write_bytes(plaintext)

            actual_sha          = self._sha256(restored_path)
            result.restored_path = str(restored_path)
            result.sha256_actual = actual_sha
            result.hash_match   = actual_sha == expected_sha256
            result.success      = True

            status = "✓ HASH OK" if result.hash_match else "✗ HASH MISMATCH"
            self._logger.info("DECRYPTED  %-45s  %s", restored_path.name, status)

            try:
                locked_path.unlink()
                result.locked_removed = True
            except PermissionError:
                self._logger.warning(
                    "Could not remove %s (permission denied — delete manually)",
                    locked_path.name,
                )

        except Exception as exc:
            result.error = str(exc)
            self._logger.error("FAILED to decrypt %s: %s", locked_path, exc)
            try:
                if restored_path.exists():
                    restored_path.unlink()
            except Exception:
                pass

        return result

    # ── Batch decryption ──────────────────────────────────────────────────────

    def decrypt_all(
        self,
        enc_results: List[EncryptedFileRecord],   # Protocol, not EncryptionResult
    ) -> List[DecryptionResult]:
        """
        Decrypt all successfully encrypted files recorded in *enc_results*.

        Args:
            enc_results: Any iterable whose items satisfy EncryptedFileRecord —
                         i.e. have .success, .encrypted_path, .sha256_before.
                         EncryptionResult from file_encryptor satisfies this
                         without an explicit import here.
        """
        results: List[DecryptionResult] = []

        for enc in enc_results:
            if not enc.success:
                continue
            dr = self.decrypt_file(Path(enc.encrypted_path), enc.sha256_before)
            results.append(dr)

        ok = sum(1 for r in results if r.success and r.hash_match)
        self._logger.info(
            "Decryption complete: %d/%d files restored with hash match.",
            ok, len(results),
        )
        return results

    # ── Note cleanup ──────────────────────────────────────────────────────────

    def remove_ransom_notes(self) -> int:
        """Delete all README_DECRYPT.txt files inside the sandbox."""
        removed = 0
        for note in self.sandbox.rglob(config.RANSOM_NOTE_NAME):
            try:
                note.unlink()
                self._logger.info("Removed note: %s", note)
                removed += 1
            except PermissionError:
                self._logger.warning(
                    "Could not remove note (permission denied): %s", note
                )
        return removed
