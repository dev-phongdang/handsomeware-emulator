"""
modules/cleanup.py
Decrypts all .locked files and verifies integrity via SHA-256.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from utils.logger import get_logger
from utils.validator import is_within_sandbox

logger = get_logger(__name__, log_file=config.LOG_FILE)



@dataclass
class DecryptionResult:
    locked_path: str
    restored_path: str = ""
    sha256_expected: str = ""
    sha256_actual: str = ""
    hash_match: bool = False
    success: bool = False
    locked_removed: bool = False
    error: str = ""


class Cleanup:
    """Reverses encryption and verifies restored file integrity."""

    def __init__(self, key: bytes, sandbox: Path) -> None:
        if len(key) != config.KEY_SIZE:
            raise ValueError(f"AES-{config.KEY_SIZE*8} requires a {config.KEY_SIZE}-byte key.")
        self._aesgcm = AESGCM(key)
        self.sandbox = sandbox

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def decrypt_file(self, locked_path: Path, expected_sha256: str) -> DecryptionResult:
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

        # Derive original filename:  file.txt.locked → file.txt
        original_name = locked_path.name[: -len(config.ENCRYPTED_EXT)]
        restored_path = locked_path.with_name(original_name)

        try:
            raw = locked_path.read_bytes()
            nonce, ciphertext = raw[:config.NONCE_SIZE], raw[config.NONCE_SIZE:]
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
            restored_path.write_bytes(plaintext)

            actual_sha = self._sha256(restored_path)
            result.restored_path = str(restored_path)
            result.sha256_actual = actual_sha
            result.hash_match = actual_sha == expected_sha256
            result.success = True

            status = "✓ HASH OK" if result.hash_match else "✗ HASH MISMATCH"
            logger.info("DECRYPTED  %-45s  %s", restored_path.name, status)

            # Attempt to remove the .locked file
            try:
                locked_path.unlink()
                result.locked_removed = True
            except PermissionError:
                logger.warning(
                    "Could not remove %s (permission denied — delete manually)",
                    locked_path.name,
                )

        except Exception as exc:
            result.error = str(exc)
            logger.error("FAILED to decrypt %s: %s", locked_path, exc)
            try:
                if restored_path.exists():
                    restored_path.unlink()
            except Exception:
                pass

        return result

    def decrypt_all(self, enc_results: List) -> List[DecryptionResult]:
        """Decrypt all previously encrypted files using their stored hashes."""
        results: List[DecryptionResult] = []
        for enc in enc_results:
            if not enc.success:
                continue
            dr = self.decrypt_file(Path(enc.encrypted_path), enc.sha256_before)
            results.append(dr)

        ok = sum(1 for r in results if r.success and r.hash_match)
        logger.info(
            "Decryption complete: %d/%d files restored with hash match.",
            ok, len(results),
        )
        return results

    def remove_ransom_notes(self) -> int:
        """Delete all README_DECRYPT.txt files inside the sandbox."""
        removed = 0
        for note in self.sandbox.rglob(config.RANSOM_NOTE_NAME):
            try:
                note.unlink()
                logger.info("Removed note: %s", note)
                removed += 1
            except PermissionError:
                logger.warning("Could not remove note (permission denied): %s", note)
        return removed
