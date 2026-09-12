"""
modules/ransom_note.py — Ransom note delivery.

RansomNoteDropper places README_DECRYPT.txt in:
  1. Every directory that contains at least one successfully encrypted file.
  2. The sandbox root (always — even if no file was encrypted directly there).

This mirrors real ransomware behaviour: a note is dropped alongside the
victim files so the user sees the demand immediately in any folder they open.

Design notes
------------
* Note content is generated at drop-time from config.RANSOM_CONTACT and
  config.ATTACKER_ID — no hardcoded string in config.
* Logger is instance-level (self._logger), same pattern as file_encryptor and
  cleanup — no module-level logger global.
* Written paths are returned so the orchestrator can hand them to
  EvaluationCollector.record_note_drop() for timeline tracking.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import config
from modules.file_encryptor import EncryptionResult
from utils.logger import get_logger


def _build_note_content() -> str:
    """Generate the ransom note body from config constants."""
    return (
        f"=== RANSOMWARE SIMULATOR — EDUCATIONAL USE ONLY ===\n"
        f"\n"
        f"Campaign ID : {config.ATTACKER_ID}\n"
        f"Contact     : {config.RANSOM_CONTACT}\n"
        f"\n"
        f"Your files inside the test_data/ directory have been encrypted.\n"
        f"\n"
        f"This is a CONTROLLED LABORATORY SIMULATION.\n"
        f"No real harm has been done. All files can be restored.\n"
        f"\n"
        f"To decrypt, run:\n"
        f"    python orchestrator.py --decrypt\n"
        f"\n"
        f"=== THIS IS NOT REAL RANSOMWARE ===\n"
    )


class RansomNoteDropper:
    """
    Drops ransom notes into every affected directory.

    Parameters
    ----------
    sandbox:  Sandbox root — always receives a note regardless of results.
    log_file: Optional log file path; injected by the orchestrator.
    """

    def __init__(self, sandbox: Path, log_file: Path | None = None) -> None:
        self._sandbox = sandbox
        self._logger  = get_logger(__name__, log_file=log_file)

    def drop_notes(self, enc_results: List[EncryptionResult]) -> List[Path]:
        """
        Write README_DECRYPT.txt into every directory that had at least one
        file successfully encrypted, plus the sandbox root.

        Parameters
        ----------
        enc_results: Return value of FileEncryptor.encrypt_all() — one entry
                     per discovered file, successful or not.

        Returns
        -------
        List of Paths where a note was actually written (write failures are
        logged as warnings and excluded from the return list).
        """
        # Collect unique target directories from successful encryptions.
        # Always include sandbox root so at least one note is always written.
        affected_dirs: set[Path] = {self._sandbox}
        for r in enc_results:
            if r.success and r.encrypted_path:
                affected_dirs.add(Path(r.encrypted_path).parent)

        content = _build_note_content()
        written: List[Path] = []

        for directory in sorted(affected_dirs):   # sorted → deterministic log order
            note_path = directory / config.RANSOM_NOTE_NAME
            try:
                note_path.write_text(content, encoding="utf-8")
                self._logger.debug("Note dropped: %s", note_path)
                written.append(note_path)
            except OSError as exc:
                self._logger.warning(
                    "Could not write ransom note to '%s': %s", note_path, exc
                )

        self._logger.info(
            "Ransom note dropped in %d director%s.",
            len(written),
            "y" if len(written) == 1 else "ies",
        )
        return written
