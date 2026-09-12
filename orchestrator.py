"""
orchestrator.py — Top-level entry point for the ransomware simulator.

Usage
-----
  # Encrypt
  python orchestrator.py

  # Decrypt (restore)
  python orchestrator.py --decrypt

  # Add EDR data to an existing report and re-export
  python orchestrator.py --add-edr \
      --detected \
      --detection-time "2026-09-12T02:49:21.300+00:00" \
      --edr-action alert \
      --files-before-detection 1

Environment requirements (enforced by validator):
  - LAB_ENVIRONMENT=1   (env var)
  - {BASE_DIR}/.lab_marker  (sentinel file)
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import config
from modules.cleanup import Cleanup
from modules.evaluation import EvaluationCollector
from modules.file_encryptor import FileEncryptor
from modules.ransom_note import RansomNoteDropper
from utils.logger import get_logger
from utils.validator import validate_environment

logger = get_logger(__name__, log_file=config.LOG_FILE)

# Separate JSON file: key + raw results (for decrypt phase replay)
_SESSION_FILE = config.BASE_DIR / "session.json"


# Lightweight record satisfying the EncryptedFileRecord Protocol.
# Rebuilt from session.json during the decrypt phase so cleanup.decrypt_all()
# can replay without importing EncryptionResult here.
from dataclasses import dataclass as _dataclass


@_dataclass
class _SessionRecord:
    success: bool
    encrypted_path: str
    sha256_before: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _generate_key() -> bytes:
    return os.urandom(config.KEY_SIZE)


def _save_session(key: bytes, enc_results) -> None:
    """Persist key + raw encryption results for later decrypt/EDR replay."""
    data = {
        "key_hex": key.hex(),
        "results": [
            {
                "original_path": r.original_path,
                "encrypted_path": r.encrypted_path,
                "sha256_before": r.sha256_before,
                "sha256_after": r.sha256_after,
                "success": r.success,
                "original_size": r.original_size,
                "original_removed": r.original_removed,
                "encrypted_at": r.encrypted_at,
                "error": r.error,
            }
            for r in enc_results
        ],
    }
    _SESSION_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    logger.info("Session data saved to '%s'", _SESSION_FILE)


# ---------------------------------------------------------------------------
# Encrypt phase
# ---------------------------------------------------------------------------
def run_encrypt() -> None:
    logger.info("=== ENCRYPT PHASE ===")

    if not validate_environment(config, logger):
        logger.critical("Environment validation failed — aborting.")
        sys.exit(1)

    collector = EvaluationCollector()
    collector.start_simulation()

    key = _generate_key()
    encryptor = FileEncryptor(
        key=key, sandbox=config.SANDBOX_DIR, log_file=config.LOG_FILE
    )

    # Discover before encrypt so total_files_discovered reflects scope
    all_files = encryptor.discover_files()
    collector.set_total_discovered(len(all_files))

    enc_results = encryptor.encrypt_all()
    collector.collect_encryption_results(enc_results)

    dropper = RansomNoteDropper(sandbox=config.SANDBOX_DIR, log_file=config.LOG_FILE)
    note_paths = dropper.drop_notes(enc_results)
    collector.record_note_drop(note_paths)

    _save_session(key, enc_results)

    report = collector.finalize()
    collector.export_json(report, config.REPORT_FILE)
    logger.info(
        "Encrypt phase done: %d/%d files. Report → '%s'",
        report.total_files_encrypted,
        report.total_files_discovered,
        config.REPORT_FILE,
    )


# ---------------------------------------------------------------------------
# Decrypt phase
# ---------------------------------------------------------------------------
def run_decrypt() -> None:
    logger.info("=== DECRYPT PHASE ===")

    if not validate_environment(config, logger):
        logger.critical("Environment validation failed — aborting.")
        sys.exit(1)

    if not _SESSION_FILE.exists():
        logger.critical("Session file '%s' not found — cannot decrypt.", _SESSION_FILE)
        sys.exit(1)

    session = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
    key = bytes.fromhex(session["key_hex"])

    enc_results = [
        _SessionRecord(
            success=r["success"],
            encrypted_path=r["encrypted_path"],
            sha256_before=r["sha256_before"],
        )
        for r in session["results"]
    ]

    cleanup = Cleanup(key=key, sandbox=config.SANDBOX_DIR, log_file=config.LOG_FILE)
    dec_results = cleanup.decrypt_all(enc_results)

    # --- Merge into existing report (preserve Group 1/2/3) ---
    collector = EvaluationCollector()

    if config.REPORT_FILE.exists():
        existing = json.loads(config.REPORT_FILE.read_text(encoding="utf-8"))
        # Restore timeline state so finalize() keeps Groups 1/2/3 intact
        from datetime import datetime

        try:
            collector._start_time = (
                datetime.fromisoformat(existing.get("simulation_start_time", ""))
                if existing.get("simulation_start_time")
                else None
            )
        except ValueError:
            pass

        # Restore enc_results shape from session for Group 1 counters
        from modules.file_encryptor import EncryptionResult

        for r in session["results"]:
            collector._enc_results.append(
                EncryptionResult(
                    original_path=r["original_path"],
                    encrypted_path=r["encrypted_path"],
                    sha256_before=r["sha256_before"],
                    sha256_after=r["sha256_after"],
                    success=r["success"],
                    original_size=r["original_size"],
                    original_removed=r["original_removed"],
                    encrypted_at=r["encrypted_at"],
                    error=r.get("error", ""),
                )
            )
            if r["success"] and r["encrypted_at"]:
                try:
                    collector._file_timestamps.append(
                        datetime.fromisoformat(r["encrypted_at"])
                    )
                except ValueError:
                    pass

        collector._total_discovered = existing.get("total_files_discovered", 0)

        # Restore Group 3 EDR data if it was previously added
        if existing.get("edr_detected"):
            collector._edr_detected = existing["edr_detected"]
            collector._edr_detection_time = existing.get("edr_detection_time", "")
            collector._edr_action = existing.get("edr_action", "")
            collector._files_before_detect = existing.get(
                "files_encrypted_before_detection", 0
            )

        # Restore note drop time
        if existing.get("ransom_note_drop_time"):
            try:
                collector._note_drop_time = datetime.fromisoformat(
                    existing["ransom_note_drop_time"]
                )
            except ValueError:
                pass

    collector.collect_cleanup_results(dec_results)
    report = collector.finalize()
    collector.export_json(report, config.REPORT_FILE)

    logger.info(
        "Decrypt phase done: %d/%d files restored. integrity_rate=%.2f. Report → '%s'",
        report.files_restored,
        report.total_files_encrypted,
        report.integrity_rate,
        config.REPORT_FILE,
    )


# ---------------------------------------------------------------------------
# EDR data injection (post-experiment manual input)
# ---------------------------------------------------------------------------
def run_add_edr(
    detected: bool,
    detection_time: str,
    action: str,
    files_before: int,
) -> None:
    logger.info("=== ADD EDR DATA ===")

    if not config.REPORT_FILE.exists():
        logger.critical(
            "Report file '%s' not found — run encrypt first.", config.REPORT_FILE
        )
        sys.exit(1)

    existing = json.loads(config.REPORT_FILE.read_text(encoding="utf-8"))

    # Reconstruct collector state from report so finalize() preserves everything
    from datetime import datetime

    collector = EvaluationCollector()

    # Restore Groups 1/2/5 from existing report fields
    if _SESSION_FILE.exists():
        session = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
        from modules.file_encryptor import EncryptionResult

        for r in session["results"]:
            collector._enc_results.append(
                EncryptionResult(
                    original_path=r["original_path"],
                    encrypted_path=r["encrypted_path"],
                    sha256_before=r["sha256_before"],
                    sha256_after=r["sha256_after"],
                    success=r["success"],
                    original_size=r["original_size"],
                    original_removed=r["original_removed"],
                    encrypted_at=r["encrypted_at"],
                    error=r.get("error", ""),
                )
            )
            if r["success"] and r["encrypted_at"]:
                try:
                    collector._file_timestamps.append(
                        datetime.fromisoformat(r["encrypted_at"])
                    )
                except ValueError:
                    pass
        collector._total_discovered = existing.get("total_files_discovered", 0)

    if existing.get("simulation_start_time"):
        try:
            collector._start_time = datetime.fromisoformat(
                existing["simulation_start_time"]
            )
        except ValueError:
            pass
    if existing.get("simulation_end_time"):
        try:
            collector._end_time = datetime.fromisoformat(
                existing["simulation_end_time"]
            )
        except ValueError:
            pass
    if existing.get("ransom_note_drop_time"):
        try:
            collector._note_drop_time = datetime.fromisoformat(
                existing["ransom_note_drop_time"]
            )
        except ValueError:
            pass

    collector.add_edr_data(
        detected=detected,
        detection_time=detection_time,
        action=action,
        files_before_detection=files_before,
    )

    report = collector.finalize()

    # Group 5 metrics are patched directly from the existing report because
    # cleanup has already run and dec_results are not available here.
    # This is safe: cleanup_status is immutable once cleanup completes,
    # and finalize() overwrites Group 5 only when self._dec_results is non-empty.
    report.files_restored = existing.get("files_restored", 0)
    report.hash_match_count = existing.get("hash_match_count", 0)
    report.integrity_rate = existing.get("integrity_rate", 0.0)
    report.cleanup_status = existing.get("cleanup_status", "")

    # Re-derive detection_stage with patched timestamps
    from modules.evaluation import EvaluationCollector as _EC

    report.detection_stage = _EC._derive_detection_stage(report)

    collector.export_json(report, config.REPORT_FILE)
    logger.info(
        "EDR data merged. detection_stage='%s'. Report → '%s'",
        report.detection_stage,
        config.REPORT_FILE,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ransomware Behaviour Simulator (educational)"
    )
    parser.add_argument(
        "--decrypt", action="store_true", help="Run decryption/restore phase"
    )
    parser.add_argument(
        "--add-edr", action="store_true", help="Inject EDR data into existing report"
    )
    parser.add_argument("--detected", action="store_true", help="[--add-edr] EDR fired")
    parser.add_argument(
        "--detection-time",
        default="",
        help="[--add-edr] ISO UTC timestamp from EDR log",
    )
    parser.add_argument(
        "--edr-action",
        default="",
        help="[--add-edr] alert | block | kill | quarantine …",
    )
    parser.add_argument(
        "--files-before-detection",
        type=int,
        default=0,
        help="[--add-edr] files encrypted before EDR fired",
    )
    args = parser.parse_args()

    if args.add_edr:
        run_add_edr(
            detected=args.detected,
            detection_time=args.detection_time,
            action=args.edr_action,
            files_before=args.files_before_detection,
        )
    elif args.decrypt:
        run_decrypt()
    else:
        run_encrypt()


if __name__ == "__main__":
    main()
