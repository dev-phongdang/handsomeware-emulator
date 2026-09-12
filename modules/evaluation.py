"""
modules/evaluation.py — Metrics collection and report generation.

Two-mode design
---------------
Mode 1 — Auto-collect (runs right after simulation):
    collector.start_simulation()
    ...run encrypt...
    collector.collect_encryption_results(enc_results)
    collector.record_note_drop([note_path])
    ...run decrypt...
    collector.collect_cleanup_results(dec_results)
    report = collector.finalize()
    collector.export_json(report, path)

Mode 2 — Manual EDR input (after reading EDR log):
    collector.add_edr_data(
        detected=True,
        detection_time="2026-09-12T02:49:21.300000+00:00",
        action="alert",
        files_before_detection=1,
    )
    report = collector.finalize()
    collector.export_json(report, path)

Metric groups
-------------
Group 1  Simulation scope
Group 2  Timeline
Group 3  EDR detection   ← manual input; auto fields default to False/""/0
Group 4  Impact assessment (derived ratios)
Group 5  Cleanup integrity
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from modules.file_encryptor import EncryptionResult
from modules.cleanup import DecryptionResult


# ---------------------------------------------------------------------------
# Report dataclass — one field per metric, all five groups
# ---------------------------------------------------------------------------
@dataclass
class SimulationReport:
    # ------------------------------------------------------------------
    # Group 1 — Simulation Scope
    # ------------------------------------------------------------------
    total_files_discovered:   int = 0
    total_files_encrypted:    int = 0
    total_bytes_encrypted:    int = 0
    files_original_removed:   int = 0

    # ------------------------------------------------------------------
    # Group 2 — Timeline  (ISO 8601 UTC strings)
    # ------------------------------------------------------------------
    simulation_start_time:       str   = ""
    simulation_end_time:         str   = ""
    encryption_duration_seconds: float = 0.0
    first_file_encrypted_time:   str   = ""
    last_file_encrypted_time:    str   = ""
    ransom_note_drop_time:       str   = ""

    # ------------------------------------------------------------------
    # Group 3 — EDR Detection  (manual input)
    # ------------------------------------------------------------------
    edr_detected:                   bool  = False
    edr_detection_time:             str   = ""
    edr_action:                     str   = ""
    files_encrypted_before_detection: int = 0
    detection_stage:                str   = "not_detected"

    # ------------------------------------------------------------------
    # Group 4 — Impact Assessment  (derived ratios)
    # ------------------------------------------------------------------
    affected_file_ratio:    float = 0.0
    pre_detection_ratio:    float = 0.0

    # ------------------------------------------------------------------
    # Group 5 — Cleanup Integrity
    # ------------------------------------------------------------------
    files_restored:   int   = 0
    hash_match_count: int   = 0
    integrity_rate:   float = 0.0
    cleanup_status:   str   = ""   # "success" | "partial" | "failed" | "pending"


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
class EvaluationCollector:
    """
    Accumulates data from each simulation phase and assembles SimulationReport.

    Typical call order:
        start_simulation()
        collect_encryption_results(enc_results)
        record_note_drop([note_path])
        collect_cleanup_results(dec_results)
        add_edr_data(...)           ← optional, manual
        finalize() → SimulationReport
        export_json(report, path)
    """

    def __init__(self) -> None:
        # Raw state accumulated across calls
        self._start_time:   Optional[datetime] = None
        self._end_time:     Optional[datetime] = None

        # Group 1
        self._total_discovered: int = 0
        self._enc_results:      List[EncryptionResult] = []

        # Group 2 — per-file timestamps parsed from EncryptionResult.encrypted_at
        self._file_timestamps:  List[datetime] = []
        self._note_drop_time:   Optional[datetime] = None

        # Group 3 — EDR (manual)
        self._edr_detected:       bool = False
        self._edr_detection_time: str  = ""
        self._edr_action:         str  = ""
        self._files_before_detect: int = 0

        # Group 5
        self._dec_results: List[DecryptionResult] = []

    # ------------------------------------------------------------------
    # Mode 1 — auto-collect methods
    # ------------------------------------------------------------------
    def start_simulation(self) -> None:
        """Record simulation_start_time. Call before the first encrypt."""
        self._start_time = datetime.now(tz=timezone.utc)

    def set_total_discovered(self, count: int) -> None:
        """
        Record how many files were discovered before encryption began.
        Call this with len(encryptor.discover_files()) before encrypt_all().
        """
        self._total_discovered = count

    def collect_encryption_results(
        self, enc_results: List[EncryptionResult]
    ) -> None:
        """
        Ingest Group 1 + 2 data from the return value of encrypt_all().

        Parses EncryptionResult.encrypted_at (ISO UTC) into datetime objects
        for timeline ordering and duration calculation.
        """
        self._enc_results = enc_results

        for r in enc_results:
            if r.success and r.encrypted_at:
                try:
                    ts = datetime.fromisoformat(r.encrypted_at)
                    self._file_timestamps.append(ts)
                except ValueError:
                    pass   # malformed timestamp — skip

    def record_note_drop(self, note_paths: List[Path]) -> None:
        """
        Record ransom_note_drop_time. Call immediately after writing the note.
        note_paths: list of Path objects for all dropped note files.
        """
        if note_paths:
            self._note_drop_time = datetime.now(tz=timezone.utc)

    def collect_cleanup_results(
        self, dec_results: List[DecryptionResult]
    ) -> None:
        """Ingest Group 5 data from decrypt_all()."""
        self._dec_results = dec_results
        self._end_time    = datetime.now(tz=timezone.utc)

    # ------------------------------------------------------------------
    # Mode 2 — manual EDR input
    # ------------------------------------------------------------------
    def add_edr_data(
        self,
        detected:              bool,
        detection_time:        str,
        action:                str,
        files_before_detection: int,
    ) -> None:
        """
        Supply Group 3 metrics from the EDR log.

        Parameters
        ----------
        detected:               Whether the EDR fired at all.
        detection_time:         ISO 8601 UTC string from the EDR log.
        action:                 What the EDR did: "alert", "block", "kill", etc.
        files_before_detection: Count of files encrypted before EDR reacted.
        """
        self._edr_detected        = detected
        self._edr_detection_time  = detection_time
        self._edr_action          = action
        self._files_before_detect = files_before_detection

    # ------------------------------------------------------------------
    # Finalize + export
    # ------------------------------------------------------------------
    def finalize(self) -> SimulationReport:
        """
        Compute all derived metrics and return the final SimulationReport.

        May be called multiple times (e.g. once after encrypt-only,
        again after add_edr_data + cleanup).
        """
        report = SimulationReport()

        # ---- Group 1 — Scope ----------------------------------------
        successful = [r for r in self._enc_results if r.success]
        report.total_files_discovered = self._total_discovered
        report.total_files_encrypted  = len(successful)
        report.total_bytes_encrypted  = sum(r.original_size for r in successful)
        report.files_original_removed = sum(1 for r in successful if r.original_removed)

        # ---- Group 2 — Timeline -------------------------------------
        report.simulation_start_time = (
            self._start_time.isoformat() if self._start_time else ""
        )
        report.simulation_end_time = (
            self._end_time.isoformat() if self._end_time else ""
        )

        if self._start_time and self._end_time:
            report.encryption_duration_seconds = round(
                (self._end_time - self._start_time).total_seconds(), 3
            )

        if self._file_timestamps:
            report.first_file_encrypted_time = min(self._file_timestamps).isoformat()
            report.last_file_encrypted_time  = max(self._file_timestamps).isoformat()

        report.ransom_note_drop_time = (
            self._note_drop_time.isoformat() if self._note_drop_time else ""
        )

        # ---- Group 3 — EDR ------------------------------------------
        report.edr_detected                    = self._edr_detected
        report.edr_detection_time              = self._edr_detection_time
        report.edr_action                      = self._edr_action
        report.files_encrypted_before_detection = self._files_before_detect
        report.detection_stage                 = self._derive_detection_stage(report)

        # ---- Group 4 — Impact ratios --------------------------------
        total = report.total_files_discovered or 1  # guard div-by-zero
        report.affected_file_ratio = round(
            report.total_files_encrypted / total, 4
        )
        report.pre_detection_ratio = round(
            report.files_encrypted_before_detection / total, 4
        ) if self._edr_detected else 0.0

        # ---- Group 5 — Cleanup integrity ----------------------------
        report.files_restored   = sum(1 for r in self._dec_results if r.success)
        report.hash_match_count = sum(
            1 for r in self._dec_results if r.success and r.hash_match
        )
        report.integrity_rate   = round(
            report.hash_match_count / report.files_restored, 4
        ) if report.files_restored else 0.0
        report.cleanup_status   = self._derive_cleanup_status(report)

        return report

    def export_json(self, report: SimulationReport, path: Path) -> None:
        """
        Serialize *report* to a JSON file at *path*.

        The output is human-readable (indent=2) so researchers can review
        results without additional tooling.
        """
        path.write_text(
            json.dumps(asdict(report), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Internal derivations
    # ------------------------------------------------------------------
    @staticmethod
    def _derive_detection_stage(report: SimulationReport) -> str:
        """
        Map edr_detection_time onto a descriptive stage label by comparing it
        against the encryption timeline.

        Stages
        ------
        not_detected            EDR did not fire.
        pre_encryption          Detection before first file was encrypted.
        during_encryption       Detection while files were being encrypted.
        post_encryption_pre_note Detection after last file but before note drop.
        post_note               Detection after ransom note was dropped.
        unknown                 EDR fired but timeline timestamps are missing.
        """
        if not report.edr_detected:
            return "not_detected"

        if not report.edr_detection_time:
            return "unknown"

        try:
            det = datetime.fromisoformat(report.edr_detection_time)
        except ValueError:
            return "unknown"

        def _parse(ts: str) -> Optional[datetime]:
            try:
                return datetime.fromisoformat(ts) if ts else None
            except ValueError:
                return None

        t_first = _parse(report.first_file_encrypted_time)
        t_last  = _parse(report.last_file_encrypted_time)
        t_note  = _parse(report.ransom_note_drop_time)

        if t_first is None:
            return "unknown"

        if det < t_first:
            return "pre_encryption"
        if t_last and det <= t_last:
            return "during_encryption"
        if t_note and det < t_note:
            return "post_encryption_pre_note"
        return "post_note"

    @staticmethod
    def _derive_cleanup_status(report: SimulationReport) -> str:
        """
        "success"  — all encrypted files restored with hash match
        "partial"  — some files restored but count or integrity is incomplete
        "failed"   — no files could be restored
        "pending"  — cleanup has not run yet (no dec_results)
        """
        encrypted = report.total_files_encrypted
        if encrypted == 0:
            return "pending"

        restored = report.files_restored
        if restored == 0:
            return "failed" if encrypted > 0 else "pending"

        if (
            restored == encrypted
            and report.hash_match_count == restored
        ):
            return "success"

        return "partial"
