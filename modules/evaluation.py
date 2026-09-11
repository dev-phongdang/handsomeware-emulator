"""
modules/evaluation.py
Collects simulation metrics and exports a structured JSON report.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

import config
from utils.logger import get_logger

logger = get_logger(__name__, log_file=config.LOG_FILE)


class Evaluator:
    """Aggregates metrics from encryptor and cleanup, exports JSON."""

    def collect_metrics(
        self,
        enc_results: List,
        dec_results: List | None = None,
        elapsed_enc: float = 0.0,
        elapsed_dec: float = 0.0,
    ) -> Dict[str, Any]:
        # ── Encryption metrics ─────────────────────────────────────────────
        total_enc = len(enc_results)
        ok_enc = [r for r in enc_results if r.success]
        fail_enc = [r for r in enc_results if not r.success]
        bytes_encrypted = sum(r.original_size for r in ok_enc)

        enc_section: Dict[str, Any] = {
            "files_targeted": total_enc,
            "files_encrypted": len(ok_enc),
            "files_failed": len(fail_enc),
            "bytes_encrypted": bytes_encrypted,
            "elapsed_seconds": round(elapsed_enc, 4),
            "throughput_kb_s": (
                round(bytes_encrypted / 1024 / elapsed_enc, 2) if elapsed_enc > 0 else 0
            ),
            "successes": [
                {
                    "original": r.path,
                    "encrypted": r.encrypted_path,
                    "size_bytes": r.original_size,
                    "sha256_before": r.sha256_before,
                }
                for r in ok_enc
            ],
            "failures": [
                {"path": r.path, "error": r.error} for r in fail_enc
            ],
        }

        # ── Decryption metrics ─────────────────────────────────────────────
        dec_section: Dict[str, Any] = {}
        if dec_results:
            ok_dec = [r for r in dec_results if r.success]
            hash_ok = [r for r in dec_results if r.hash_match]
            dec_section = {
                "files_decrypted": len(ok_dec),
                "hash_match": len(hash_ok),
                "hash_mismatch": len(ok_dec) - len(hash_ok),
                "elapsed_seconds": round(elapsed_dec, 4),
                "details": [
                    {
                        "restored": r.restored_path,
                        "hash_match": r.hash_match,
                        "error": r.error,
                    }
                    for r in dec_results
                ],
            }

        metrics: Dict[str, Any] = {
            "campaign_id": config.ATTACKER_ID,
            "sandbox": str(config.SANDBOX_DIR.resolve()),
            "target_extensions": config.TARGET_EXTENSIONS,
            "encryption": enc_section,
        }
        if dec_section:
            metrics["decryption"] = dec_section

        return metrics

    def export_json(self, metrics: Dict[str, Any]) -> Path:
        out = config.REPORT_FILE
        out.write_text(
            json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        logger.info("Evaluation report → %s", out)
        return out

    def print_summary(self, metrics: Dict[str, Any]) -> None:
        enc = metrics.get("encryption", {})
        print("\n" + "─" * 60)
        print("  SIMULATION SUMMARY")
        print("─" * 60)
        print(f"  Campaign   : {metrics['campaign_id']}")
        print(f"  Sandbox    : {metrics['sandbox']}")
        print(f"  Encrypted  : {enc.get('files_encrypted')}/{enc.get('files_targeted')} files")
        print(f"  Bytes      : {enc.get('bytes_encrypted', 0):,} B")
        print(f"  Enc time   : {enc.get('elapsed_seconds')} s")
        print(f"  Throughput : {enc.get('throughput_kb_s')} KB/s")
        if "decryption" in metrics:
            dec = metrics["decryption"]
            print(f"  Decrypted  : {dec.get('files_decrypted')} files")
            print(f"  Hash OK    : {dec.get('hash_match')}/{dec.get('files_decrypted')}")
        print("─" * 60)
        print(f"  Report     : {config.REPORT_FILE}")
        print("─" * 60 + "\n")
