#!/usr/bin/env python3
"""
orchestrator.py
Main entry point for the ransomware simulator.

Usage:
  python orchestrator.py              # run full encryption simulation
  python orchestrator.py --decrypt    # decrypt + verify (requires prior run)
  python orchestrator.py --seed       # seed test_data/ with dummy files
"""
from __future__ import annotations

import argparse
import os
import sys
import time

import config
from modules.cleanup import Cleanup
from modules.evaluation import Evaluator
from modules.file_encryptor import FileEncryptor
from modules.ransom_note import RansomNoteDropper
from utils.logger import get_logger
from utils.validator import validate_environment

logger = get_logger(__name__, log_file=config.LOG_FILE)

# ── Key is generated once per session and held only in memory ─────────────────
_SESSION_KEY: bytes | None = None
_SESSION_ENC_RESULTS: list = []


def _get_or_create_key() -> bytes:
    global _SESSION_KEY
    if _SESSION_KEY is None:
        _SESSION_KEY = os.urandom(32)
        logger.debug("AES-256 session key generated (in memory only).")
    return _SESSION_KEY


def run_encryption() -> None:
    """Phase 1 – discovery → encrypt → drop notes → evaluate."""
    key = _get_or_create_key()

    logger.info("═" * 60)
    logger.info("PHASE 1: ENCRYPTION SIMULATION")
    logger.info("Sandbox : %s", config.SANDBOX_DIR.resolve())
    logger.info("═" * 60)

    # Safety gate
    if not validate_environment(config.SANDBOX_DIR):
        logger.critical("Environment validation failed. Aborting.")
        sys.exit(1)

    # Encrypt
    encryptor = FileEncryptor(key=key, sandbox=config.SANDBOX_DIR)
    t0 = time.perf_counter()
    enc_results = encryptor.encrypt_all()
    elapsed_enc = time.perf_counter() - t0

    if not enc_results:
        logger.warning("Nothing encrypted — seed test_data/ first with --seed.")
        return

    _SESSION_ENC_RESULTS.extend(enc_results)

    # Drop ransom notes
    dropper = RansomNoteDropper()
    dropper.drop_notes(enc_results)
    dropper.write_persistence_report(config.SANDBOX_DIR)

    # Evaluate & report
    evaluator = Evaluator()
    metrics = evaluator.collect_metrics(enc_results, elapsed_enc=elapsed_enc)
    evaluator.export_json(metrics)
    evaluator.print_summary(metrics)


def run_decryption() -> None:
    """Phase 2 – decrypt all .locked files and verify hashes."""
    global _SESSION_ENC_RESULTS

    if not _SESSION_ENC_RESULTS:
        logger.error(
            "No encryption results in session. Run encryption first (same process)."
        )
        sys.exit(1)

    key = _get_or_create_key()

    logger.info("═" * 60)
    logger.info("PHASE 2: DECRYPTION + VERIFICATION")
    logger.info("═" * 60)

    cleanup = Cleanup(key=key, sandbox=config.SANDBOX_DIR)
    t0 = time.perf_counter()
    dec_results = cleanup.decrypt_all(_SESSION_ENC_RESULTS)
    elapsed_dec = time.perf_counter() - t0
    cleanup.remove_ransom_notes()

    evaluator = Evaluator()
    metrics = evaluator.collect_metrics(
        _SESSION_ENC_RESULTS, dec_results,
        elapsed_dec=elapsed_dec,
    )
    evaluator.export_json(metrics)
    evaluator.print_summary(metrics)


def seed_test_data() -> None:
    """Create sample files in test_data/ for simulation runs."""
    import random, string

    sandbox = config.SANDBOX_DIR
    sandbox.mkdir(parents=True, exist_ok=True)

    files = {
        "documents/report_q3.txt": "Q3 Financial Summary\n" + "─" * 40 + "\nRevenue: $1,200,000\n",
        "documents/notes.txt": "Meeting notes:\n- Deploy on Friday\n- Review PR #42\n",
        "documents/config.json": '{"env": "production", "debug": false, "db_host": "10.0.0.1"}\n',
        "images/photo_001.jpg": bytes(random.getrandbits(8) for _ in range(1024)),
        "images/diagram.png": bytes(random.getrandbits(8) for _ in range(2048)),
        "reports/audit_2025.csv": "id,name,amount\n1,Alice,500\n2,Bob,750\n3,Carol,300\n",
        "reports/summary.txt": "Audit complete.\nTotal: 1550\nStatus: PASS\n",
    }

    created = 0
    for rel_path, content in files.items():
        path = sandbox / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
        logger.info("Seeded: %s (%d bytes)", path, path.stat().st_size)
        created += 1

    print(f"\n✓  {created} test files created in {sandbox.resolve()}\n")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="T4816 Ransomware Behavior Simulator (Educational)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python orchestrator.py --seed       # create dummy files\n"
            "  python orchestrator.py              # simulate encryption\n"
            "  python orchestrator.py --full-cycle # encrypt then decrypt\n"
        ),
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt all .locked files (only valid after encryption in same session)",
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="Seed test_data/ with sample files",
    )
    parser.add_argument(
        "--full-cycle",
        action="store_true",
        dest="full_cycle",
        help="Encrypt then immediately decrypt (verifies full round-trip)",
    )
    args = parser.parse_args()

    print(
        "\n╔══════════════════════════════════════════╗\n"
        "║  T4816 Ransomware Behavior Simulator     ║\n"
        "║  [Educational / Research Use Only]       ║\n"
        "╚══════════════════════════════════════════╝\n"
    )

    if args.seed:
        seed_test_data()
    elif args.decrypt:
        run_decryption()
    elif args.full_cycle:
        run_encryption()
        print("\n  → Starting decryption phase...\n")
        run_decryption()
    else:
        run_encryption()


if __name__ == "__main__":
    main()
