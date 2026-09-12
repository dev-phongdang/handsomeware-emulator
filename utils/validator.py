"""
utils/validator.py — Pre-flight environment safety checks.

Design rationale
----------------
We cannot trust ANY path-level logic until we have first confirmed, through
out-of-band signals, that this process is running inside a prepared lab.
A misconfigured or accidentally-moved installation could otherwise apply
"sandbox" path guards to the wrong directory.

Two independent out-of-band signals are required:
  1. Environment variable  LAB_ENVIRONMENT=1   (set by the lab harness)
  2. Sentinel file         {BASE_DIR}/.lab_marker  (placed by lab setup)

If EITHER is missing → immediate abort before any path logic is evaluated.
"""

import logging
import os
from pathlib import Path


def validate_environment(cfg, logger: logging.Logger) -> bool:
    """
    Run 6 ordered safety checks.  Returns True only if all pass.

    Checks 1–2 are lab-identity guards; failure causes immediate return False.
    Checks 3–5 are path-safety guards; failure causes immediate return False.
    Check 6 is advisory (non-empty sandbox); emits WARNING but does not abort.
    """

    # ------------------------------------------------------------------
    # CHECK 1 — LAB_ENVIRONMENT env var
    # ------------------------------------------------------------------
    if os.environ.get("LAB_ENVIRONMENT") != "1":
        logger.critical(
            "[CHECK 1] FAIL — env var LAB_ENVIRONMENT is not set to '1'. "
            "Refusing to run outside a confirmed lab environment."
        )
        return False

    # ------------------------------------------------------------------
    # CHECK 2 — .lab_marker sentinel file
    # ------------------------------------------------------------------
    sentinel = cfg.BASE_DIR / ".lab_marker"
    if not sentinel.exists():
        logger.critical(
            "[CHECK 2] FAIL — sentinel file '%s' not found. "
            "Refusing to run: lab identity unconfirmed.", sentinel
        )
        return False

    logger.info("[CHECK 1] PASS — LAB_ENVIRONMENT=1")
    logger.info("[CHECK 2] PASS — sentinel file present")

    # ------------------------------------------------------------------
    # CHECK 3 — SANDBOX_DIR exists
    # ------------------------------------------------------------------
    if not cfg.SANDBOX_DIR.exists():
        logger.critical(
            "[CHECK 3] FAIL — SANDBOX_DIR '%s' does not exist.", cfg.SANDBOX_DIR
        )
        return False
    logger.info("[CHECK 3] PASS — SANDBOX_DIR exists")

    # ------------------------------------------------------------------
    # CHECK 4 — SANDBOX_DIR is a directory
    # ------------------------------------------------------------------
    if not cfg.SANDBOX_DIR.is_dir():
        logger.critical(
            "[CHECK 4] FAIL — SANDBOX_DIR '%s' exists but is not a directory.",
            cfg.SANDBOX_DIR,
        )
        return False
    logger.info("[CHECK 4] PASS — SANDBOX_DIR is a directory")

    # ------------------------------------------------------------------
    # CHECK 5 — path traversal: sandbox must be inside BASE_DIR
    # ------------------------------------------------------------------
    try:
        cfg.SANDBOX_DIR.resolve().relative_to(cfg.BASE_DIR.resolve())
    except ValueError:
        logger.critical(
            "[CHECK 5] FAIL — SANDBOX_DIR '%s' is not under BASE_DIR '%s'. "
            "Possible path-traversal attempt.",
            cfg.SANDBOX_DIR, cfg.BASE_DIR,
        )
        return False
    logger.info("[CHECK 5] PASS — SANDBOX_DIR is inside BASE_DIR")

    # ------------------------------------------------------------------
    # CHECK 6 — sandbox is not empty (advisory only)
    # ------------------------------------------------------------------
    files = list(cfg.SANDBOX_DIR.iterdir())
    if not files:
        logger.warning(
            "[CHECK 6] WARN — SANDBOX_DIR '%s' is empty. "
            "Nothing to encrypt.", cfg.SANDBOX_DIR
        )
    else:
        logger.info("[CHECK 6] PASS — SANDBOX_DIR is non-empty (%d entries)", len(files))

    return True


def is_within_sandbox(path: Path, sandbox: Path) -> bool:
    """
    Return True if *path* resolves to a location inside *sandbox*.

    Used as a per-file guard inside file_encryptor and cleanup to prevent
    any single file operation from escaping the sandbox even if a path
    is somehow crafted to point outside it.
    """
    try:
        path.resolve().relative_to(sandbox.resolve())
        return True
    except ValueError:
        return False
