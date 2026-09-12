"""
utils/validator.py
Environment safety checks — 6 ordered checks that must ALL pass before
any destructive operation is allowed.

Check order (early-exit on CRITICAL):
  1. LAB_ENVIRONMENT env-var == "1"          → CRITICAL  (lab identity)
  2. BASE_DIR/.lab_marker sentinel exists    → CRITICAL  (lab identity)
  3. SANDBOX_DIR exists                      → ERROR
  4. SANDBOX_DIR is a directory              → ERROR
  5. SANDBOX_DIR is inside BASE_DIR          → CRITICAL  (path-traversal guard)
  6. SANDBOX_DIR contains ≥1 file           → WARNING   (no exit)

Checks 1+2 are grouped as "lab identity" and short-circuit immediately:
if either fails the validator stops without inspecting paths, because we
cannot trust any path-level logic outside a confirmed lab environment.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import logging

_LAB_ENV_VAR  = "LAB_ENVIRONMENT"
_LAB_ENV_VAL  = "1"
_SENTINEL_NAME = ".lab_marker"


def validate_environment(cfg, logger: "logging.Logger") -> bool:
    """
    Run all 6 pre-flight checks against *cfg* (the config module).

    Args:
        cfg:    The imported config module (provides BASE_DIR, SANDBOX_DIR).
        logger: A Logger instance — caller supplies it so the validator stays
                decoupled from the logging initialisation order.

    Returns:
        True  — all critical/error checks passed (warnings may still exist).
        False — at least one CRITICAL or ERROR check failed; nothing runs.
    """

    # ── CHECK 1: LAB_ENVIRONMENT variable ────────────────────────────────────
    lab_env = os.environ.get(_LAB_ENV_VAR, "")
    if lab_env != _LAB_ENV_VAL:
        logger.critical(
            "[CHECK 1] FAIL — %s is not set to '%s' (got %r). "
            "Refusing to run outside a confirmed lab environment.",
            _LAB_ENV_VAR, _LAB_ENV_VAL, lab_env,
        )
        return False          # immediate exit — no further checks
    logger.debug("[CHECK 1] PASS — %s=%s", _LAB_ENV_VAR, lab_env)

    # ── CHECK 2: Sentinel file ────────────────────────────────────────────────
    sentinel = cfg.BASE_DIR / _SENTINEL_NAME
    if not sentinel.exists():
        logger.critical(
            "[CHECK 2] FAIL — Sentinel file not found: %s. "
            "Create this file in the VM to enable the simulator.",
            sentinel,
        )
        return False          # immediate exit
    logger.debug("[CHECK 2] PASS — sentinel found: %s", sentinel)

    # Lab identity confirmed — safe to inspect paths.

    # ── CHECK 3: SANDBOX_DIR exists ───────────────────────────────────────────
    if not cfg.SANDBOX_DIR.exists():
        logger.error(
            "[CHECK 3] FAIL — SANDBOX_DIR does not exist: %s",
            cfg.SANDBOX_DIR,
        )
        return False
    logger.debug("[CHECK 3] PASS — SANDBOX_DIR exists: %s", cfg.SANDBOX_DIR)

    # ── CHECK 4: SANDBOX_DIR is a directory ───────────────────────────────────
    if not cfg.SANDBOX_DIR.is_dir():
        logger.error(
            "[CHECK 4] FAIL — SANDBOX_DIR is not a directory: %s",
            cfg.SANDBOX_DIR,
        )
        return False
    logger.debug("[CHECK 4] PASS — SANDBOX_DIR is a directory")

    # ── CHECK 5: Path-traversal guard ─────────────────────────────────────────
    # Most important safety check: SANDBOX_DIR must resolve to a path
    # strictly inside BASE_DIR. Catches symlink attacks and misconfiguration.
    try:
        cfg.SANDBOX_DIR.resolve().relative_to(cfg.BASE_DIR.resolve())
    except ValueError:
        logger.critical(
            "[CHECK 5] FAIL — SANDBOX_DIR (%s) is outside BASE_DIR (%s). "
            "Possible path-traversal misconfiguration. Aborting.",
            cfg.SANDBOX_DIR.resolve(),
            cfg.BASE_DIR.resolve(),
        )
        return False
    logger.debug(
        "[CHECK 5] PASS — SANDBOX_DIR is inside BASE_DIR (%s)",
        cfg.BASE_DIR.resolve(),
    )

    # ── CHECK 6: Sandbox not empty (warning only — no exit) ───────────────────
    has_files = any(f.is_file() for f in cfg.SANDBOX_DIR.rglob("*"))
    if not has_files:
        logger.warning(
            "[CHECK 6] WARN — SANDBOX_DIR appears empty. "
            "Seed it first with: python orchestrator.py --seed",
        )
    else:
        logger.debug("[CHECK 6] PASS — SANDBOX_DIR contains at least one file")

    # ── All critical/error checks passed ──────────────────────────────────────
    logger.info(
        "Environment validation passed. Sandbox: %s",
        cfg.SANDBOX_DIR.resolve(),
    )
    return True


def is_within_sandbox(path: Path, sandbox: Path) -> bool:
    """Return True if *path* resolves strictly inside *sandbox*.

    Used by FileEncryptor and Cleanup to guard every individual file
    operation — a second line of defence after validate_environment().
    """
    try:
        path.resolve().relative_to(sandbox.resolve())
        return True
    except ValueError:
        return False
