"""
utils/validator.py
Environment safety checks — ensures the simulator ONLY touches the sandbox.
"""
import os
import sys
from pathlib import Path

from utils.logger import get_logger

logger = get_logger(__name__)

# Paths that must NEVER be touched
_FORBIDDEN_ROOTS = [
    Path("/"),
    Path.home(),
    Path("/etc"),
    Path("/var"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/tmp"),
]


def is_within_sandbox(path: Path, sandbox: Path) -> bool:
    """Return True if *path* is strictly under *sandbox*."""
    try:
        path.resolve().relative_to(sandbox.resolve())
        return True
    except ValueError:
        return False


def validate_environment(sandbox: Path) -> bool:
    """
    Pre-flight checks before any destructive operation.
    Returns True if safe to proceed, False otherwise.
    """
    errors: list[str] = []

    # 1. Sandbox must exist
    if not sandbox.exists():
        errors.append(f"Sandbox directory does not exist: {sandbox}")

    # 2. Sandbox must be a directory, not a file or symlink chain
    if sandbox.exists() and not sandbox.is_dir():
        errors.append(f"Sandbox path is not a directory: {sandbox}")

    # 3. Sandbox must not resolve to a forbidden root
    try:
        resolved = sandbox.resolve()
        for forbidden in _FORBIDDEN_ROOTS:
            if resolved == forbidden.resolve():
                errors.append(
                    f"Sandbox resolves to a forbidden path: {resolved}"
                )
    except Exception as exc:
        errors.append(f"Could not resolve sandbox path: {exc}")

    # 4. Do NOT run as root
    if os.name != "nt" and os.geteuid() == 0:
        errors.append("Simulator should not run as root.")

    if errors:
        for e in errors:
            logger.error("SAFETY CHECK FAILED: %s", e)
        return False

    logger.info("Environment validation passed. Sandbox: %s", sandbox.resolve())
    return True
