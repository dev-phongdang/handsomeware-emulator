"""
utils/logger.py
Centralized logging for ransomware simulator.
All modules should import get_logger() from here.
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


class _MsFormatter(logging.Formatter):
    """Logging formatter with millisecond-precision timestamps.

    Standard logging.Formatter uses time.strftime() which does not support
    sub-second precision. This subclass overrides formatTime() to append
    milliseconds, producing timestamps like: 2025-01-15 10:23:41.847

    Millisecond precision is required for evaluation: detection time deltas
    between file encryption events and EDR alerts may be sub-second.
    """

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        return (
            datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            + f".{int(record.msecs):03d}"
        )


_FMT = _MsFormatter("[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s")


def get_logger(name: str, log_file: Path | None = None) -> logging.Logger:
    """Return a named logger with console (INFO+) and optional file (DEBUG+) handlers.

    Args:
        name:     Logger name, typically the module name (e.g. "encryptor").
        log_file: If provided, DEBUG-level output is also written to this file.
                  The parent directory is created automatically if needed.

    Returns:
        Configured logging.Logger instance. Safe to call multiple times with
        the same name — handlers are only attached once.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured — avoid duplicate handlers

    logger.setLevel(logging.DEBUG)

    # Console handler — INFO and above only (avoid cluttering stdout with DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(_FMT)
    logger.addHandler(ch)

    # File handler — DEBUG and above for full audit trail
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_FMT)
        logger.addHandler(fh)

    return logger

