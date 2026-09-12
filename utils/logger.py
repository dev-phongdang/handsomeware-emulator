"""
utils/logger.py — Structured logger with millisecond UTC timestamps.

Standard logging.Formatter's datefmt has no sub-second directive, so we
subclass it and override formatTime() to emit UTC time at ms precision.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path


class _MsFormatter(logging.Formatter):
    """Formatter that emits UTC timestamps with millisecond precision."""

    def formatTime(self, record, datefmt=None):  # noqa: N802 (stdlib naming)
        return (
            datetime.fromtimestamp(record.created, tz=timezone.utc)
            .strftime("%Y-%m-%d %H:%M:%S")
            + f".{int(record.msecs):03d}"
        )


_FMT     = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATEFMT = None   # handled inside _MsFormatter.formatTime


def get_logger(name: str, log_file: Path | None = None) -> logging.Logger:
    """
    Return a logger for *name*.

    Parameters
    ----------
    name:     module __name__ or any label
    log_file: optional path to write a file handler alongside stderr
    """
    logger    = logging.getLogger(name)
    formatter = _MsFormatter(fmt=_FMT, datefmt=_DATEFMT)

    if not logger.handlers:
        # Console handler
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        logger.addHandler(sh)

        # File handler (caller supplies the path)
        if log_file is not None:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(formatter)
            logger.addHandler(fh)

        logger.setLevel(logging.DEBUG)
        logger.propagate = False

    return logger
