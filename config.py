"""
config.py
Central configuration for the ransomware simulator.
Edit this file to tune scope, extensions, and output paths.
"""

from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
SANDBOX_DIR = BASE_DIR / "test_data"  # ONLY directory ever touched
LOG_FILE = BASE_DIR / "simulation.log"
REPORT_FILE = BASE_DIR / "evaluation_report.json"

# ── Encryption ────────────────────────────────────────────────────────────────
KEY_SIZE = 32  # bytes → AES-256  (must be passed to AESGCM as exactly 32 B)
NONCE_SIZE = 12  # bytes → GCM standard nonce (96-bit)
AUTH_TAG_SIZE = 16  # bytes → GCM authentication tag appended by cryptography lib
ENCRYPTED_EXT = ".locked"  # suffix appended to every encrypted file

# On-disk layout per encrypted file:
#   [ NONCE_SIZE bytes ][ ciphertext ][ AUTH_TAG_SIZE bytes ]
#   └── 12 B nonce ──┘ └── variable ─┘ └── 16 B GCM tag ──┘
# Total overhead per file: NONCE_SIZE + AUTH_TAG_SIZE = 28 bytes

# ── Targeting ─────────────────────────────────────────────────────────────────
# frozenset  → immutable (cannot be mutated at runtime), O(1) membership lookup
# list[str]  → mutable   (accidental .append() possible),  O(n) lookup
TARGET_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".txt",
        ".csv",
        ".json",
        ".pdf",
        ".docx",
        ".xlsx",
        ".jpg",
        ".jpeg",
        ".png",
        ".log",
        ".xml",
        ".html",
    }
)

# ── Ransom note ───────────────────────────────────────────────────────────────
RANSOM_NOTE_NAME = "README_DECRYPT.txt"
RANSOM_CONTACT = "sim-research@lab.local"  # fictional address
ATTACKER_ID = "T1486-SIMULATOR"  # campaign identifier

# ── Persistence simulation ────────────────────────────────────────────────────
# No real persistence is created; only a JSON report of what WOULD be applied.
PERSISTENCE_REPORT_NAME = ".persistence_sim.json"

# C2 Server
CALLBACK_SERVER_HOST = "10.0.1.1"
CALLBACK_SERVER_PORT = 4444
