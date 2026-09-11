# T4816 Ransomware Behavior Simulator

> **Educational / Research Use Only**  
> All operations are confined to `test_data/` — nothing outside is touched.

## Quick Start

```bash
# 1. Install dependency
pip install cryptography

# 2. Seed test_data/ with dummy files
python orchestrator.py --seed

# 3. Run encryption simulation
python orchestrator.py

# 4. Inspect results — then decrypt & verify
python orchestrator.py --decrypt

# Or do a full round-trip in one command:
python orchestrator.py --seed && python orchestrator.py --full-cycle
```

## Project Structure

```
ransomware_simulator/
├── config.py               ← paths, target extensions, campaign ID
├── orchestrator.py         ← CLI entry point, coordinates all phases
├── modules/
│   ├── file_encryptor.py   ← AES-256-GCM, per-file nonce, SHA-256 tracking
│   ├── ransom_note.py      ← drops README_DECRYPT.txt + persistence report
│   ├── cleanup.py          ← decryption + hash verification
│   └── evaluation.py       ← metrics collection, JSON report
├── utils/
│   ├── logger.py           ← centralised logging (console + file)
│   └── validator.py        ← environment safety checks
├── test_data/              ← ONLY directory ever modified
│   ├── documents/
│   ├── images/
│   └── reports/
├── simulation.log          ← full debug log (generated at runtime)
└── evaluation_report.json  ← structured metrics (generated at runtime)
```

## Key Design Decisions

| Property | Value |
|---|---|
| Cipher | AES-256-GCM (authenticated) |
| Key size | 32 bytes, random, **in memory only** |
| Nonce | 12 bytes, random per file |
| Encrypted format | `[12B nonce][ciphertext + 16B GCM tag]` |
| File rename | `file.txt` → `file.txt.locked` |
| Network | None |
| Scope enforcement | `utils/validator.py` — hard abort if outside sandbox |

## Behaviors Simulated

- **File discovery** — recursive scan for target extensions
- **Encryption** — AES-256-GCM, one nonce per file
- **Ransom note** — `README_DECRYPT.txt` in every affected directory
- **Persistence report** — shows OS-specific persistence tactics (no real modification)
- **Decryption** — full reversal with SHA-256 integrity check
- **Evaluation** — JSON metrics report with throughput, hash match rate
