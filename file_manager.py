import os, json, hashlib
from datetime import datetime

LOGS_DIR = "logs"

def compute_hash(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def save_snapshot(processes: list[dict], mem: dict, username: str) -> str:
    os.makedirs(LOGS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"snapshot_{timestamp}.json"
    filepath = os.path.join(LOGS_DIR, filename)

    snapshot = {
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "created_by": username,
            "process_count": len(processes)
        },
        "memory": mem,
        "processes": processes
    }
    with open(filepath, "w") as f:
        json.dump(snapshot, f, indent=2)

    file_hash = compute_hash(filepath)
    hash_file = filepath + ".sha256"
    with open(hash_file, "w") as f:
        f.write(file_hash)
    print(f"[+] Snapshot saved: {filepath}")
    print(f"[+] Integrity hash: {file_hash[:16]}...")

    return filepath

def verify_log(filepath: str) -> bool:
    hash_file = filepath + ".sha256"
    if not os.path.exists(hash_file):
        print("[-] No hash file found - can't verify integrity.")
        return False
    with open(hash_file, "r") as f:
        stored_hash = f.read().strip()
    current_hash = compute_hash(filepath)
    if current_hash == stored_hash:
        print(f"[+] Integrity OK: file has not been tampered with.")
        return True
    else:
        print(f"[!] Integrity Violation: file has been modified!")
        print(f"    Stored: {stored_hash[:32]}...")
        print(f"    Current: {current_hash[:32]}...")
        return False

def list_logs() -> list[str]:
    os.makedirs(LOGS_DIR, exist_ok=True)
    return [
        os.path.join(LOGS_DIR, f)
        for f in sorted(os.listdir(LOGS_DIR))
        if f.endswith(".json") and not f.endswith(".sha256")
    ]

def delete_log(filepath: str):
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return
    os.remove(filepath)
    hash_file = filepath +".sha256"
    if os.path.exists(hash_file):
        os.remove(hash_file)
    print(f"[+] Deleted: {filepath}")
     