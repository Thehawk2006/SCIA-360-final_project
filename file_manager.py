#This is the module B program for the project
#It handles file systems and data persistence
#It also handles saving system snapshots, verifying file integrity, and managing log files
#It demonstrates file metadata management and tamper detection using a SHA-256 checksum
import os, json, hashlib
from datetime import datetime

#This is the directory where all the log files and snapshots are stored
LOGS_DIR = "logs"

#This function computes a SHA-256 checksum of a file which can detect tampering
#It also reads the file into 4096 byte chunks to handle large files efficiently
#It then returns a 64 character hex string that represents the file contents
#If even one character in the file changes the hash will be completely different
def compute_hash(filepath: str) -> str:
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        #This reads the file in chunks so large files don't use that much memory
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

#This function saves the current system state to a timestamped JSON log file
#This captures the process list, memory stats, and metadata including who created it
#Then it immediates generates a SHA-256 hash after saving for future integrity checks
def save_snapshot(processes: list[dict], mem: dict, username: str) -> str:
    #This creates the logs directory if it doesn't exist yet
    os.makedirs(LOGS_DIR, exist_ok=True)

    #This creates a unique filename using the current date and time
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"snapshot_{timestamp}.json"
    filepath = os.path.join(LOGS_DIR, filename)

    #This builds the snapshot directory with metadata, memory, and process data
    snapshot = {
        "metadata": {
            "created_at": datetime.now().isoformat(), #The exact timestamp of its creating 
            "created_by": username, #Which user generated this report/snapshot
            "process_count": len(processes) #How many processes were captured
        },
        "memory": mem, #This shows the ram and swap statistics at the time of the snapshot
        "processes": processes #This shows the full list of running processes at the time of the snapshot
    }

    #This writes the snapshot data to the JSON file
    with open(filepath, "w") as f:
        json.dump(snapshot, f, indent=2)

    #This generates the integrity hash immediately after writing it
    #The hash is stored separatelt and used to detect tampering if changed
    file_hash = compute_hash(filepath)
    hash_file = filepath + ".sha256"
    with open(hash_file, "w") as f:
        f.write(file_hash)
    print(f"[+] Snapshot saved: {filepath}")
    print(f"[+] Integrity hash: {file_hash[:16]}...") #This shows the first 16 characters of the hash

    return filepath

#This function verifies that a log file has not been tampered with since it was created
#It also recomputes the SHA-256 hash and compares it to the stored hash
#If the hashes match they are ok, but if they differ the file was modified
def verify_log(filepath: str) -> bool:
    
    #This looks for the stored hash file that was created alongside the snapshot
    hash_file = filepath + ".sha256"
    if not os.path.exists(hash_file):
        print("[-] No hash file found - can't verify integrity.")
        return False
    
    #This reads the original hash that was stored when the file was first created
    with open(hash_file, "r") as f:
        stored_hash = f.read().strip()

    #This recomputes the hash of the current file contents
    current_hash = compute_hash(filepath)

    #This compares the two hashes (they must exactly match)
    if current_hash == stored_hash:
        print(f"[+] Integrity OK: file has not been tampered with.")
        return True
    else:
        #This shows the hashes don't match meaning the file was changed after creation
        print(f"[!] Integrity Violation: file has been modified!")
        print(f"    Stored: {stored_hash[:32]}...") #Original hash
        print(f"    Current: {current_hash[:32]}...") #New hash after it was tampered with
        return False

#This function returns a sorted list of all snapshot log files in the logs directory
#It excludes the .sha256 files
def list_logs() -> list[str]:

    os.makedirs(LOGS_DIR, exist_ok=True)
    return [
        os.path.join(LOGS_DIR, f)
        #This only includes .json files but not .sha256 files
        for f in sorted(os.listdir(LOGS_DIR))
        if f.endswith(".json") and not f.endswith(".sha256")
    ]

#This function allows for log files and its hash files to be deleted 
#Only admin users are allowed to do this
#Both the snapshot and its .sha256 integrity file are removed together
def delete_log(filepath: str):

    #This checks the file to make sure it actually exists before trying to delete it
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return
    
    #This deletes the main snapshot file
    os.remove(filepath)

    #This also deletes the corresponding hash file if it exists
    hash_file = filepath +".sha256"
    if os.path.exists(hash_file):
        os.remove(hash_file)
    print(f"[+] Deleted: {filepath}")
     