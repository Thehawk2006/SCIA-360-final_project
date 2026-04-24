import json, hashlib, os, secrets, getpass
from datetime import datetime

Users_file = "users.json"

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

def load_users() -> dict:
    if not os.path.exists(Users_file):
        return {}
    with open(Users_file, "r") as f:
        return json.load(f)

def save_users(users: dict):
    with open(Users_file, "w") as f:
        json.dump(users, f, indent=2)

def register_user(username: str, password: str, role: str):
    if role not in ("admin", "auditor", "auditor1"):
        raise ValueError("admin", "auditor")
    users = load_users()
    if username in users:
        raise ValueError(f"User '{username}' already exists.")
    salt = secrets.token_hex(16)
    hashed = hash_password(password, salt)
    users[username] = {"salt": salt, "hash": hashed, "role": role}
    save_users(users)
    print(f"[+] User '{username}' registered as {role}.")

def login() -> tuple[str, str] | None:
    print("\n--- SSO Login ---")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    users = load_users()
    if username not in users:
        print("[-] Login failed: unknown user.")
        log_security_alert(username, "LOGIN_FAILED", "Unknown username")
        return None
    stored = users[username]
    attempt_hash = hash_password(password, stored["salt"])
    if attempt_hash != stored["hash"]:
        print("[-] Login failed: wrong password.")
        log_security_alert(username, "LOGIN_FAILED", "Wrong password")
        return None
    print(f"[+] Welcome, {username} ({stored['role'].upper()})")
    return username, stored["role"]

def check_permission(role: str, action: str, username: str) -> bool:
    """
    RBAC enforcement. Auditors cannot: delete logs, view root processes.
    Logs a Security Alert if denied.
    """

    admin_only = {"delete_log", "view_root_processes"}
    if action in admin_only and role != "admin":
        msg = f"Auditor '{username}' attempted restricted action: {action}"
        print(f"[!] ACCESS DENIED: {msg}")
        log_security_alert(username, "ACCESS_DENIED", msg)
        return False
    return True

def log_security_alert(username: str, alert_type: str, detail: str):
    "Append a security alert to the audit log file"
    os.makedirs("logs", exist_ok=True)
    with open("logs/security_audit.log", "a") as f:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "user": username,
            "type": alert_type,
            "detail": detail
        }
        f.write(json.dumps(entry) + "\n")
