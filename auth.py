# Program for Module C of Project: Security & Access Control
# It Handles user authentication, password hashing, RBAC, and security alert logging
#These are imports for the program
import json, hashlib, os, secrets, getpass
from datetime import datetime

#This is the name of the file where all user credentials are stored securely
Users_file = "users.json"

#This combines the password & salt together than hashes it with SHA-256
#This makes it so where the password can't be reversed to get the original password
#The salt is added to make every hash unique even if two users have the same password
def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

#This function loads all the users from the json file to the directory
#It returns an empty directory if the file does not exist yet
def load_users() -> dict:
    if not os.path.exists(Users_file):
        return {}
    with open(Users_file, "r") as f:
        return json.load(f)

#This function writes the users directory back to the json file
#It is called every time a new user is registered
def save_users(users: dict):
    with open(Users_file, "w") as f:
        json.dump(users, f, indent=2)

#This function creates a new user and saves them to the json file
def register_user(username: str, password: str, role: str):
    #Roles must either be admin or auditor, no other roles must be allowed
    if role not in ("admin", "auditor"):
        raise ValueError("admin", "auditor")

    #This loads existing users to check if the username is already taken    
    users = load_users()
    if username in users:
        raise ValueError(f"User '{username}' already exists.")

    #This generates a random 32 character salt that makes the hash unique
    #It is cryptographically secure and not random    
    salt = secrets.token_hex(16)
    #This hashes the password and combines it with the salt
    hashed = hash_password(password, salt)

    #This stores the salt, hash, and role: never stores the password in plaintext
    users[username] = {"salt": salt, "hash": hashed, "role": role}
    #This saves the updated users back into the file
    save_users(users)
    print(f"[+] User '{username}' registered as {role}.")

#This function prompts the user for credentials (username, password) and validates them
#It also returns the username and role if it's successful, and nothing if the login fails
def login() -> tuple[str, str] | None:
    print("\n--- SSO Login ---")
    username = input("Username: ").strip()
    #The getpass hides the password while the user is typing so nobody sees it on the screen
    password = getpass.getpass("Password: ")

    #This loads all the users from the file to check the credentials against it
    users = load_users()

    #This checks to see if the username exists in the system
    if username not in users:
        print("[-] Login failed: unknown user.")

        #This records a failed login attempt/username in the security audit log
        log_security_alert(username, "LOGIN_FAILED", "Unknown username")
        return None
    
    #This retrieves the stored salt and hash for the specific user
    stored = users[username]

    #This hashes the password attempt with the stored salt and compares it to see if it matches
    attempt_hash = hash_password(password, stored["salt"])
    if attempt_hash != stored["hash"]:
        #This records the failed password attempt in the security audit logs
        print("[-] Login failed: wrong password.")
        log_security_alert(username, "LOGIN_FAILED", "Wrong password")
        return None
    
    #This prints a successful login: welcomes the user and shows their role in the system
    print(f"[+] Welcome, {username} ({stored['role'].upper()})")
    
    #This records the successful login attempt in the security audit logs
    log_security_alert(username, "LOGIN_SUCCESS", "User logged in successfully")
    #This returns the username and role so the main program can enforce permissions to it
    return username, stored["role"]

#This function encforces RBAC
#It Checks if the current user's role is allowed to perform the requested action
#Auditors can't delete logs or view root processes
#If its denied it will log a security audit log
def check_permission(role: str, action: str, username: str) -> bool:
    #This defines which actions require the role of admin to do
    admin_only = {"delete_log", "view_root_processes"}

    #If the action is only for admin and the user is an auditor, it will deny it and log the action
    if action in admin_only and role != "admin":
        msg = f"Auditor '{username}' attempted restricted action: {action}"
        print(f"[!] ACCESS DENIED: {msg}")
        #This records the denied action to the security audit log
        log_security_alert(username, "ACCESS_DENIED", msg)
        return False

    #This grants permission
    return True

#This function appends a security event to the audit log file
#It records failed logins, successful logins, logouts, and access denials
#Each entry in it includes a timestamp, username, event type, and details of the log
def log_security_alert(username: str, alert_type: str, detail: str):
    os.makedirs("logs", exist_ok=True)
    
    with open("logs/security_audit.log", "a") as f:
        entry = { 
            "timestamp": datetime.now().isoformat(), #Exact time of the event
            "user": username, #What user/who triggered the event
            "type": alert_type, #The type of event 
            "detail": detail #A full description of what happened
        }

        #This writes the entry as a json line so each event has its own line
        f.write(json.dumps(entry) + "\n")
