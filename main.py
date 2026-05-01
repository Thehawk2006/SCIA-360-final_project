from auth import login, check_permission, log_security_alert
from kernel_monitor import get_processes, get_memory_info, display_processes, display_memory
from file_manager import save_snapshot, verify_log, list_logs, delete_log
from datetime import datetime

def main():
    print("=" * 50)
    print("    Secure System Observer (SSO)")
    print("=" * 50)

    result = login()
    if result is None:
        print("Exiting SSO.")
        return
    username, role = result
    login_time = datetime.now()

    while True:
        print(f"\n[{role.upper()}] Main Menu")
        print(" 1. View Running Processes")
        print(" 2. View Memory Usage")
        print(" 3. Save System Snapshot")
        print(" 4. List Saved Logs")
        print(" 5. View Security Audit Log Events")
        print(" 6. Verify log integrity")
        print(" 7. Delete a log (For Admin Only)")
        print(" 8. Exit")
        

        choice = input("\nChoice: ").strip()

        if choice == "1":
            if role == "auditor":
                print("[i] Auditor view: root-owned processes are hidden. For admin user only!")
            elif role == "admin":
                print("[i] Admin View")
            procs = get_processes(role)
            display_processes(procs)

        elif choice == "2":
            mem = get_memory_info()
            display_memory(mem)

        elif choice == "3":
            procs = get_processes(role)
            mem = get_memory_info()
            save_snapshot(procs, mem, username)

        elif choice == "4":
            logs = list_logs()
            if not logs:
                print("No logs found!")
            else:
                print("\nSaved logs:")
                for i, log in enumerate(logs):
                    print(f" [{i}] {log}")
        
        elif choice == "5":
            try:
                with open("logs/security_audit.log", "r") as f:
                    print("\n--- Security Audit Log Events ---")
                    for line in f:
                        print(line.strip())  
            except FileNotFoundError:
                print("No security audit logs found.")

        elif choice == "6":
            logs = list_logs()
            if not logs:
                print("No logs to verify.")
            else:
                for i, log in enumerate(logs):
                    print(f" [{i}] {log}")
                idx = input("Select log number: ").strip()
                try:
                    verify_log(logs[int(idx)])
                except (ValueError, IndexError):
                    print("Invalid Selection.")
            
        elif choice == "7":
            if role != "admin":
                print("Access denied! Only admin users can delete logs")
                log_security_alert(username, "ACCESS_DENIED", "Auditor attempted to delete log!")
                continue

            if not check_permission(role, "delete_log", username):
                continue

            else:
                for i, log in enumerate(logs):
                    print(f" [{i}] {log}")
                inx = input("Select a log to delete: ").strip()
                try:
                    delete_log(logs[int(idx)])
                except (ValueError, IndexError):
                    print("Invalid Selection.")


        

        elif choice == "8":
            logout_time = datetime.now()
            duration = logout_time - login_time
            log_security_alert(username, "LOGOUT", f"User exited SSO | Session duration: {duration}")
            print("Goodbye!")
            break


        else:
            print("Invalid choice, please try again!")

if __name__ == "__main__":
    main()