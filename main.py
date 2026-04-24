from auth import login, check_permission
from kernel_monitor import get_processes, get_memory_info, display_processes, display_memory
from file_manager import save_snapshot, verify_log, list_logs, delete_log

def main():
    print("=" * 50)
    print("    Secure System Observer (SSO)")
    print("=" * 50)

    result = login()
    if result is None:
        print("Exiting SSO.")
        return
    username, role = result

    while True:
        print(f"\n[{role.upper()}] Main Menu")
        print(" 1. View Running Processes")
        print(" 2. View Memory Usage")
        print(" 3. Save System Snapshot")
        print(" 4. List Saved Logs")
        print(" 5. Verify log integrity")
        if role == "admin" or "auditor":
            print(" 6. Delete a log (For Admin Only)")
        print(" 7. Exit")

        choice = input("\nChoice: ").strip()

        if choice == "1":
            if role == "auditor" or "auditor1":
                print("[i] Auditor view: root-owned processes are hidden. For admin user only!")
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
            logs = list_logs()
            if not logs:
                print("No logs to verify.")
            else:
                for i, log in enumerate(logs):
                    print(f" [{i}] {log}")
                idx = input("Select log number: ").strip()
                try:
                    verify_log(logs[int](idx))
                except (ValueError, IndexError):
                    print("Invalid Selection.")
            
        elif choice == "6":
            if not check_permission(role, "delete_log", username):
                continue
            logs = list_logs()
            if not logs:
                print("No logs to delete.")
            else:
                for i, log in enumerate(logs):
                    print(f"  [{i}] {log}")
                idx = input("Select log to delete: ").strip()
                try:
                    delete_log(logs[int(idx)])
                except (ValueError, IndexError):
                    print("Invalid selection.")
        
        elif choice == "7":
            print("Goodbye!")
            break

        else:
            print("Invalid choice, please try again!")

if __name__ == "__main__":
    main()