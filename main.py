#This is the program of the Secure System Observer (SSO)
#This program ties all the modules into one application
#It includes Module A: kernel_monitor.py, Module B: file_manager.py, and Module C: auth.py

#This imports the necessary functions from all three modules
from auth import login, check_permission, log_security_alert
from kernel_monitor import get_processes, get_memory_info, display_processes, display_memory
from file_manager import save_snapshot, verify_log, list_logs, delete_log
from datetime import datetime

#This function prints the application header or GUI
def main():
    print("=" * 50)
    print("    Secure System Observer (SSO)")
    print("=" * 50)

    #This is from Module C: the authentication gate
    #The application will not proceed past this point with a successful login
    #The login() will return the username and role if login is successful and Nothing if it was unsuccessful
    result = login()
    if result is None:
        print("Exiting SSO.")
        return
    
    #This unpacks the username and role returned from the login
    username, role = result
    #This records the login time to calculate session duration when it logs out
    login_time = datetime.now()

    #This is the main menu loop - it will keep running until the user chooses the exit option
    while True:
        #This shows the role in the menu header so the user knows who they are logged in as
        print(f"\n[{role.upper()}] Main Menu")
        print(" 1. View Running Processes")
        print(" 2. View Memory Usage")
        print(" 3. Save System Snapshot")
        print(" 4. List Saved Logs")
        print(" 5. View Security Audit Log Events")
        print(" 6. Verify log integrity")
        print(" 7. Delete a log (For Admin Only)") #This option is shown to all but denied when auditor tries to access it and allowed for admin only
        print(" 8. Exit")
        
        #This is the choice input
        choice = input("\nChoice: ").strip()

        #This is from Module A: which displays running processes in the system
        #Auditors will see a filtered list without root processes
        #Admins will see all the processes including the root owned ones
        if choice == "1":
            if role == "auditor":
                print("[i] Auditor view: root-owned processes are hidden. For admin user only!")
            
            elif role == "admin":
                print("[i] Admin View")
            
            #This shows the get_processes() which filters based on the role internally
            procs = get_processes(role)
            display_processes(procs)

        #This is from Module A: which will display RAM and Swap memory usage in the system
        #This also shows physical RAM vs virtual Swap memory separately
        elif choice == "2":
            mem = get_memory_info()
            display_memory(mem)

        #This from Module B: which saves a snapshot of the current system state
        #It captures all the processes and memory stats to a timestamped json file
        #It also generates a SHA-256 hash for future integrity verifications
        elif choice == "3":
            procs = get_processes(role)
            mem = get_memory_info()
            save_snapshot(procs, mem, username)

        #This is from Module B: which lists all the saved snapshot log files
        elif choice == "4":
            logs = list_logs()
            if not logs:
                print("No logs found!")

            else:
                print("\nSaved logs:")
                for i, log in enumerate(logs):
                    print(f" [{i}] {log}")
        
        #This is from Module C: Which views the security audit logs
        #This shows all recorded events including logins, logouts, failures of logins, and denial of access to certain things
        elif choice == "5":
            try:
                with open("logs/security_audit.log", "r") as f:
                    print("\n--- Security Audit Log Events ---")
                    for line in f:
                        print(line.strip())

            except FileNotFoundError:
                print("No security audit logs found.")

        #This is from Module B: it verifies that a log file has not been tampered with
        # It also recomputes the SHA-256 hash and then compares it to the stored hash 
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

        #This from Module C: it allows to delete a log file but only if your admin
        # It first checks if the user is admin, if it isn't the action is denied and the attempt is logged
        # This also reinforces the principle of least privilege from RBAC (Role-Based Access Control)    
        elif choice == "7":
            if role != "admin":
                print("Access denied! Only admin users can delete logs")
                #This records the unauthorized attempt to the security audit log
                log_security_alert(username, "ACCESS_DENIED", "Auditor attempted to delete log!")
                continue

            #This double checks the permission using the RBAC function from auth.py program
            if not check_permission(role, "delete_log", username):
                continue

            else:
                #This shows available logs and lets the admin choose which ones to delete
                for i, log in enumerate(logs):
                    print(f" [{i}] {log}")
                inx = input("Select a log to delete: ").strip()
                try:
                    delete_log(logs[int(idx)])
                except (ValueError, IndexError):
                    print("Invalid Selection.")

        elif choice == "8":
            #This logs the logout event with duration of the session before exiting it
            logout_time = datetime.now()
            duration = logout_time - login_time #This calculates how long they were logged in for 
            log_security_alert(username, "LOGOUT", f"User exited SSO | Session duration: {duration}")
            print("Goodbye!")
            break

        else:
            #This handles any invalid menu choices
            print("Invalid choice, please try again!")

#This is the entry point that only runs if the file is executed directly
if __name__ == "__main__":
    main()