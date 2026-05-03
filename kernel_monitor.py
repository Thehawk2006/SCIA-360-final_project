#Program for module A of the Project
#It reads live processes and memory data directly from the OS kernel
#It uses a psutil library which interfaces with the /proc files
import os, psutil

#This functions retrieves a list of all current running processes on the system
#Admins can see every processes including ones owned by the root
#Auditors can only see non-root processes enforcing the principle of least privilege
def get_processes(role: str) -> list[dict]:
    processes = []

    #psutil.process_iter loops every active process on the system
    #It reads from /proc/[pid]/stat on Linux for each process
    for proc in psutil.process_iter(['pid', 'name', 'status', 'username']):
        try:
            info = proc.info

            # Auditors cannot see root-owned processes
            # This enforces the least privilege principle from Module C
            if role == "auditor" and info.get("username") == "root":
                continue

            #This adds the process info to our list
            processes.append({
                "pid":      info["pid"], #This shows the process ID unique identifier
                "name":     info["name"] or "N/A", #This is the name of the process
                "state":    map_state(info["status"]), #This converts the state to a single letter to represent it
                "user":     info.get("username", "N/A") #This shows which user owns this process
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            #NoSuchProcess means the process ended while we were reading it
            #AccessDenied means we dont have permission to read it
            continue
    return processes

#This function converts the psutil process status strings to standard OS state codes
#These codes match what you see in the Linux /proc/[pid]/stat file
#The states include: R = running, S = sleeping, D = disk-sleep, ST = stopped, Z = zombie, I = idle
def map_state(status: str) -> str:
    mapping = {
        "running": "R", #This is currently using the CPU
        "sleeping": "S", #This is waiting for an event like a user input
        "disk-sleep": "D", #Waiting for the Disk IO must not be interrupted
        "stopped": "ST", #The process has been paused
        "zombie": "Z", #The process has finished but parent hasn't read exited it yet
        "idle": "I" #Process is idle and not doing anything
    }
    #This returns the code or ? if we don't recognize the status of the process
    return mapping.get(status, "?")

#This function retrieves current RAM and Swap memory stats from the OS
#Also demonstrates an understanding of VM concepts
#The Linux psutil reads /proc/meminfo to get these values
#Ram is the physical memory installed on the machine and Swap is the virtual memory on the disk when RAM is full
def get_memory_info() -> dict:

    ram = psutil.virtual_memory() #Physical RAM stats
    swap = psutil.swap_memory() #Swap space stats

    #This returns the RAM statistics - pysical memory on the machine
    return {
        "ram_total_mb":  round(ram.total  / 1024**2, 1), #Total RAM installed
        "ram_used_mb":   round(ram.used   / 1024**2, 1), #RAM currently used
        "ram_free_mb":   round(ram.available / 1024**2, 1), #RAM available to use
        "ram_percent":   ram.percent, #The percentage used

        #This returns the swap statistics - virtual memory on the disk
        "swap_total_mb": round(swap.total / 1024**2, 1), #Total swap space
        "swap_used_mb":  round(swap.used  / 1024**2, 1), #Swap currently being used
        "swap_free_mb":  round((swap.total - swap.used) / 1024**2, 1), #Swap available for use
        "swap_percent":  swap.percent, #The percentage of swap used
    }

#This function prints a list of processes in a formatted table to the terminal
#It shows up to 30 processes then tells you how many there are
def display_processes(processes: list[dict]):
    print(f"\n{'PID':<8} {'State':<6} {'User':<15} {'Name'}")
    print("-" * 50)

    #This prints each process on its own line with fixed column widths
    for p in processes[:30]:
        print(f"{p['pid']:<8} {p['state']:<6} {p['user']:<15} {p['name']}")
    
    #This tells you if there are more than 30 processes it tells how many are hidden
    if len(processes) > 30:
        print(f"  ... and {len(processes) - 30} more processes")

#This function prints the RAM and Swap memory usage to the terminal
# It also clearly separates physical RAM from swap to show understanding of virtual memory     
def display_memory(mem: dict):
    print("\n--- Memory Usage ---")
    print(f"  Physical RAM : {mem['ram_used_mb']} / {mem['ram_total_mb']} MB  ({mem['ram_percent']}% used)")
    print(f"  Swap Space   : {mem['swap_used_mb']} / {mem['swap_total_mb']} MB  ({mem['swap_percent']}% used)")
