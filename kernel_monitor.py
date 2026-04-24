import os, psutil

def get_processes(role: str) -> list[dict]:
    """
    Returns list of process dicts.
    Admins see all processes; auditors skip root-owned ones.
    """
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'status', 'username']):
        try:
            info = proc.info
            # Auditors cannot see root-owned processes
            if role == "auditor" and info.get("username") == "root":
                continue
            processes.append({
                "pid":      info["pid"],
                "name":     info["name"] or "N/A",
                "state":    map_state(info["status"]),
                "user":     info.get("username", "N/A")
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

def map_state(status: str) -> str:
    mapping = {
        "running": "R",
        "sleeping": "S",
        "disk-sleep": "D",
        "stopped": "ST",
        "zombie": "Z",
        "idle": "I"
    }
    return mapping.get(status, "?")

def get_memory_info() -> dict:
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "ram_total_mb":  round(ram.total  / 1024**2, 1),
        "ram_used_mb":   round(ram.used   / 1024**2, 1),
        "ram_free_mb":   round(ram.available / 1024**2, 1),
        "ram_percent":   ram.percent,
        "swap_total_mb": round(swap.total / 1024**2, 1),
        "swap_used_mb":  round(swap.used  / 1024**2, 1),
        "swap_free_mb":  round((swap.total - swap.used) / 1024**2, 1),
        "swap_percent":  swap.percent,
    }

def display_processes(processes: list[dict]):
    print(f"\n{'PID':<8} {'State':<6} {'User':<15} {'Name'}")
    print("-" * 50)
    for p in processes[:30]:
        print(f"{p['pid']:<8} {p['state']:<6} {p['user']:<15} {p['name']}")
    if len(processes) > 30:
        print(f"  ... and {len(processes) - 30} more processes")
    
def display_memory(mem: dict):
    print("\n--- Memory Usage ---")
    print(f"  Physical RAM : {mem['ram_used_mb']} / {mem['ram_total_mb']} MB  ({mem['ram_percent']}% used)")
    print(f"  Swap Space   : {mem['swap_used_mb']} / {mem['swap_total_mb']} MB  ({mem['swap_percent']}% used)")
