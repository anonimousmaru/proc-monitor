#!/usr/bin/env python3
"""
Proc-Monitor - Process Resource Monitor
No external dependencies required! Works with standard Python libraries only.
Monitors high CPU/RAM processes and identifies their parent services.

Supports two modes:
- threshold: Capture all processes above CPU/RAM thresholds
- top_n: Capture top N processes by CPU/RAM usage

GitHub: https://github.com/cagatayuresin/proc-monitor
Usage: sudo python3 proc_monitor.py

License: MIT
"""

import os
import sys
import time
import json
import signal
from datetime import datetime
from collections import defaultdict

# ============================================================================
# DEFAULT CONFIGURATION (overridden by config.json if present)
# ============================================================================
DEFAULT_CONFIG = {
    "mode": "threshold",          # "threshold" or "top_n"
    "top_n": 5,                   # Number of top processes to track (for top_n mode)
    "cpu_threshold": 50.0,        # CPU usage threshold (percentage)
    "ram_threshold": 10.0,        # RAM usage threshold (percentage)
    "check_interval": 0.3,        # Check interval in seconds
    "output_file": "resource_report.json",
    "track_cpu": True,
    "track_ram": True
}

# ============================================================================
# LOAD CONFIGURATION
# ============================================================================
def load_config():
    """Load configuration from config.json or use defaults."""
    config = DEFAULT_CONFIG.copy()
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
                config.update(user_config)
                print(f"[INFO] Configuration loaded from: {config_path}")
        except (json.JSONDecodeError, IOError) as e:
            print(f"[WARN] Failed to load config.json, using defaults: {e}")
    else:
        print(f"[INFO] No config.json found, using default configuration")
    
    return config

# Load config at startup
CONFIG = load_config()

MODE = CONFIG["mode"]
TOP_N = CONFIG["top_n"]
CPU_THRESHOLD = CONFIG["cpu_threshold"]
RAM_THRESHOLD = CONFIG["ram_threshold"]
CHECK_INTERVAL = CONFIG["check_interval"]
OUTPUT_FILE = CONFIG["output_file"]
TRACK_CPU = CONFIG["track_cpu"]
TRACK_RAM = CONFIG["track_ram"]

# ============================================================================
# GLOBAL STATE
# ============================================================================
captured_processes = []
prev_proc_stats = {}        # For CPU calculation: {pid: (utime+stime, timestamp)}
total_cpu_time_prev = 0
prev_timestamp = 0
NUM_CPUS = os.cpu_count() or 1


def read_file_safe(path):
    """Safely read a file, returning None if it fails."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def get_all_pids():
    """Get all PIDs from /proc directory."""
    pids = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pids.append(int(entry))
    except OSError:
        pass
    return pids


def get_process_stat(pid):
    """
    Read /proc/<pid>/stat and parse it.
    Returns dict with: pid, name, state, ppid, utime, stime, starttime
    """
    content = read_file_safe(f'/proc/{pid}/stat')
    if not content:
        return None
    
    try:
        # The comm field (process name) can contain spaces and parentheses
        start = content.find('(')
        end = content.rfind(')')
        
        if start == -1 or end == -1:
            return None
        
        name = content[start+1:end]
        rest = content[end+2:].split()
        
        return {
            'pid': pid,
            'name': name,
            'state': rest[0],
            'ppid': int(rest[1]),
            'utime': int(rest[11]),
            'stime': int(rest[12]),
            'starttime': int(rest[19]),
        }
    except (IndexError, ValueError):
        return None


def get_process_cmdline(pid):
    """Get the command line of a process."""
    content = read_file_safe(f'/proc/{pid}/cmdline')
    if not content:
        return "(Access Denied or Exited)"
    return content.replace('\x00', ' ').strip() or "(No cmdline)"


def get_process_memory(pid):
    """
    Get memory usage from /proc/<pid>/statm.
    Returns (rss_bytes, percent_of_total)
    """
    content = read_file_safe(f'/proc/{pid}/statm')
    if not content:
        return 0, 0.0
    
    try:
        parts = content.split()
        rss_pages = int(parts[1])
        page_size = os.sysconf('SC_PAGE_SIZE')
        rss_bytes = rss_pages * page_size
        
        meminfo = read_file_safe('/proc/meminfo')
        if meminfo:
            for line in meminfo.split('\n'):
                if line.startswith('MemTotal:'):
                    total_kb = int(line.split()[1])
                    total_bytes = total_kb * 1024
                    percent = (rss_bytes / total_bytes) * 100
                    return rss_bytes, percent
        return rss_bytes, 0.0
    except (IndexError, ValueError):
        return 0, 0.0


def get_process_user(pid):
    """Get the username of process owner."""
    try:
        uid = os.stat(f'/proc/{pid}').st_uid
        passwd = read_file_safe('/etc/passwd')
        if passwd:
            for line in passwd.split('\n'):
                parts = line.split(':')
                if len(parts) >= 3 and parts[2].isdigit():
                    if int(parts[2]) == uid:
                        return parts[0]
        return str(uid)
    except (OSError, FileNotFoundError):
        return "Unknown"


def get_systemd_service(pid):
    """Get the systemd service name for a process."""
    content = read_file_safe(f'/proc/{pid}/cgroup')
    if not content:
        return "Unknown"
    
    for line in content.split('\n'):
        if '.service' in line:
            parts = line.strip().split('/')
            for part in reversed(parts):
                if '.service' in part:
                    return part
        
        if 'user.slice' in line or 'session' in line:
            return "User Session Process"
    
    for line in content.split('\n'):
        if '.scope' in line:
            parts = line.strip().split('/')
            for part in reversed(parts):
                if '.scope' in part:
                    return part
    
    return "Unknown/Orphan"


def get_parent_chain(pid, max_depth=10):
    """Get the parent process chain up to init (PID 1) or max_depth."""
    chain = []
    current_pid = pid
    seen = set()
    
    for _ in range(max_depth):
        if current_pid in seen or current_pid <= 0:
            break
        seen.add(current_pid)
        
        stat = get_process_stat(current_pid)
        if not stat:
            break
        
        chain.append((current_pid, stat['name']))
        
        if current_pid == 1 or stat['ppid'] == 0:
            break
        
        current_pid = stat['ppid']
    
    return chain


def get_total_cpu_time():
    """Get total CPU time from /proc/stat."""
    content = read_file_safe('/proc/stat')
    if not content:
        return 0
    
    for line in content.split('\n'):
        if line.startswith('cpu '):
            parts = line.split()
            total = sum(int(x) for x in parts[1:9])
            return total
    return 0


def calculate_cpu_percent(pid, stat, current_time, total_cpu_delta):
    """Calculate CPU percentage for a process."""
    global prev_proc_stats
    
    proc_time = stat['utime'] + stat['stime']
    
    if pid in prev_proc_stats:
        prev_proc_time, prev_time = prev_proc_stats[pid]
        time_delta = current_time - prev_time
        
        if time_delta > 0 and total_cpu_delta > 0:
            proc_delta = proc_time - prev_proc_time
            cpu_percent = (proc_delta / total_cpu_delta) * 100 * NUM_CPUS
            prev_proc_stats[pid] = (proc_time, current_time)
            return cpu_percent
    
    prev_proc_stats[pid] = (proc_time, current_time)
    return 0.0


def format_bytes(bytes_val):
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} TB"


def signal_handler(sig, frame):
    """Handle CTRL+C to save report and exit."""
    print("\n\n[INFO] Monitoring stopped. Preparing report...")
    save_report()
    sys.exit(0)


def save_report():
    """Save collected data to JSON file."""
    if not captured_processes:
        print("[INFO] No high-resource processes detected during monitoring.")
        return
    
    service_summary = defaultdict(lambda: {'count': 0, 'processes': []})
    for proc in captured_processes:
        svc = proc['service']
        service_summary[svc]['count'] += 1
        if len(service_summary[svc]['processes']) < 5:
            service_summary[svc]['processes'].append({
                'name': proc['name'],
                'pid': proc['pid'],
                'cmdline': proc['cmdline'][:100]
            })
    
    report = {
        'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'config': {
            'mode': MODE,
            'top_n': TOP_N if MODE == 'top_n' else None,
            'cpu_threshold': CPU_THRESHOLD if MODE == 'threshold' else None,
            'ram_threshold': RAM_THRESHOLD if MODE == 'threshold' else None,
            'check_interval': CHECK_INTERVAL
        },
        'summary': {
            'total_events': len(captured_processes),
            'by_service': dict(service_summary)
        },
        'events': captured_processes
    }
    
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n{'='*60}")
        print(f"[INFO] Report saved to: {os.path.abspath(OUTPUT_FILE)}")
        print(f"[INFO] Total events captured: {len(captured_processes)}")
        print(f"\n[SUMMARY] Events by Service/Source:")
        print(f"{'-'*60}")
        for svc, data in sorted(service_summary.items(), key=lambda x: -x[1]['count']):
            print(f"  {svc}: {data['count']} events")
    except Exception as e:
        print(f"[ERROR] Error saving report: {e}")


def print_header():
    """Print startup header."""
    print("="*70)
    print("  PROC-MONITOR - Process Resource Monitor")
    print("  https://github.com/cagatayuresin/proc-monitor")
    print("="*70)
    print(f"  Mode          : {MODE.upper()}")
    if MODE == 'threshold':
        print(f"  CPU Threshold : {CPU_THRESHOLD}%")
        print(f"  RAM Threshold : {RAM_THRESHOLD}%")
    else:
        print(f"  Top N         : {TOP_N}")
    print(f"  Check Interval: {CHECK_INTERVAL}s")
    print(f"  CPU Cores     : {NUM_CPUS}")
    print(f"  Tracking      : {'CPU ' if TRACK_CPU else ''}{'RAM' if TRACK_RAM else ''}")
    print(f"  Output File   : {OUTPUT_FILE}")
    print("="*70)
    print("Press CTRL+C to stop and generate report.\n")


def build_process_info(pid, stat, cpu_percent, ram_bytes, ram_percent, triggered_by):
    """Build a log entry for a process."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cmdline = get_process_cmdline(pid)
    user = get_process_user(pid)
    service = get_systemd_service(pid)
    parent_chain = get_parent_chain(pid)
    
    return {
        'timestamp': now,
        'pid': pid,
        'ppid': stat['ppid'],
        'name': stat['name'],
        'cpu_percent': round(cpu_percent, 2),
        'ram_percent': round(ram_percent, 2),
        'ram_bytes': ram_bytes,
        'ram_human': format_bytes(ram_bytes),
        'cmdline': cmdline,
        'user': user,
        'service': service,
        'parent_chain': [{'pid': p, 'name': n} for p, n in parent_chain],
        'triggered_by': triggered_by
    }


def print_process_info(log_entry):
    """Print process info to console."""
    trigger_str = '/'.join(log_entry['triggered_by'])
    parent_chain = log_entry['parent_chain']
    parent_info = ' -> '.join(f"{p['name']}({p['pid']})" for p in parent_chain[:3])
    
    print(f"[{log_entry['timestamp']}] [{trigger_str}] {log_entry['name']} (PID:{log_entry['pid']})")
    print(f"    CPU: {log_entry['cpu_percent']:.1f}% | RAM: {log_entry['ram_percent']:.1f}% ({log_entry['ram_human']})")
    print(f"    Service: {log_entry['service']}")
    print(f"    User: {log_entry['user']}")
    print(f"    Chain: {parent_info}")
    cmdline = log_entry['cmdline']
    print(f"    Cmd: {cmdline[:80]}{'...' if len(cmdline) > 80 else ''}")
    print()


def monitor_threshold(pids, current_time, total_cpu_delta):
    """Monitor using threshold mode - capture all above threshold."""
    for pid in pids:
        stat = get_process_stat(pid)
        if not stat:
            continue
        
        triggered_by = []
        cpu_percent = 0.0
        ram_bytes, ram_percent = 0, 0.0
        
        if TRACK_CPU:
            cpu_percent = calculate_cpu_percent(pid, stat, current_time, total_cpu_delta)
            if cpu_percent > CPU_THRESHOLD:
                triggered_by.append('CPU')
        
        if TRACK_RAM:
            ram_bytes, ram_percent = get_process_memory(pid)
            if ram_percent > RAM_THRESHOLD:
                triggered_by.append('RAM')
        
        if triggered_by:
            # Get memory if not already fetched
            if not TRACK_RAM:
                ram_bytes, ram_percent = get_process_memory(pid)
            # Get CPU if not already fetched
            if not TRACK_CPU:
                cpu_percent = calculate_cpu_percent(pid, stat, current_time, total_cpu_delta)
            
            log_entry = build_process_info(pid, stat, cpu_percent, ram_bytes, ram_percent, triggered_by)
            captured_processes.append(log_entry)
            print_process_info(log_entry)


def monitor_top_n(pids, current_time, total_cpu_delta):
    """Monitor using top_n mode - capture top N processes."""
    process_data = []
    
    for pid in pids:
        stat = get_process_stat(pid)
        if not stat:
            continue
        
        cpu_percent = 0.0
        ram_bytes, ram_percent = 0, 0.0
        
        if TRACK_CPU:
            cpu_percent = calculate_cpu_percent(pid, stat, current_time, total_cpu_delta)
        
        if TRACK_RAM:
            ram_bytes, ram_percent = get_process_memory(pid)
        
        # Skip kernel threads and very low usage processes
        if cpu_percent < 0.1 and ram_percent < 0.1:
            continue
        
        process_data.append({
            'pid': pid,
            'stat': stat,
            'cpu_percent': cpu_percent,
            'ram_bytes': ram_bytes,
            'ram_percent': ram_percent
        })
    
    # Get top N by CPU
    if TRACK_CPU:
        top_cpu = sorted(process_data, key=lambda x: x['cpu_percent'], reverse=True)[:TOP_N]
        for proc in top_cpu:
            if proc['cpu_percent'] > 0.1:  # Only log if meaningful
                log_entry = build_process_info(
                    proc['pid'], proc['stat'], proc['cpu_percent'],
                    proc['ram_bytes'], proc['ram_percent'], ['TOP_CPU']
                )
                captured_processes.append(log_entry)
                print_process_info(log_entry)
    
    # Get top N by RAM
    if TRACK_RAM:
        top_ram = sorted(process_data, key=lambda x: x['ram_percent'], reverse=True)[:TOP_N]
        for proc in top_ram:
            if proc['ram_percent'] > 0.1:  # Only log if meaningful
                # Check if already logged as TOP_CPU
                already_logged = any(
                    p['pid'] == proc['pid'] and 'TOP_CPU' in p['triggered_by']
                    for p in captured_processes[-TOP_N*2:]  # Check recent entries
                )
                if not already_logged:
                    log_entry = build_process_info(
                        proc['pid'], proc['stat'], proc['cpu_percent'],
                        proc['ram_bytes'], proc['ram_percent'], ['TOP_RAM']
                    )
                    captured_processes.append(log_entry)
                    print_process_info(log_entry)


def monitor():
    """Main monitoring loop."""
    global prev_proc_stats, total_cpu_time_prev, prev_timestamp
    
    print_header()
    
    if not os.path.exists('/proc'):
        print("[ERROR] /proc filesystem not found. This script requires Linux.")
        sys.exit(1)
    
    if MODE not in ('threshold', 'top_n'):
        print(f"[ERROR] Invalid mode '{MODE}'. Use 'threshold' or 'top_n'.")
        sys.exit(1)
    
    total_cpu_time_prev = get_total_cpu_time()
    prev_timestamp = time.time()
    
    # Initialize CPU measurements for all processes
    for pid in get_all_pids():
        stat = get_process_stat(pid)
        if stat:
            proc_time = stat['utime'] + stat['stime']
            prev_proc_stats[pid] = (proc_time, prev_timestamp)
    
    print("[INFO] Initialization complete. Monitoring started...\n")
    time.sleep(CHECK_INTERVAL)
    
    while True:
        try:
            current_time = time.time()
            total_cpu_time = get_total_cpu_time()
            total_cpu_delta = total_cpu_time - total_cpu_time_prev
            
            pids = get_all_pids()
            active_pids = set(pids)
            
            if MODE == 'threshold':
                monitor_threshold(pids, current_time, total_cpu_delta)
            else:  # top_n
                monitor_top_n(pids, current_time, total_cpu_delta)
            
            # Cleanup old entries in prev_proc_stats
            dead_pids = set(prev_proc_stats.keys()) - active_pids
            for pid in dead_pids:
                del prev_proc_stats[pid]
            
            total_cpu_time_prev = total_cpu_time
            prev_timestamp = current_time
            
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            time.sleep(CHECK_INTERVAL)


def check_root():
    """Check if running as root and warn if not."""
    if os.geteuid() != 0:
        print("!"*70)
        print("  WARNING: Running without root privileges!")
        print("  Some process information may be inaccessible.")
        print("  For best results, run with: sudo python3 proc_monitor.py")
        print("!"*70)
        print()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    check_root()
    monitor()
