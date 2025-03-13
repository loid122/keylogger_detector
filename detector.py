from scapy.all import sniff, TCP, IP
import socket
import os
import time
import psutil
import re
import winreg
import ctypes

# Constants
alert_threshold = 3  # Number of suspicious traits required to flag a process
known_system_processes = {  # Whitelist of known system  (added only some for reference)
    "svchost.exe", "explorer.exe", "winlogon.exe", "lsass.exe", "csrss.exe",
    "smss.exe", "services.exe", "System", "System Idle Process", "taskhost.exe",
    "dwm.exe", "spoolsv.exe", "msmpeng.exe"  
}
known_keylogging_libraries = {  # Keylogging libraries to detect
    "pynput", "pyinput", "keyboard", "pyhook", "pyxhook", "pywinauto"
}
trusted_ips = {  # Whitelist of trusted IPs (e.g., Google, Microsoft, local network) added some for reference
    "8.8.8.8", "8.8.4.4", "142.250.190.78", "192.168.1.1", "192.168.1.255",
    "127.0.0.1", "172.217.10.46", "104.215.148.63", "13.107.21.200"
}
trusted_domains = {  # Whitelist of trusted domains - added some for reference
    "google.com", "microsoft.com", "windowsupdate.com", "youtube.com", "mozilla.org",
    "github.com", "python.org", "ubuntu.com", "apple.com", "amazon.com"
}

#Initializing 
alert_levels = {}

# Initializing dictionary to track POST requests to unknown IPs
unknown_ip_post_count = {}

# Function to check for long-running non-system processes
def check_long_processes():
    for proc in psutil.process_iter(['pid', 'name', 'create_time']):
        try:
            process_name = proc.info['name']
            if process_name not in known_system_processes:
                runtime = time.time() - proc.info['create_time']
                if runtime > 18000:                                         #if the processes run for more than 5 hours
                    alert_levels[proc.info['pid']] = alert_levels.get(proc.info['pid'], 0) + 1
                    print(f"[Alert] Process {process_name} (PID: {proc.info['pid']}) has been running for {runtime//3600} hours.")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

# Function to resolve domain names using socket library
def resolve_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

# Function to monitor network traffic for suspicious POST requests (if keyloagger is sending data back)
def monitor_network_traffic():
    def packet_callback(packet):
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            if dst_ip not in trusted_ips:                           # Check if the destination IP is in list of Trusted IPs
                domain = resolve_domain(dst_ip)
                if domain and any(trusted_domain in domain for trusted_domain in trusted_domains):
                    return  

                payload = str(packet[TCP].payload)                                  
                if "POST" in payload:                                                     # Check for POST requests
                    unknown_ip_post_count[dst_ip] = unknown_ip_post_count.get(dst_ip, 0) + 1     #incrementing count of POST req sent to same ip 

                    if unknown_ip_post_count[dst_ip] > 10:                              # Alert if it sends more than 10 POST requests to that ip
                        print(f"[Alert] Suspicious POST request to unknown IP: {dst_ip} (Count: {unknown_ip_post_count[dst_ip]})")
                        for conn in psutil.net_connections():
                            if conn.raddr and conn.raddr.ip == dst_ip:
                                pid = conn.pid
                                alert_levels[pid] = alert_levels.get(pid, 0) + 1
                                print(f"Process (PID: {pid}) is sending POST requests to {dst_ip}.")
                                break

    sniff(filter="tcp", prn=packet_callback, timeout=30)

# Function to detect use of keylogging libraries
def detect_known_keylogging_libraries():
    for root, dirs, files in os.walk("C:\\"):
        for file in files:
            if file.endswith(".py"):
                try:
                    with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for lib in known_keylogging_libraries:
                            if re.search(f"import {lib}|from {lib}", content):
                                print(f"[Alert] Suspicious file: {os.path.join(root, file)} uses {lib}")
                                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                                    try:
                                        if proc.info['exe'] and os.path.join(root, file) in proc.info['exe']:
                                            pid = proc.info['pid']
                                            alert_levels[pid] = alert_levels.get(pid, 0) + 1
                                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                                        pass
                except PermissionError:
                    pass

# Function to check for unauthorized startup entries
def check_startup_entries():
    startup_keys = [
        "SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
        "SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce"
    ]

    trusted_startup_apps = {
    "C:\Program Files\Google\Chrome\Application\chrome.exe",
    "C:\Windows\System32\OneDrive.exe"
    }

    for key_path in startup_keys:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, value, _ = winreg.EnumValue(key, i)
                
                if value not in trusted_startup_apps:                                  # Check if the startup entry is not in the whitelist
                    print(f"[ALERT] Unknown startup entry: {name} -> {value}")
                    for proc in psutil.process_iter(['pid', 'name', 'exe']):
                        try:
                            if proc.info['exe'] and value in proc.info['exe']:
                                pid = proc.info['pid']
                                alert_levels[pid] = alert_levels.get(pid, 0) + 1
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
        except FileNotFoundError:
            pass

# Function to monitor for low-level keyboard hooks
def check_keyboard_hooks():
    WH_KEYBOARD_LL = 13             # Constant for low-level keyboard hook
    hook = ctypes.windll.user32.GetAsyncKeyState(WH_KEYBOARD_LL)
    if hook:
        print("[Alert] Low-level keyboard hook detected!")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if "keyboard" in proc.info['name'].lower():
                    pid = proc.info['pid']
                    alert_levels[pid] = alert_levels.get(pid, 0) + 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

# Main function to run all checks
def main():
    print("Starting keylogger detection...")
    check_long_processes()
    monitor_network_traffic()
    detect_known_keylogging_libraries()
    check_startup_entries()
    check_keyboard_hooks()

    # Report processes with high alert levels
    print("\nProcesses with high alert levels:")
    for pid, level in alert_levels.items():
        if level >= alert_threshold:
            try:
                proc = psutil.Process(pid)
                print(f"Process {proc.name()} (PID: {pid}) has an alert level of {level}.")
            except psutil.NoSuchProcess:
                pass

if __name__ == "__main__":
    main()