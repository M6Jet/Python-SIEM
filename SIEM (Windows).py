import os
import sys
import re
import json
from collections import defaultdict
from datetime import datetime, timedelta


# ============================================================
#   ASCII Banner
# ============================================================
print(
    """
  __  __   __       _      _   
 |  \/  | / /      | |    | |  
 | \  / |/ /_      | | ___| |_ 
 | |\/| | '_ \ _   | |/ _ \ __|
 | |  | | (_) | |__| |  __/ |_ 
 |_|  |_|\___/ \____/ \___|\__|
    Python SIEM Setup
    """
)


# ============================================================
#   WINDOWS LOG FILE SUPPORT
# ============================================================

# Default Windows log path
WINDOWS_LOG_PATH = r"C:\Users\Mason\PycharmProjects\SIEM\logs\auth.log"

def ensure_log_file(path):
    """Ensure log folder and file exist on Windows."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)

    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("=== Log file created ===\n")


def collect_logs(log_file_path):
    """Read the log file safely."""
    try:
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"[!] Log file not found: {log_file_path}")
        return []


# ============================================================
#   PARSER
# ============================================================
def parse_line(line):
    pattern = (
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s'
        r'(?P<host>\S+)\s(?P<service>\w+):\s+(?P<user>\w+)\s:\s(?P<message>.+)'
    )
    match = re.match(pattern, line)
    if not match:
        return None

    log = match.groupdict()

    # Normalize failed password messages
    if "incorrect password" in log["message"].lower():
        log["action"] = "Incorrect Password"
    else:
        log["action"] = "Other"

    # Extra field extraction
    fields = log["message"].split(";")
    for field in fields:
        if "USER=" in field:
            log["target_user"] = field.split("=")[1].strip()
        elif "COMMAND=" in field:
            log["command"] = field.split("=")[1].strip()

    return log


# ============================================================
#   DETECTION ENGINE
# ============================================================
ALLOWED_USERS = ["Lebron", "root"]


def detect_failed_logins(logs, threshold=2, window_minutes=10):
    alerts = []
    failed_by_user = defaultdict(list)

    # Group failed logins by user
    for log in logs:
        if log.get("action") == "Incorrect Password":
            user = log.get("user", "unknown")
            timestamp = datetime.fromisoformat(log["timestamp"])
            failed_by_user[user].append(timestamp)

    # Detect brute force
    for user, times in failed_by_user.items():
        times.sort()

        for i in range(len(times)):
            window = times[i:i + threshold]
            if len(window) == threshold and (window[-1] - window[0]) <= timedelta(minutes=window_minutes):
                alerts.append({
                    "type": "Brute Force Alert",
                    "user": user,
                    "count": threshold,
                    "timeframe": f"{window_minutes} mins",
                    "first_attempt": window[0].isoformat(),
                    "last_attempt": window[-1].isoformat()
                })

    return alerts


def detect_sensitive_commands(logs, keywords=None):
    if keywords is None:
        keywords = ["shutdown", "reboot", "su", "rm", "adduser", "usermod", "passwd"]

    alerts = []

    for log in logs:
        user = log.get("user", "")
        if user in ALLOWED_USERS:
            continue

        cmd = log.get("command", "").lower()

        for keyword in keywords:
            if keyword in cmd:
                alerts.append({
                    "type": "Sensitive Command Alert",
                    "user": user,
                    "command": cmd,
                    "keyword": keyword,
                    "timestamp": log.get("timestamp")
                })
                break

    return alerts


def save_alerts_to_file(alerts, filename="alerts.json"):
    with open(filename, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"[+] Saved {len(alerts)} alerts to {filename}")


# ============================================================
#   MAIN WORKFLOW
# ============================================================
log_file_path = sys.argv[1] if len(sys.argv) > 1 else WINDOWS_LOG_PATH

ensure_log_file(log_file_path)

print(f"[+] Reading log file: {log_file_path}")

raw_logs = collect_logs(log_file_path)
parsed_logs = []

for line in raw_logs:
    parsed = parse_line(line)
    if parsed:
        parsed_logs.append(parsed)

with open("logs.json", "w") as outfile:
    json.dump(parsed_logs, outfile, indent=2)

print(f"[+] Parsed and saved {len(parsed_logs)} logs to logs.json")

alerts = []
alerts.extend(detect_failed_logins(parsed_logs))
alerts.extend(detect_sensitive_commands(parsed_logs))

save_alerts_to_file(alerts)


# ============================================================
#   SUMMARY OUTPUT
# ============================================================
def summarize_alerts(alerts):
    summary = defaultdict(lambda: defaultdict(int))
    total_alerts = len(alerts)

    print(f"[+] Total alerts: {total_alerts}")

    for alert in alerts:
        alert_type = alert.get("type", "Unknown")
        user = alert.get("user", "Unknown")
        summary[alert_type][user] += 1

    for alert_type, users in summary.items():
        print(f"  - {alert_type}:")
        for user, count in users.items():
            print(f"     - User '{user}': {count} alert(s)")


summarize_alerts(alerts)