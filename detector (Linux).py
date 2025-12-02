print(
    """
  __  __   __       _      _   
 |  \/  | / /      | |    | |  
 | \  / |/ /_      | | ___| |_ 
 | |\/| | '_ \ _   | |/ _ \ __|
 | |  | | (_) | |__| |  __/ |_ 
 |_|  |_|\___/ \____/ \___|\__|
    Python SIEM DETECTOR CODE
    """
)




import json
from collections import defaultdict
from datetime import datetime, timedelta

ALLOWED_USERS = ["Lebron", "root"]

def load_logs(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def detect_failed_logins(logs, threshold=2, window_minutes=10):
    alerts = []
    failed_by_user = defaultdict(list)

    for log in logs:
        if log.get("action") == "Incorrect password":
            user = log.get("user", "unknown")
            timestamp = datetime.fromisoformat(log["timestamp"])
            failed_by_user[user].append(timestamp)

    for user, times in failed_by_user.items():
        times.sort()
        for i in range(len(times)):
            window = times[i:i+threshold]
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
                    "user": log.get("user"),
                    "command": cmd,
                    "timestamp": log.get("timestamp"),
                    "matched_keyword": keyword
                })
                break

    return alerts

if __name__ == "__main__":
    logs = load_logs("logs.json")

    brute_alerts = detect_failed_logins(logs, threshold=2, window_minutes=10)
    cmd_alerts = detect_sensitive_commands(logs)

    all_alerts = brute_alerts + cmd_alerts

    print(f"[+] Found {len(all_alerts)} alerts.")
    for alert in all_alerts:
        print(json.dumps(alert, indent=2))

def save_alerts_to_file(alerts, filename="alerts.json"):
    with open(filename, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"[+] Saved {len(alerts)} alerts to {filename}")