print(
    """
  __  __   __       _      _   
 |  \/  | / /      | |    | |  
 | \  / |/ /_      | | ___| |_ 
 | |\/| | '_ \ _   | |/ _ \ __|
 | |  | | (_) | |__| |  __/ |_ 
 |_|  |_|\___/ \____/ \___|\__|
    Python SIEM RUN CODE
    """
)

import sys
from collector import collect_logs
from parser import parse_line
from collections import defaultdict
from detector import save_alerts_to_file, detect_failed_logins, detect_sensitive_commands
import json

log_file_path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/auth.log"
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

def summarize_alerts(alerts):
  summary = defaultdict(lambda: defaultdict(int))
  total_alerts = len(alerts)

  for alert in alerts:
    alert_type = alert.get("type", "Unknown")
    user = alert.get("user", "Unknown")
    summary[alert_type][user] += 1
  print(f"[+] Total alerts: {total_alerts}")
  for alert_type, users in summary.items():
     print(f"  - {alert_type}:")
     for user, count in users.items():
       print(f"     - User '{user}': {count} alert(s)")

summarize_alerts(alerts)