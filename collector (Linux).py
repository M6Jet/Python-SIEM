print(
    """
  __  __   __       _      _   
 |  \/  | / /      | |    | |  
 | \  / |/ /_      | | ___| |_ 
 | |\/| | '_ \ _   | |/ _ \ __|
 | |  | | (_) | |__| |  __/ |_ 
 |_|  |_|\___/ \____/ \___|\__|
    Python SIEM COLLECTOR CODE
    """
)




def collect_logs(log_file_path):
    with open(log_file_path, 'r') as file:
        lines = file.readlines()
    return lines
if __name__ == "__main__":
    logs = collect_logs("/var/log/auth.log")
    print(f"[+] Collected {len(logs)} log lines")