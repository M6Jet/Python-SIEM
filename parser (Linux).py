print(
    """
  __  __   __       _      _   
 |  \/  | / /      | |    | |  
 | \  / |/ /_      | | ___| |_ 
 | |\/| | '_ \ _   | |/ _ \ __|
 | |  | | (_) | |__| |  __/ |_ 
 |_|  |_|\___/ \____/ \___|\__|
    Python SIEM PARSER CODE
    """
)




import re

def parse_line(line):
    pattern = r'(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s(?P<host>\S+)\s(?P<service>\w+):\s+(?P<user>\w+)\s:\s(?P<message>.+)'
    match = re.match(pattern, line)

    if not match:
        return None

    log = match.groupdict()

    if "incorrect password" in log["message"].lower():
        log["action"] = "Incorrect password"
    else:
        log["action"] = "Other"

    fields = log["message"].split(";")
    for field in fields:
        if "USER=" in field:
            log["target_user"] = field.split("=")[1].strip()
        elif "COMMAND=" in field:
            log["command"] = field.split("=")[1].strip()

    return log