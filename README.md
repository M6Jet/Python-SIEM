🛡️ Python-SIEM

A lightweight, modular, Python-based SIEM for Windows & Linux log monitoring, parsing, and threat detection.






📖 Overview

Python-SIEM is a simple yet functional Security Information & Event Management system designed for learning, home labs, and lightweight monitoring environments.
It collects logs, parses and normalizes them, and runs detection logic to identify suspicious events.

The goal:
✔ Understand how SIEM pipelines work
✔ Build your own collectors → parsers → detectors
✔ Run lightweight monitoring on Windows or Linux hosts

🏗️ Architecture

Below is the general flow of the SIEM:

                 +------------------+
                 |     LOG FILES    |
                 | (Windows/Linux)  |
                 +--------+---------+
                          |
                          v
                +---------------------+
                |      COLLECTOR      |
                | - Reads raw logs    |
                | - Sends data forward|
                +----------+----------+
                           |
                           v
                +----------------------+
                |       PARSER         |
                | - Normalizes logs    |
                | - Extracts fields    |
                +----------+-----------+
                           |
                           v
                +----------------------+
                |      DETECTOR        |
                | - Runs detection     |
                | - Flags anomalies    |
                +----------+-----------+
                           |
                           v
                +----------------------+
                |      ALERTING        |
                | (Console for now)    |
                +----------------------+

📁 Repository Layout
Python-SIEM/
│── SIEM (Windows).py            # Full Windows SIEM pipeline script
│── collector (Linux).py         # Linux log collector
│── parser (Linux).py            # Linux log parser
│── detector (Linux).py          # Linux rule-based detector
│── run (Linux).py               # Main Linux entry point
│── LICENSE                      # MIT License

🚀 Getting Started
1️⃣ Clone the Repository
git clone https://github.com/M6Jet/Python-SIEM.git
cd Python-SIEM

🪟 Running on Windows

The Windows SIEM uses a single script containing:

Log collection

Log normalization

Detection

Alerts

Run it with:

python "SIEM (Windows).py"

🐧 Running on Linux

The Linux SIEM uses a modular pipeline:

Step 1 — Collect Logs
python "collector (Linux).py"

Step 2 — Parse Logs
python "parser (Linux).py"

Step 3 — Run Detection
python "detector (Linux).py"

OR simply run the full automated pipeline:
python "run (Linux).py"

🔍 Sample Detection Output

A typical alert might look like:

[ALERT] Suspicious activity detected!
User: root
Event: Multiple Failed SSH Logins
Source IP: 192.168.1.50
Timestamp: 2025-02-01 13:22:10

🧩 Customizing the SIEM

You can extend or modify:

✔ Log Sources

Add log paths or new collection methods.

✔ Parsers

Support new log formats (JSON logs, web server logs, etc.).

✔ Detection Logic

Add rules like:

Brute force login attempts

Privilege escalation

Unauthorized process creation

File integrity violations

✔ Alerting

Integrate with:

Email

Slack / Discord

Webhooks

Databases

Elasticsearch

📦 Example: Building a Custom Detection Rule

Inside your Linux detector (Linux).py, you could add logic like:

if "Failed password" in log_line:
    failed_attempts[ip] += 1
    if failed_attempts[ip] > 5:
        print("[ALERT] Possible SSH brute force from", ip)

🧠 What This SIEM Is and Is Not
✔ Suitable For:

Learning SIEM components

Cybersecurity practice labs

Home monitoring

Teaching incident detection

✘ Not Designed For:

High-speed enterprise log ingestion

Correlated multi-host analytics

Full SIEM dashboards (Splunk/ELK/Sentinel level)

🗺️ Roadmap / Future Improvements
Feature	Status	Notes
Windows log integration	✔	Already included
Linux modular pipeline	✔	Collector → Parser → Detector
Configurable rule engine	⏳	Planned for next update
Email / webhook alerts	⏳	In development
SQLite / JSON log storage	🔜	Coming soon
Dashboard or Web UI	🚀	Long-term feature
🤝 Contributing

Contributions are welcome!
You can help by:

Improving parsers

Expanding detection rules

Adding alerting modules

Refactoring code into a package

Writing documentation

Submit a pull request or open an issue to start contributing.

📜 License

This project is licensed under the MIT License.
See the LICENSE file for more details.
