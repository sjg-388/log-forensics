import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_parser.apache_parser import parse_line as parse_apache
from log_parser.auth_parser import parse_auth_line as parse_auth
from rules.suspicious_user_agent import detect_suspicious_user_agent
from rules.brute_force import detect_brute_force
from rules.directory_scan import detect_directory_scan
from rules.sql_injection import detect_sql_injection

def load_logs(log_file):
    events = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = parse_apache(line)
            if not event:
                event = parse_auth(line)
            if event:
                events.append(event)
    return events

def main(log_file):
    events = load_logs(log_file)
    print(f"Parsed {len(events)} events")

    apache_events = [e for e in events if e.source == "apache"]
    auth_events = [e for e in events if e.source == "auth"]
    print(f"  Apache: {len(apache_events)}, Auth: {len(auth_events)}")

    print("\n[Suspicious User-Agent]")
    ua_findings = detect_suspicious_user_agent(events)
    print(f"Detected {len(ua_findings)} events")
    for f in ua_findings:
        print(json.dumps(f, default=str, indent=2))

    print("\n[Brute-force]")
    bf_findings = detect_brute_force(events)
    print(f"Detected {len(bf_findings)} events")
    for f in bf_findings:
        print(json.dumps(f, default=str, indent=2))

    print("\n[Directory Scanning]")
    ds_findings = detect_directory_scan(events)
    print(f"Detected {len(ds_findings)} events")
    for f in ds_findings:
        print(json.dumps(f, default=str, indent=2))

    print("\n[SQL Injection]")
    sqli_findings = detect_sql_injection(events)
    print(f"Detected {len(sqli_findings)} events")
    for f in sqli_findings:
        print(json.dumps(f, default=str, indent=2))

if __name__ == "__main__":
    main(sys.argv[1])