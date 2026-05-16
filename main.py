import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_parser.apache_parser import parse_line
from rules.suspicious_user_agent import detect_suspicious_user_agent

def main(log_file):
    events = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            event = parse_line(line.strip())
            if event:
                events.append(event)

    print(f"Parsed {len(events)} events")

    findings = detect_suspicious_user_agent(events)
    print(f"Detected {len(findings)} suspicious user-agent events")

    for f in findings:
        print(json.dumps(f, default=str, indent=2))

if __name__ == "__main__":
    main(sys.argv[1])