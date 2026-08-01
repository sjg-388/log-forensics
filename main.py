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
from ioc_extractor import extract_ioc
from timeline_reconstructor import build_timeline, print_timeline
from report_generator import generate_markdown_report

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

def save_results(log_file, ioc, timeline):
    base = os.path.splitext(os.path.basename(log_file))[0]
    
    ioc_path = f"{base}_ioc.json"
    with open(ioc_path, "w", encoding="utf-8") as f:
        json.dump(ioc, f, ensure_ascii=False, indent=2)
    print(f"IOC 저장 완료: {ioc_path}")
    
    timeline_path = f"{base}_timeline.json"
    with open(timeline_path, "w", encoding="utf-8") as f:
        json.dump(timeline, f, ensure_ascii=False, indent=2)
    print(f"타임라인 저장 완료: {timeline_path}")

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

    all_findings = ua_findings + bf_findings + ds_findings + sqli_findings
    ioc = extract_ioc(all_findings)

    print("\n" + "="*50)
    print("[IOC 추출 결과]")
    print("="*50)
    print(json.dumps(ioc, default=str, indent=2))

    timeline = build_timeline(all_findings)
    print_timeline(timeline)

    save_results(log_file, ioc, timeline)

    print("\n[리포트 생성]")
    generate_markdown_report(
        log_file, len(events), all_findings, ioc, timeline,
        ua_findings, bf_findings, ds_findings, sqli_findings
    )

if __name__ == "__main__":
    main(sys.argv[1])