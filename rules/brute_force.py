import yaml
import os
from collections import defaultdict
from datetime import timedelta

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules.yaml")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def detect_brute_force(events):
    config = load_config()
    threshold = config["brute_force"]["threshold"]
    window_seconds = config["brute_force"]["window_seconds"]
    
    findings = []
    
    failed_logins = [e for e in events if e.event_type == "ssh_failed_login" and e.src_ip is not None]
    
    ip_events = defaultdict(list)
    for event in failed_logins:
        ip_events[event.src_ip].append(event)
    
    for ip, ip_event_list in ip_events.items():
        ip_event_list.sort(key=lambda e: e.timestamp)
        
        for i, event in enumerate(ip_event_list):
            window_end = event.timestamp + timedelta(seconds=window_seconds)
            count = sum(1 for e in ip_event_list[i:] if e.timestamp <= window_end)
            
            if count >= threshold:
                findings.append({
                    "rule": "brute_force",
                    "src_ip": ip,
                    "count": count,
                    "window_seconds": window_seconds,
                    "first_seen": str(event.timestamp),
                    "reason": f"{count} failed logins from {ip} within {window_seconds}s"
                })
                break
    
    return findings