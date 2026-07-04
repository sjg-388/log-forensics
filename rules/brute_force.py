from collections import defaultdict
from datetime import timedelta

def detect_brute_force(events, threshold=10, window_seconds=300):
    findings = []
    
    # ssh_failed_login 이벤트만 필터링
    failed_logins = [e for e in events if e.event_type == "ssh_failed_login"]
    
    # IP별로 이벤트 묶기
    ip_events = defaultdict(list)
    for event in failed_logins:
        ip_events[event.src_ip].append(event)
    
    # IP별로 슬라이딩 윈도우 적용
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