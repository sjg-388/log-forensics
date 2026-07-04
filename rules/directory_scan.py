from collections import defaultdict
from datetime import timedelta

def detect_directory_scan(events, threshold=20, window_seconds=60):
    findings = []
    
    # 404 이벤트만 필터링
    not_found_events = [
        e for e in events 
        if e.source == "apache" and e.status_code == 404
    ]
    
    # IP별로 이벤트 묶기
    ip_events = defaultdict(list)
    for event in not_found_events:
        ip_events[event.src_ip].append(event)
    
    # IP별로 슬라이딩 윈도우 적용
    for ip, ip_event_list in ip_events.items():
        ip_event_list.sort(key=lambda e: e.timestamp)
        
        for i, event in enumerate(ip_event_list):
            window_end = event.timestamp + timedelta(seconds=window_seconds)
            window_events = [e for e in ip_event_list[i:] if e.timestamp <= window_end]
            
            unique_paths = set(e.path for e in window_events)
            
            if len(window_events) >= threshold and len(unique_paths) >= threshold // 2:
                findings.append({
                    "rule": "directory_scan",
                    "src_ip": ip,
                    "count": len(window_events),
                    "unique_paths": len(unique_paths),
                    "window_seconds": window_seconds,
                    "first_seen": str(event.timestamp),
                    "reason": f"{len(window_events)} requests with {len(unique_paths)} unique paths from {ip} within {window_seconds}s"
                })
                break
    
    return findings