import yaml
import os
from urllib.parse import urlparse, parse_qs, unquote

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules.yaml")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def detect_sql_injection(events):
    config = load_config()
    patterns = config["sql_injection"]["patterns"]
    
    findings = []
    
    for event in events:
        if event.source != "apache" or not event.path:
            continue
        
        # 쿼리스트링 부분만 추출 (? 이후)
        parsed = urlparse(event.path)
        query = unquote(parsed.query).lower()
        
        # 쿼리스트링 없으면 건너뜀
        if not query:
            continue
        
        for pattern in patterns:
            if pattern.lower() in query:
                findings.append({
                    "rule": "sql_injection",
                    "src_ip": event.src_ip,
                    "path": event.path,
                    "query": parsed.query,
                    "method": event.method,
                    "pattern": pattern,
                    "timestamp": str(event.timestamp),
                    "reason": f"SQL Injection 시도 의심 패턴 탐지 (쿼리스트링): {pattern}"
                })
                break
    
    return findings