import yaml
import os

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules.yaml")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def detect_suspicious_user_agent(events):
    config = load_config()
    keywords = config["suspicious_user_agent"]["keywords"]
    
    findings = []
    for event in events:
        if not event.user_agent:
            continue
        ua_lower = event.user_agent.lower()
        for keyword in keywords:
            if keyword in ua_lower:
                findings.append({
                    "rule": "suspicious_user_agent",
                    "src_ip": event.src_ip,
                    "path": event.path,
                    "user_agent": event.user_agent,
                    "reason": f"User-Agent contains suspicious keyword: {keyword}",
                    "timestamp": str(event.timestamp),
                })
                break
    return findings