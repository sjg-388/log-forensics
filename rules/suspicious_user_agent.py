SUSPICIOUS_UA_KEYWORDS = [
    "sqlmap",
    "nikto",
    "acunetix",
    "nmap",
    "dirbuster",
    "gobuster",
    "python-requests"
]

def detect_suspicious_user_agent(events):
    findings = []

    for event in events:
        if not event.user_agent:
            continue

        ua_lower = event.user_agent.lower()

        for keyword in SUSPICIOUS_UA_KEYWORDS:
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