def extract_ioc(all_findings, events=None):
    suspicious_ips = set()
    suspicious_urls = set()
    suspicious_user_agents = set()
    suspicious_accounts = set()

    for finding in all_findings:
        if finding.get("src_ip"):
            suspicious_ips.add(finding["src_ip"])

        if finding.get("path"):
            suspicious_urls.add(finding["path"])

        if finding.get("user_agent"):
            suspicious_user_agents.add(finding["user_agent"])

        if finding.get("username"):
            suspicious_accounts.add(finding["username"])

    # auth 이벤트에서 직접 username 추출
    if events:
        for event in events:
            if event.source == "auth" and event.username:
                suspicious_accounts.add(event.username)

    return {
        "suspicious_ips": sorted(list(suspicious_ips)),
        "suspicious_urls": sorted(list(suspicious_urls)),
        "suspicious_user_agents": sorted(list(suspicious_user_agents)),
        "suspicious_accounts": sorted(list(suspicious_accounts)),
    }