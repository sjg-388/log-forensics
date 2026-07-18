from collections import defaultdict

def extract_ioc(all_findings):
    """
    탐지 결과 리스트를 받아서 IOC를 추출한다.
    all_findings: 모든 룰의 탐지 결과를 합친 리스트
    """
    suspicious_ips = set()
    suspicious_urls = set()
    suspicious_user_agents = set()
    suspicious_accounts = set()

    for finding in all_findings:
        rule = finding.get("rule")

        # IP 추출 (모든 룰 공통)
        if finding.get("src_ip"):
            suspicious_ips.add(finding["src_ip"])

        # URL 추출 (Apache 관련 룰)
        if finding.get("path"):
            suspicious_urls.add(finding["path"])

        # User-Agent 추출
        if finding.get("user_agent"):
            suspicious_user_agents.add(finding["user_agent"])

        # 계정명 추출 (Brute-force)
        if finding.get("username"):
            suspicious_accounts.add(finding["username"])

    return {
        "suspicious_ips": sorted(list(suspicious_ips)),
        "suspicious_urls": sorted(list(suspicious_urls)),
        "suspicious_user_agents": sorted(list(suspicious_user_agents)),
        "suspicious_accounts": sorted(list(suspicious_accounts)),
    }