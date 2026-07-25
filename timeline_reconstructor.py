def build_timeline(all_findings):
    """
    모든 탐지 결과를 시간순으로 정렬해서 타임라인을 만든다.
    """
    # timestamp 기준으로 정렬
    sorted_findings = sorted(
        all_findings,
        key=lambda x: x.get("timestamp", "") or x.get("first_seen", "")
    )

    timeline = []
    for finding in sorted_findings:
        rule = finding.get("rule", "unknown")
        src_ip = finding.get("src_ip", "unknown")
        timestamp = finding.get("timestamp") or finding.get("first_seen", "unknown")
        reason = finding.get("reason", "")
        path = finding.get("path", "")

        entry = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "rule": rule,
            "detail": reason,
        }

        if path:
            entry["path"] = path

        timeline.append(entry)

    return timeline


def print_timeline(timeline):
    print("\n" + "="*60)
    print("[공격 타임라인]")
    print("="*60)

    if not timeline:
        print("탐지된 이벤트 없음")
        return

    for entry in timeline:
        print(f"\n[{entry['timestamp']}]")
        print(f"  IP     : {entry['src_ip']}")
        print(f"  룰     : {entry['rule']}")
        print(f"  상세   : {entry['detail']}")
        if entry.get("path"):
            print(f"  경로   : {entry['path']}")