from datetime import datetime

def build_cases(all_findings, events):
    """
    동일 src_ip의 의심 이벤트를 하나의 Case로 묶는다.
    """
    cases = {}

    for finding in all_findings:
        ip = finding.get("src_ip")
        if not ip:
            continue

        if ip not in cases:
            cases[ip] = {
                "src_ip": ip,
                "first_seen": None,
                "last_seen": None,
                "findings": [],
                "related_iocs": set(),
                "evidence": []
            }

        case = cases[ip]
        case["findings"].append(finding)

        # 타임스탬프 추적
        ts_str = finding.get("timestamp") or finding.get("first_seen")
        if ts_str:
            try:
                ts_raw = str(ts_str).replace("+0000", "+00:00")
                ts = datetime.fromisoformat(ts_raw)
                # timezone 정보 제거해서 naive로 통일
                ts = ts.replace(tzinfo=None)
            except Exception:
                ts = None

            if ts:
                if case["first_seen"] is None or ts < case["first_seen"]:
                    case["first_seen"] = ts
                if case["last_seen"] is None or ts > case["last_seen"]:
                    case["last_seen"] = ts

        # IOC 수집
        if finding.get("path"):
            case["related_iocs"].add(finding["path"])
        if finding.get("user_agent"):
            case["related_iocs"].add(finding["user_agent"])

    # 원본 로그 증거 연결
    for event in events:
        ip = event.src_ip
        if ip and ip in cases:
            if event.raw not in cases[ip]["evidence"]:
                cases[ip]["evidence"].append(event.raw)

    # set → list 변환
    for case in cases.values():
        case["related_iocs"] = sorted(list(case["related_iocs"]))
        case["first_seen"] = str(case["first_seen"]) if case["first_seen"] else None
        case["last_seen"] = str(case["last_seen"]) if case["last_seen"] else None

    return list(cases.values())


def print_cases(cases):
    print("\n" + "="*60)
    print("[Case 분석 결과]")
    print("="*60)

    if not cases:
        print("분석된 Case 없음")
        return

    for i, case in enumerate(cases, 1):
        print(f"\n--- Case #{i} ---")
        print(f"  IP         : {case['src_ip']}")
        print(f"  First seen : {case['first_seen']}")
        print(f"  Last seen  : {case['last_seen']}")
        print(f"  탐지 이벤트: {len(case['findings'])}건")

        for f in case["findings"]:
            print(f"    [{f.get('timestamp') or f.get('first_seen')}] {f['rule']} — {f['reason']}")

        if case["related_iocs"]:
            print(f"  관련 IOC   :")
            for ioc in case["related_iocs"]:
                print(f"    - {ioc}")

        print(f"  원본 증거  : {len(case['evidence'])}건")
        if case["evidence"]:
            print(f"    {case['evidence'][0]}")
            if len(case["evidence"]) > 1:
                print(f"    ... 외 {len(case['evidence'])-1}건")