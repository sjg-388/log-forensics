# log-forensics

공개 보안 로그 기반 공격 행위 탐지 및 IOC 추출 자동화 시스템

공개적으로 수집 가능한 웹 서버 로그와 인증 로그를 입력으로 받아, 공격자의 행위를 시간 순서대로 재구성하고 의심 IOC(침해 지표)를 자동 추출하는 Python 기반 경량 포렌식 분석 도구다.

---

## 주요 기능

- Apache Combined Log / Linux auth.log 파싱
- 4가지 공격 패턴 탐지 (YAML 설정 기반)
  - Suspicious User-Agent
  - Brute-force (SSH 로그인 실패 반복)
  - Directory scanning (짧은 시간 내 다양한 경로 404)
  - SQL Injection 시도 (쿼리스트링 패턴)
- IOC 자동 추출 (의심 IP / URL / User-Agent / 계정)
- 공격 타임라인 자동 생성
- Markdown / HTML 포렌식 리포트 자동 생성
- JSON 결과 파일 저장

---

## 프로젝트 구조

    log-forensics/
    ├── main.py                  # 실행 진입점
    ├── ioc_extractor.py         # IOC 추출 엔진
    ├── timeline_reconstructor.py # 타임라인 생성
    ├── report_generator.py      # 리포트 생성
    ├── rules.yaml               # 탐지 룰 설정
    ├── log_parser/
    │   ├── apache_parser.py     # Apache Combined Log 파서
    │   └── auth_parser.py       # Linux auth.log 파서
    ├── models/
    │   └── log_event.py         # 공통 이벤트 모델
    ├── rules/
    │   ├── suspicious_user_agent.py
    │   ├── brute_force.py
    │   ├── directory_scan.py
    │   └── sql_injection.py
    ├── templates/
    │   ├── report.md.j2         # Markdown 리포트 템플릿
    │   └── report.html.j2       # HTML 리포트 템플릿
    ├── tests/
    │   └── test_parsers.py      # 단위 테스트
    └── sample_logs/
        ├── apache_logs.txt      # Apache 샘플 로그
        ├── Linux_2k.log         # Linux 시스템 로그
        └── attack_sample.log    # 공격 패턴 테스트 로그

---

## 설치 방법

Python 3.11 이상이 필요하다.

    pip install pyyaml jinja2

---

## 실행 방법

    python main.py <로그 파일 경로>

예시:

    python main.py sample_logs/apache_logs.txt
    python main.py sample_logs/Linux_2k.log
    python main.py sample_logs/attack_sample.log

---

## 출력 파일

로그 파일명을 기반으로 아래 파일이 자동 생성된다.

| 파일 | 설명 |
|---|---|
| *_ioc.json | IOC 추출 결과 (JSON) |
| *_timeline.json | 공격 타임라인 (JSON) |
| *_report.md | 포렌식 리포트 (Markdown) |
| *_report.html | 포렌식 리포트 (HTML) |

---

## 탐지 룰 설정

`rules.yaml` 파일에서 탐지 기준을 조정할 수 있다.

    brute_force:
      threshold: 10        # 실패 횟수 임계값
      window_seconds: 300  # 시간 창 (초)

    directory_scan:
      threshold: 20        # 404 횟수 임계값
      window_seconds: 60   # 시간 창 (초)

    suspicious_user_agent:
      keywords:
        - sqlmap
        - nikto
        - gobuster

    sql_injection:
      patterns:
        - union
        - select
        - "'"
        - "--"

---

## 단위 테스트 실행

    python tests/test_parsers.py

---

## 분석 대상 로그 형식

**Apache Combined Log**

    192.168.1.1 - - [10/May/2015:01:12:01 +0000] "GET /admin HTTP/1.1" 404 512 "-" "Mozilla/5.0"

**Linux auth.log**

    Jun 14 15:16:01 combo sshd[19939]: Failed password for root from 218.188.2.4 port 22 ssh2