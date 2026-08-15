# 포렌식 분석 리포트

**분석 대상:** attack_sample.log
**분석 일시:** 2026-08-16 05:09:11
**총 파싱 이벤트:** 23개

---

## Executive Summary

| 항목 | 수치 |
|---|---|
| 총 탐지 이벤트 | 3건 |
| 의심 IP | 2개 |
| 의심 URL | 1개 |
| 의심 User-Agent | 1개 |

---

## 탐지 결과 요약

| 룰 | 탐지 건수 |
|---|---|
| Suspicious User-Agent | 1건 |
| Brute-force | 0건 |
| Directory Scanning | 1건 |
| SQL Injection | 1건 |

---

## 공격 타임라인



### [2015-05-10 01:12:01+00:00]
- **IP:** 192.168.1.100
- **룰:** directory_scan
- **상세:** 21 requests with 21 unique paths from 192.168.1.100 within 60s



### [2015-05-10 01:13:01+00:00]
- **IP:** 10.0.0.5
- **룰:** suspicious_user_agent
- **상세:** User-Agent contains suspicious keyword: sqlmap
- **경로:** /login?user=admin'--&pass=x


### [2015-05-10 01:13:01+00:00]
- **IP:** 10.0.0.5
- **룰:** sql_injection
- **상세:** SQL Injection 시도 의심 패턴 탐지 (쿼리스트링): '
- **경로:** /login?user=admin'--&pass=x




---

## IOC 목록

### 의심 IP


- 10.0.0.5

- 192.168.1.100



### 의심 URL


- /login?user=admin'--&pass=x



### 의심 User-Agent


- sqlmap/1.7



### 의심 계정

없음
