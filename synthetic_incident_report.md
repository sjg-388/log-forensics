# 포렌식 분석 리포트

**분석 대상:** synthetic_incident.log
**분석 일시:** 2026-09-21 00:59:51
**총 파싱 이벤트:** 35개

---

## Executive Summary

| 항목 | 수치 |
|---|---|
| 총 탐지 이벤트 | 7건 |
| 의심 IP | 1개 |
| 의심 URL | 3개 |
| 의심 User-Agent | 1개 |

---

## 탐지 결과 요약

| 룰 | 탐지 건수 |
|---|---|
| Suspicious User-Agent | 3건 |
| Brute-force | 1건 |
| Directory Scanning | 1건 |
| SQL Injection | 2건 |

---

## 공격 타임라인



### [2015-05-10 09:00:01+00:00]
- **IP:** 10.0.0.23
- **룰:** directory_scan
- **상세:** 21 requests with 21 unique paths from 10.0.0.23 within 60s



### [2015-05-10 09:03:00+00:00]
- **IP:** 10.0.0.23
- **룰:** suspicious_user_agent
- **상세:** User-Agent contains suspicious keyword: sqlmap
- **경로:** /search?q=%27%20OR%201%3D1


### [2015-05-10 09:03:00+00:00]
- **IP:** 10.0.0.23
- **룰:** sql_injection
- **상세:** SQL Injection 시도 의심 패턴 탐지 (쿼리스트링): '
- **경로:** /search?q=%27%20OR%201%3D1


### [2015-05-10 09:03:01+00:00]
- **IP:** 10.0.0.23
- **룰:** suspicious_user_agent
- **상세:** User-Agent contains suspicious keyword: sqlmap
- **경로:** /product?id=1%20UNION%20SELECT%20username%20FROM%20users


### [2015-05-10 09:03:01+00:00]
- **IP:** 10.0.0.23
- **룰:** sql_injection
- **상세:** SQL Injection 시도 의심 패턴 탐지 (쿼리스트링): union
- **경로:** /product?id=1%20UNION%20SELECT%20username%20FROM%20users


### [2015-05-10 09:05:00+00:00]
- **IP:** 10.0.0.23
- **룰:** suspicious_user_agent
- **상세:** User-Agent contains suspicious keyword: sqlmap
- **경로:** /login


### [2015-05-10 09:08:00]
- **IP:** 10.0.0.23
- **룰:** brute_force
- **상세:** 11 failed logins from 10.0.0.23 within 300s





---

## IOC 목록

### 의심 IP


- 10.0.0.23



### 의심 URL


- /login

- /product?id=1%20UNION%20SELECT%20username%20FROM%20users

- /search?q=%27%20OR%201%3D1



### 의심 User-Agent


- sqlmap/1.7



### 의심 계정


- admin

- guest

- root

- ubuntu

