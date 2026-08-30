# 포렌식 분석 리포트

**분석 대상:** zanbil_access.log
**분석 일시:** 2026-08-30 23:48:38
**총 파싱 이벤트:** 5000개

---

## Executive Summary

| 항목 | 수치 |
|---|---|
| 총 탐지 이벤트 | 5건 |
| 의심 IP | 4개 |
| 의심 URL | 4개 |
| 의심 User-Agent | 0개 |

---

## 탐지 결과 요약

| 룰 | 탐지 건수 |
|---|---|
| Suspicious User-Agent | 0건 |
| Brute-force | 0건 |
| Directory Scanning | 1건 |
| SQL Injection | 4건 |

---

## 공격 타임라인



### [2019-01-22 03:58:28+03:30]
- **IP:** 31.56.96.51
- **룰:** sql_injection
- **상세:** SQL Injection 시도 의심 패턴 탐지 (쿼리스트링): select
- **경로:** /image/28821?name=silver-select....-.jpg&wh=max


### [2019-01-22 03:58:36+03:30]
- **IP:** 31.56.96.51
- **룰:** sql_injection
- **상세:** SQL Injection 시도 의심 패턴 탐지 (쿼리스트링): select
- **경로:** /image/28821?name=-gold-select...-.jpg&wh=max


### [2019-01-22 03:59:50+03:30]
- **IP:** 207.46.13.136
- **룰:** sql_injection
- **상세:** SQL Injection 시도 의심 패턴 탐지 (쿼리스트링): --
- **경로:** /image/32150?name=rf-840n--e2-11.jpg&wh=max


### [2019-01-22 04:09:26+03:30]
- **IP:** 5.123.209.223
- **룰:** sql_injection
- **상세:** SQL Injection 시도 의심 패턴 탐지 (쿼리스트링): --
- **경로:** /image/8243?name=fc---19dd4sa.jpg&wh=200x200


### [2019-01-22 04:09:40+03:30]
- **IP:** 31.184.130.52
- **룰:** directory_scan
- **상세:** 24 requests with 24 unique paths from 31.184.130.52 within 60s





---

## IOC 목록

### 의심 IP


- 207.46.13.136

- 31.184.130.52

- 31.56.96.51

- 5.123.209.223



### 의심 URL


- /image/28821?name=-gold-select...-.jpg&wh=max

- /image/28821?name=silver-select....-.jpg&wh=max

- /image/32150?name=rf-840n--e2-11.jpg&wh=max

- /image/8243?name=fc---19dd4sa.jpg&wh=200x200



### 의심 User-Agent

없음


### 의심 계정

없음
