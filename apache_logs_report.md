# 포렌식 분석 리포트

**분석 대상:** apache_logs.txt
**분석 일시:** 2026-08-02 04:01:37
**총 파싱 이벤트:** 9999개

---

## Executive Summary

| 항목 | 수치 |
|---|---|
| 총 탐지 이벤트 | 1건 |
| 의심 IP | 1개 |
| 의심 URL | 1개 |
| 의심 User-Agent | 1개 |

---

## 탐지 결과 요약

| 룰 | 탐지 건수 |
|---|---|
| Suspicious User-Agent | 1건 |
| Brute-force | 0건 |
| Directory Scanning | 0건 |
| SQL Injection | 0건 |

---

## 공격 타임라인



### [2015-05-20 06:05:14+00:00]
- **IP:** 162.213.42.132
- **룰:** suspicious_user_agent
- **상세:** User-Agent contains suspicious keyword: python-requests
- **경로:** /robots.txt




---

## IOC 목록

### 의심 IP


- 162.213.42.132



### 의심 URL


- /robots.txt



### 의심 User-Agent


- python-requests/1.2.0 CPython/2.7.4 Linux/3.8.0-33-generic



### 의심 계정

없음
