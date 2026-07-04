import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_parser.apache_parser import parse_line
from log_parser.auth_parser import parse_auth_line

# ===== Apache 파서 테스트 =====

def test_apache_normal():
    line = '83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /index.html HTTP/1.1" 200 203023 "-" "Mozilla/5.0"'
    result = parse_line(line)
    assert result is not None
    assert result.src_ip == "83.149.9.216"
    assert result.method == "GET"
    assert result.path == "/index.html"
    assert result.status_code == 200
    assert result.source == "apache"
    print("test_apache_normal PASSED")

def test_apache_404():
    line = '192.168.1.1 - - [17/May/2015:10:05:03 +0000] "GET /admin HTTP/1.1" 404 512 "-" "Mozilla/5.0"'
    result = parse_line(line)
    assert result is not None
    assert result.status_code == 404
    assert result.path == "/admin"
    print("test_apache_404 PASSED")

def test_apache_invalid():
    line = "이건 아파치 로그가 아닙니다"
    result = parse_line(line)
    assert result is None
    print("test_apache_invalid PASSED")

def test_apache_user_agent():
    line = '10.0.0.1 - - [17/May/2015:10:05:03 +0000] "GET /search HTTP/1.1" 200 1024 "-" "sqlmap/1.7"'
    result = parse_line(line)
    assert result is not None
    assert result.user_agent == "sqlmap/1.7"
    print("test_apache_user_agent PASSED")

def test_apache_post():
    line = '10.0.0.1 - - [17/May/2015:10:05:03 +0000] "POST /login HTTP/1.1" 302 256 "-" "Mozilla/5.0"'
    result = parse_line(line)
    assert result is not None
    assert result.method == "POST"
    assert result.path == "/login"
    print("test_apache_post PASSED")

# ===== auth 파서 테스트 =====

def test_auth_failed_login():
    line = 'Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4'
    result = parse_auth_line(line)
    assert result is not None
    assert result.event_type == "ssh_failed_login"
    assert result.src_ip == "218.188.2.4"
    assert result.source == "auth"
    print("test_auth_failed_login PASSED")

def test_auth_invalid():
    line = "이건 auth 로그가 아닙니다"
    result = parse_auth_line(line)
    assert result is None
    print("test_auth_invalid PASSED")

if __name__ == "__main__":
    test_apache_normal()
    test_apache_404()
    test_apache_invalid()
    test_apache_user_agent()
    test_apache_post()
    test_auth_failed_login()
    test_auth_invalid()
    print("\n모든 테스트 통과")