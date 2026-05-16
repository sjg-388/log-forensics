import re
from datetime import datetime
from models.log_event import LogEvent

# Apache Combined Log Format 정규식
LOG_PATTERN = re.compile(
    r'(?P<src_ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status_code>\d{3}) \S+ '
    r'"[^"]*" '
    r'"(?P<user_agent>[^"]*)"'
)

def parse_line(line: str) -> LogEvent | None:
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    
    timestamp = datetime.strptime(
        match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z"
    )
    
    return LogEvent(
        timestamp=timestamp,
        source="apache",
        src_ip=match.group("src_ip"),
        event_type="web_request",
        method=match.group("method"),
        path=match.group("path"),
        status_code=int(match.group("status_code")),
        user_agent=match.group("user_agent"),
        username=None,
        raw=line.strip()
    )