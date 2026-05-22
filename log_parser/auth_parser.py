import re
from datetime import datetime
from models.log_event import LogEvent

LOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+\S+:'
    r'\s+(?P<message>.+?)(?:\s+rhost=(?P<src_ip>\S+))?$'
)

def parse_auth_line(line: str) -> LogEvent | None:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    message = match.group("message")

    if "authentication failure" in message or "Failed password" in message:
        event_type = "ssh_failed_login"
    elif "Accepted password" in message or "session opened" in message:
        event_type = "ssh_success_login"
    else:
        return None

    time_str = f"2005 {match.group('month')} {match.group('day')} {match.group('time')}"
    try:
        timestamp = datetime.strptime(time_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    return LogEvent(
        timestamp=timestamp,
        source="auth",
        src_ip=match.group("src_ip"),
        event_type=event_type,
        method=None,
        path=None,
        status_code=None,
        user_agent=None,
        username=None,
        raw=line.strip()
    )