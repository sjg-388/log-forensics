from dataclasses import dataclass
from datetime import datetime

@dataclass
class LogEvent:
    timestamp: datetime
    source: str          # "apache" 또는 "auth"
    src_ip: str | None
    event_type: str      # "web_request", "ssh_failed_login" 등
    method: str | None   # GET, POST 등
    path: str | None     # /admin, /.env 등
    status_code: int | None
    user_agent: str | None
    username: str | None # auth.log용
    raw: str             # 원본 로그 한 줄