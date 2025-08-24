from pathlib import Path 
import re
from datetime import datetime

from pathlib import Path
import re
from datetime import datetime, timedelta
from typing import Optional, Dict

# 2025-08-24 수정버젼 
# --- Precompiled regex ---
NGINX_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/\d(?:\.\d)?)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)\s+"[^"]*"\s+"(?P<agent>[^"]*)"$'
)

AUTH_FAILED_RE = re.compile(
    r'^(?P<mon>[A-Z][a-z]{2})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<ts>\d{2}:\d{2}:\d{2}).*?'
    r'Failed password for (?:invalid user )?(?P<user>[^\s:]+)\s+from\s+(?P<ip>\S+)'
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


def parse_nginx_access_line(line: str) -> dict | None:
    m = NGINX_ACCESS_RE.fullmatch(line)
    if not m:
        return None
    d = m.groupdict()
    d["status"] = int(d["status"])
    d["size"] = 0 if d["size"] == "-" else int(d["size"])
    # d["time"]는 문자열 그대로 유지 (원하면 별도 파서에서 datetime 변환)
    return d


def parse_auth_failed_line(line: str) -> dict | None:
    m = AUTH_FAILED_RE.search(line)
    if not m:
        return None

    mon = MONTH_MAP.get(m.group("mon"))
    if not mon:
        return None

    day = int(m.group("day"))
    ts_str = m.group("ts")

    # 로컬 시간 기준으로 연도 추정 + 연말/연초 보정
    now = datetime.now()
    ts_dt = datetime.strptime(f"{now.year}-{mon:02d}-{day:02d} {ts_str}", "%Y-%m-%d %H:%M:%S")
    # 미래로 1일 이상 벌어지면 전년도 로그로 보정
    if ts_dt - now > timedelta(days=1):
        ts_dt = ts_dt.replace(year=now.year - 1)

    return {"user": m.group("user"), "ip": m.group("ip"), "ts": ts_dt}


def iter_nginx(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_nginx_access_line(line.rstrip("\n"))
            if rec:
                yield rec


def iter_auth_failed(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_auth_failed_line(line.rstrip("\n"))
            if rec:
                yield rec


# <기존 버젼>
# def parse_nginx_access_line(line: str) -> dict | None:
#     pattern = (
#         r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
#         r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>HTTP/\d\.\d)" '
#         r'(?P<status>\d{3}) (?P<size>\d+|-) "[^"]*" "(?P<agent>[^"]*)"' 
#     )

#     m = re.match(pattern, line)
#     if not m:
#         return None

#     d = m.groupdict()
#     d["status"] = int(d["status"])
#     d["size"] = 0 if d["size"] == "-" else int(d["size"])
#     return d


# def parse_auth_failed_line(line: str):
#     m = re.search(
#         r'^(?P<mon>\w{3})\s+'
#         r'(?P<day>\d{1,2})\s+'
#         r'(?P<ts>\d{2}:\d{2}:\d{2}).*?'
#         r'Failed password for (?:invalid user )?(?P<user>[^\s:]+) from (?P<ip>[^\s]+)',
#         line
#     )
#     if not m:
#         return None
        
#     month_map = {
#         "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
#         "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
#     }

#     mon = month_map.get(m.group("mon"), 1)
#     day = int(m.group("day"))
#     ts_str = m.group("ts")  # <- 수정
#     now_year = datetime.utcnow().year

#     ts_dt = datetime.strptime(f"{now_year}-{mon:02d}-{day:02d} {ts_str}", "%Y-%m-%d %H:%M:%S")

#     return {"user": m.group("user"), "ip": m.group("ip"), "ts": ts_dt}


# def iter_nginx(path: Path): 
#     with path.open("r", encoding="utf-8") as f: 
#         for line in f: 
#             rec = parse_nginx_access_line(line.rstrip("\n")) 
#             if rec: 
#                 yield rec

# def iter_auth_failed(path: Path): 
#     with path.open("r", encoding="utf-8") as f: 
#         for line in f: 
#             rec =parse_auth_failed_line(line.rstrip("\n")) 
#             if rec: 
#                 yield rec