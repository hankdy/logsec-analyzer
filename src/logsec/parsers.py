from pathlib import Path 
import re
from datetime import datetime



def parse_nginx_access_line(line: str) -> dict | None:
    pattern = (
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>HTTP/\d\.\d)" '
        r'(?P<status>\d{3}) (?P<size>\d+|-) "[^"]*" "(?P<agent>[^"]*)"' 
    )

    m = re.match(pattern, line)
    if not m:
        return None

    d = m.groupdict()
    d["status"] = int(d["status"])
    d["size"] = 0 if d["size"] == "-" else int(d["size"])
    return d


def parse_auth_failed_line(line: str):
    m = re.search(
        r'^(?P<mon>\w{3})\s+'
        r'(?P<day>\d{1,2})\s+'
        r'(?P<ts>\d{2}:\d{2}:\d{2}).*?'
        r'Failed password for (?:invalid user )?(?P<user>[^\s:]+) from (?P<ip>[^\s]+)',
        line
    )
    if not m:
        return None

    month_map = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    mon = month_map.get(m.group("mon"), 1)
    day = int(m.group("day"))
    t = m.group("ts")  # <- 수정
    now_year = datetime.utcnow().year

    ts = datetime.strptime(f"{now_year}-{mon:02d}-{day:02d} {t}", "%Y-%m-%d %H:%M:%S")

    return {"user": m.group("user"), "ip": m.group("ip"), "ts": ts}
    

def iter_nginx(path: Path): 
    with path.open("r", encoding="utf-8") as f: 
        for line in f: 
            rec = parse_nginx_access_line(line.rstrip("\n")) 
            if rec: 
                yield rec

def iter_auth_failed(path: Path): 
    with path.open("r", encoding="utf-8") as f: 
        for line in f: 
            rec =parse_auth_failed_line(line.rstrip("\n")) 
            if rec: 
                yield rec