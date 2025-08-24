from pathlib import Path 
from collections import Counter 
from .parsers import iter_nginx, iter_auth_failed
from rich.console import Console 
from rich.table import Table 
from rich.panel import Panel 
from rich import box
from collections import Counter, deque 
from datetime import timedelta
from collections import deque 
from typing import List, Dict, Any


console = Console()

def print_nginx_summary(nsum: Dict) -> None: 
    if not nsum: 
        console.print("[yellow]Nginx 요약 데이터가 없습니다.[/]") 
        return
    cg = nsum.get("code_groups", {}) 
    line = (f"[bold]총 요청:[/] {nsum.get('total', 0)} | "
                f"[green]2xx {cg.get('2xx', 0)}[/] / "
                f"[cyan]3xx {cg.get('3xx', 0)}[/] / "
                f"[yellow]4xx {cg.get('4xx', 0)}[/] / "
                f"[red]5xx {cg.get('5xx', 0)}[/]")
    
    console.print(line)
    

# 상태코드 TOP
    t1 = Table(title="상태코드 상위", box=box.SIMPLE_HEAVY)
    t1.add_column("Status", justify="center", style="bold")
    t1.add_column("Count", justify="right")
    for code, cnt in nsum.get("status_top", []):
        color = "green" if 200 <= code < 300 else ("cyan" if 300 <= code < 400 else ("yellow" if 400 <= code < 500 else "red"))
        t1.add_row(f"[{color}]{code}[/{color}]", str(cnt))
    console.print(t1)

        # 경로 TOP
    t2 = Table(title="경로 상위", box=box.SIMPLE_HEAVY)
    t2.add_column("Path", overflow="fold")
    t2.add_column("Count", justify="right")
    for path, cnt in nsum.get("path_top", []):
        t2.add_row(path, str(cnt))
    console.print(t2)

        # 클라이언트 IP TOP
    t3 = Table(title="클라이언트 IP 상위", box=box.SIMPLE_HEAVY)
    t3.add_column("IP")
    t3.add_column("Count", justify="right")
    for ip, cnt in nsum.get("ip_top", []):
        t3.add_row(ip, str(cnt))
    console.print(t3)
       
        # 상태코드 그룹 요약
    t4 = Table(title="상태코드 그룹 요약", box=box.SIMPLE_HEAVY) 
    t4.add_column("Group", justify="center") 
    t4.add_column("Count", justify="right") 
    for g,color in [("2xx", "green"), ("3xx", "cyan"), ("4xx", "yellow"), ("5xx", "red")]: 
        t4.add_row(f"[{color}]{g}[/{color}]", str(cg.get(g, 0))) 
    console.print(t4)

def print_auth_summary(asum: Dict) -> None:
    if not asum: 
        console.print("[yellow]Auth(SSH) 요약 데이터가 없습니다.[/]") 
        return 
    console.print(Panel.fit("Auth(SSH) 실패 로그인 요약", style="bold magenta", box=box.ROUNDED)) 
    console.print(f"[bold]실패 총 횟수:[/] {asum.get('failed_total', 0)}\n")

    t1 = Table(title="실패 IP 상위", box=box.SIMPLE_HEAVY)
    t1.add_column("IP")
    t1.add_column("Count", justify="right")
    for ip, cnt in asum.get("failed_ip_top", []):
        t1.add_row(ip, str(cnt))
    console.print(t1)

    t2 = Table(title="실패 사용자 상위", box=box.SIMPLE_HEAVY)
    t2.add_column("User")
    t2.add_column("Count", justify="right")
    for user, cnt in asum.get("failed_user_top", []):
        t2.add_row(user, str(cnt))
    console.print(t2)
        
    alerts = asum.get("alerts", []) 
    if alerts: 
        t3 = Table(title=f"경고: {asum.get('window_sec',60)}초 내 {asum.get('threshold',5)}회 이상 실패", box=box.SIMPLE_HEAVY) 
        t3.add_column("IP") 
        t3.add_column("최대 시도수", justify="right") 
        for a in alerts: 
            t3.add_row(f"[red]{a['ip']}[/]", f"[red]{a['max_in_window']}[/]") 
        console.print(t3)
    else: 
        console.print("[green]허용 임계치 내에서 정상입니다.[/]")   
    

def summarize_nginx(path: Path) -> Dict: 
    total = 0 
    status_counter = Counter() 
    path_counter = Counter() 
    ip_counter = Counter() 
    code_groups = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    for rec in iter_nginx(path): 
        total += 1 
        status_counter[rec["status"]] += 1 
        path_counter[rec["path"]] += 1 
        ip_counter[rec["ip"]] += 1 
        code = rec["status"] 
        if 200 <= code < 300: code_groups["2xx"] += 1 
        elif 300 <= code < 400: code_groups["3xx"] += 1 
        elif 400 <= code < 500: code_groups["4xx"] += 1 
        elif 500 <= code < 600:
            code_groups["5xx"] += 1
        
    return { "total": total, 
             "status_top": status_counter.most_common(5), 
            "path_top": path_counter.most_common(5),
            "ip_top": ip_counter.most_common(5),
            "code_groups": code_groups,
            }

def summarize_auth(path: Path, window_sec: int = 60, threshold: int = 5) -> Dict:
    total = 0 
    ip_counter = Counter() 
    user_counter = Counter() 
    records = []
    for rec in iter_auth_failed(path): 
        total += 1 
        ip_counter[rec["ip"]] += 1 
        user_counter[rec["user"]] += 1 
        if "ts" in rec:
            records.append(rec) 
    if records:
        alerts = detect_burst_failures(records, window_sec=window_sec, threshold=threshold)
    else:
        alerts = []
    return { "failed_total": total, 
                "failed_ip_top": ip_counter.most_common(5),
                "failed_user_top": user_counter.most_common(5),
                "alerts": alerts,
                "window_sec": window_sec, "threshold": threshold, 
                }

    
    
def detect_burst_failures(records: List[Dict], window_sec: int = 60, threshold: int = 5) -> List[Dict[str,Any]]:
    """
    records: [{"ip": str, "user": str, "ts": datetime}, ...]
    window_sec : 슬라이딩 윈도우(초)
    threshold  : 윈도우 내 실패 횟수 임계치
    """
    if not records:
        return []

    per_ip: Dict[str, List] = {}
    for r in sorted(records, key=lambda x: x["ts"]):
        per_ip.setdefault(r["ip"], []).append(r["ts"])

    alerts: List[Dict[str,Any]] = []
    win = timedelta(seconds=window_sec)

    for ip, times in per_ip.items():
        q = deque()
        max_count = 0
        max_window = (None, None)

        for t in times:
            q.append(t)
            # 윈도우에서 벗어난 시간 제거
            while q and (t - q[0]) > win:
                q.popleft_ts = q.popleft()
            cur_len = len(q)
            if cur_len > max_count:
               max_count = cur_len
               max_window = (q[0], t)

        if max_count >= threshold:
            alerts.append({
            "ip": ip,
            "max_in_window": max_count,
            "start_ts": max_window[0],
            "end_ts": max_window[1],
            "window_sec": window_sec,
            })

    return alerts


# 예시 실패 확인 로그 코드
# Aug 16 10:00:15 host sshd[1234]: Failed password for root from 203.0.113.10 port 525 ssh2

# 실행 코드
# python -m src.logsec.main --fail-window-sec 60 --fail-threshold 3