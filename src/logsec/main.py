import argparse 
from pathlib import Path 
from rich import print 
from .report import summarize_nginx, summarize_auth
from .report import print_nginx_summary, print_auth_summary

def main(): 
    ap = argparse.ArgumentParser(description="보안 로그 분석기(nginx/auth)")
    ap.add_argument("--fail-window-sec", type=int, default=60, help="SSH 실패 탐지 시간창(초)") 
    ap.add_argument("--fail-threshold", type=int, default=5, help="시간창 내 실패 임계치")
    ap.add_argument("--nginx", type=Path, default=Path("sample_logs/nginx_access.log")) 
    ap.add_argument("--auth", type=Path, default=Path("sample_logs/auth.log")) 
    args = ap.parse_args()

    if args.nginx.exists():
        nsum = summarize_nginx(args.nginx)
        print_nginx_summary(nsum)
        
    else:
        print(f"[yellow]nginx 로그 없음:[/] {args.nginx}")

    if args.auth.exists():
        asum = summarize_auth(args.auth, window_sec=args.fail_window_sec, threshold=args.fail_threshold)
        print_auth_summary(asum)
        
    else:
        print(f"[yellow]auth 로그 없음:[/] {args.auth}")
        
if __name__ == "__main__":
    main()