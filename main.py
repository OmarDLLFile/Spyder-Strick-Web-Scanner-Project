"""Spyder-Strick CLI (thin wrapper over engine.ScanEngine).

Usage:
  python main.py -u http://localhost:8000 --authorize
  python main.py -u https://example.com --authorize --depth 2 --intensity medium
  python main.py --dashboard            # regenerate dashboard from history
  python main.py --serve                # serve reports/ on http://localhost:8080
  python main.py --list-scans
  python main.py -u http://localhost:8000 --sast ./myapp --ai-provider ollama --ai-model llama3.1
Positional URL also works: python main.py http://localhost:8000
"""
from __future__ import annotations
import argparse, http.server, logging, os, sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def build_parser():
    p = argparse.ArgumentParser(prog="spyder-strick",
                                description="Spyder-Strick — AI-powered enterprise security assessment platform")
    p.add_argument("url", nargs="?", help="Target URL (or use -u/--url)")
    p.add_argument("-u", "--url", dest="url_opt", default=None)
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--workers", type=int, default=10)
    p.add_argument("--delay", type=float, default=0.1, help="Min seconds between requests")
    p.add_argument("--max-requests", type=int, default=2000)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--authorize", action="store_true",
                   help="Confirm you are authorised to test this target (required for non-local targets)")
    p.add_argument("--allow", action="append", default=[], help="Extra allowed host (repeatable)")
    p.add_argument("--auth", default="", help="user:pass or 'Bearer <token>'")
    p.add_argument("--cookies", default="", help="Cookie header value, e.g. 'session=abc; x=1'")
    p.add_argument("--openapi", default="", help="OpenAPI/Swagger spec URL or local file")
    p.add_argument("--sast", default="", help="Path to source code for SAST")
    p.add_argument("--ai-provider", default="none", choices=["none", "ollama", "openai"])
    p.add_argument("--ai-model", default="")
    p.add_argument("--ai-base-url", default="")
    p.add_argument("--intensity", default="medium", choices=["low", "medium", "high"])
    p.add_argument("--output-dir", default="reports")
    p.add_argument("--format", default="all", choices=["json", "html", "csv", "all"])
    p.add_argument("--no-verify", action="store_true", help="Disable TLS verification (test targets only)")
    p.add_argument("--config", default="", help="YAML config file")
    p.add_argument("--dashboard", action="store_true", help="Regenerate reports/dashboard.html from history")
    p.add_argument("--serve", action="store_true", help="Serve reports/ via stdlib http.server on :8080")
    p.add_argument("--serve-port", type=int, default=8080)
    p.add_argument("--list-scans", action="store_true", help="List past scans from history DB")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    target = args.url_opt or args.url

    if args.list_scans:
        from core.store import ScanStore
        store = ScanStore(f"{args.output_dir}/spyder.db")
        for s in store.list_scans():
            print(f"#{s['id']} {s['target']} — {s['total_findings']} findings "
                  f"(C:{s['critical']} H:{s['high']} M:{s['medium']} L:{s['low']} I:{s['info']}) @ {s['started_at']}")
        store.close()
        return 0

    if args.dashboard:
        from core.reporter import build_dashboard
        path = build_dashboard(f"{args.output_dir}/spyder.db", f"{args.output_dir}/dashboard.html")
        print(f"[+] Dashboard: {path}")
        return 0

    if args.serve:
        os.chdir(args.output_dir)
        print(f"[+] Serving {os.getcwd()} at http://localhost:{args.serve_port} (Ctrl+C to stop)")
        http.server.ThreadingHTTPServer(("127.0.0.1", args.serve_port),
                                        http.server.SimpleHTTPRequestHandler).serve_forever()
        return 0

    if not target:
        build_parser().print_help()
        print("\nError: a target URL is required (positional or -u/--url).", file=sys.stderr)
        return 2
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    from core.config import ScanConfig
    cfg = ScanConfig.from_yaml(args.config, target_url=target, depth=args.depth, workers=args.workers,
                               delay=args.delay, max_requests=args.max_requests, timeout=args.timeout,
                               verify_tls=not args.no_verify, intensity=args.intensity,
                               authorize=args.authorize, allow_hosts=args.allow,
                               auth=args.auth, cookies=args.cookies, openapi=args.openapi,
                               sast_path=args.sast, ai_provider=args.ai_provider, ai_model=args.ai_model,
                               ai_base_url=args.ai_base_url, output_dir=args.output_dir,
                               formats=["json", "html", "csv"] if args.format == "all" else [args.format])
    from engine.scanner import ScanEngine
    try:
        engine = ScanEngine(cfg)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    engine.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
