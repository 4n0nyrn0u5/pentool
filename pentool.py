#!/usr/bin/env python3
"""
PenTool v2.0 — Professional Web Pentest & OSINT Framework
Author  : Red Team Project
License : MIT (faqat ruxsat berilgan targetlarda)
"""

import argparse
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.banner   import show_banner
from modules.osint    import OSINTScanner
from modules.scanner  import WebScanner
from modules.report   import ReportGenerator
from modules.logger   import log


def build_parser():
    parser = argparse.ArgumentParser(
        description="PenTool v2.0 — Red Team Web & OSINT Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Misol: python3 pentool.py full -d example.com -o report\n"
               "       python3 pentool.py scan -u https://example.com --all --crawl"
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── OSINT ─────────────────────────────────────────────────────
    op = sub.add_parser("osint", help="Passive & Active Recon / OSINT")
    op.add_argument("-d", "--domain",    required=True,  help="Target domen (example.com)")
    op.add_argument("--subdomains",      action="store_true", help="Subdomain brute-force + CT log")
    op.add_argument("--ports",           action="store_true", help="Port skan + banner grabbing")
    op.add_argument("--emails",          action="store_true", help="Email harvest")
    op.add_argument("--tech",            action="store_true", help="Texnologiya fingerprint")
    op.add_argument("--all",             action="store_true", help="Barcha OSINT modullari")
    op.add_argument("--wordlist",        default=None,        help="Subdomain wordlist")
    op.add_argument("-o", "--output",    default=None,        help="JSON natija fayli")
    op.add_argument("--threads",         type=int, default=50,  help="Thread soni (default: 50)")
    op.add_argument("--timeout",         type=int, default=5,   help="Timeout (s, default: 5)")
    op.add_argument("--rate-limit",      type=float, default=0, help="Request orasidagi kutish (s)")

    # ── WEB SCAN ──────────────────────────────────────────────────
    sp = sub.add_parser("scan", help="Web zaiflik skanerlash")
    sp.add_argument("-u", "--url",       required=True,  help="Target URL")
    sp.add_argument("--sqli",            action="store_true", help="SQL Injection")
    sp.add_argument("--xss",             action="store_true", help="XSS (Reflected + DOM hints)")
    sp.add_argument("--lfi",             action="store_true", help="LFI / Path Traversal")
    sp.add_argument("--ssrf",            action="store_true", help="SSRF tekshirish")
    sp.add_argument("--ssti",            action="store_true", help="Server-Side Template Injection")
    sp.add_argument("--headers",         action="store_true", help="Security Headers audit")
    sp.add_argument("--idor",            action="store_true", help="IDOR (kontekstli)")
    sp.add_argument("--redirect",        action="store_true", help="Open Redirect")
    sp.add_argument("--cors",            action="store_true", help="CORS Misconfiguration")
    sp.add_argument("--all",             action="store_true", help="Barcha modullar")
    sp.add_argument("--crawl",           action="store_true", help="Saytni crawl qilish")
    sp.add_argument("--depth",           type=int, default=3,  help="Crawl chuqurligi (default: 3)")
    sp.add_argument("--threads",         type=int, default=10, help="Thread soni (default: 10)")
    sp.add_argument("--timeout",         type=int, default=10, help="Timeout (s)")
    sp.add_argument("--rate-limit",      type=float, default=0, help="Request orasidagi kutish (s)")
    sp.add_argument("--cookie",          default=None,  help="Cookie (session=abc123)")
    sp.add_argument("--header",          action="append", default=[], help="Custom header")
    sp.add_argument("--proxy",           default=None,  help="HTTP proxy (http://127.0.0.1:8080)")
    sp.add_argument("-o", "--output",    default=None,  help="JSON natija fayli")

    # ── FULL COMBO ────────────────────────────────────────────────
    fp = sub.add_parser("full", help="OSINT + Web Scan + Hisobot (to'liq)")
    fp.add_argument("-d", "--domain",    required=True,  help="Target domen")
    fp.add_argument("--threads",         type=int, default=30, help="Thread soni")
    fp.add_argument("--timeout",         type=int, default=8,  help="Timeout (s)")
    fp.add_argument("--rate-limit",      type=float, default=0, help="Request delay (s)")
    fp.add_argument("--cookie",          default=None)
    fp.add_argument("--header",          action="append", default=[])
    fp.add_argument("--proxy",           default=None)
    fp.add_argument("--depth",           type=int, default=2)
    fp.add_argument("-o", "--output",    default="pentest_report", help="Hisobot nomi")
    fp.add_argument("--client",          default="N/A",       help="Mijoz nomi")
    fp.add_argument("--tester",          default="Pentester",  help="Pentester ismi")

    # ── REPORT ────────────────────────────────────────────────────
    rp = sub.add_parser("report", help="JSON natijadan hisobot yaratish")
    rp.add_argument("-i", "--input",     required=True)
    rp.add_argument("-o", "--output",    default="pentest_report")
    rp.add_argument("--format",          choices=["html", "txt", "both"], default="both")
    rp.add_argument("--client",          default="N/A")
    rp.add_argument("--tester",          default="Pentester")

    return parser


def run_full(args):
    from rich.console import Console
    console = Console()
    console.print("\n[bold cyan][ FULL MODE ][/bold cyan] OSINT + Web Scan + Hisobot\n")

    # OSINT
    class OsintArgs:
        domain    = args.domain
        subdomains= True
        ports     = True
        emails    = True
        tech      = True
        all       = True
        wordlist  = None
        threads   = args.threads
        timeout   = args.timeout
        output    = None
        rate_limit= getattr(args, "rate_limit", 0)

    osint_results = OSINTScanner(OsintArgs()).run()

    # Web scan
    target_url = f"https://{args.domain}"
    class ScanArgs:
        url       = target_url
        sqli      = True
        xss       = True
        lfi       = True
        ssrf      = True
        ssti      = True
        headers   = True
        idor      = True
        redirect  = True
        cors      = True
        all       = True
        crawl     = True
        depth     = getattr(args, "depth", 2)
        threads   = args.threads
        timeout   = args.timeout
        rate_limit= getattr(args, "rate_limit", 0)
        cookie    = args.cookie
        header    = args.header
        proxy     = getattr(args, "proxy", None)
        output    = None

    scan_results = WebScanner(ScanArgs()).run()

    combined = {
        "target"  : args.domain,
        "osint"   : osint_results,
        "scan"    : scan_results,
    }

    # Natija JSON
    json_file = args.output + "_raw.json"
    with open(json_file, "w") as f:
        json.dump(combined, f, indent=2, default=str)
    log.success(f"Raw JSON: {json_file}")

    # Hisobot
    rgen = ReportGenerator()
    rgen.generate(combined, args.output, fmt="both",
                  client=getattr(args, "client", "N/A"),
                  tester=getattr(args, "tester", "Pentester"))


def main():
    show_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "osint":
        scanner = OSINTScanner(args)
        results = scanner.run()
        if args.output:
            scanner.save_results(results, args.output)

    elif args.command == "scan":
        scanner = WebScanner(args)
        results = scanner.run()
        if args.output:
            scanner.save_results(results, args.output)

    elif args.command == "full":
        run_full(args)

    elif args.command == "report":
        with open(args.input) as f:
            data = json.load(f)
        ReportGenerator().generate(data, args.output,
                                   fmt=args.format,
                                   client=args.client,
                                   tester=args.tester)


if __name__ == "__main__":
    main()
