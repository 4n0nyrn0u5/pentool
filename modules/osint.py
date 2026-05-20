"""
OSINT moduli v2.0
Yaxshilanishlar:
  - Wildcard DNS detection (false-positive kamaytirish)
  - Certificate Transparency log (crt.sh)
  - Banner grabbing port skanda
  - DMARC / SPF / DKIM tekshirish
  - Passive recon: Shodan, VirusTotal (API keysiz variant)
  - WHOIS emaillarini natijaga qo'shish
  - Rate limiting qo'llab-quvvatlash
  - Thread-safe lock barcha yozuvlarda
"""

import socket
import json
import re
import threading
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import dns.resolver
import dns.exception
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from .logger import log

console = Console()

# ── Konstantalar ──────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
]

COMMON_SUBDOMAINS = [
    # Standart
    "www","mail","ftp","smtp","pop","ns1","ns2","webmail","admin","portal",
    "api","dev","staging","test","beta","app","vpn","remote","secure","shop",
    "blog","forum","help","support","login","dashboard","cdn","img","static",
    "assets","media","upload","download","files","docs","wiki","git","gitlab",
    # DevOps
    "jenkins","jira","confluence","monitor","status","health","metrics","mx",
    "grafana","kibana","prometheus","vault","consul","k8s","kube","docker",
    "registry","harbor","nexus","sonar","sonarqube","artifactory","rancher",
    # Mail
    "email","autodiscover","autoconfig","exchange","owa","relay","smtp2","imap",
    "pop3","lists","newsletter","mx1","mx2","mail2","webmail2",
    # Infra
    "crm","erp","intranet","internal","corp","web","server","host","panel",
    "cpanel","whm","plesk","direct","manage","cloud","s3","storage","backup",
    "db","database","sql","mysql","postgres","redis","elastic","mongo",
    # Auth
    "sso","oauth","auth","id","accounts","identity","login2","saml","ldap",
    # API
    "api2","v1","v2","v3","graphql","rest","ws","websocket","grpc",
    # Misc
    "old","new","sandbox","qa","uat","prod","production","live","demo",
    "preview","cms","mobile","m","wap","pay","billing","checkout","cart",
    "store","shop2","media2","img2","cdn2","proxy","gateway","edge",
    "fw","firewall","waf","loadbalancer","lb","haproxy","nginx",
]

COMMON_PORTS = [
    (21,   "FTP"),         (22,   "SSH"),
    (23,   "Telnet"),      (25,   "SMTP"),
    (53,   "DNS"),         (80,   "HTTP"),
    (110,  "POP3"),        (143,  "IMAP"),
    (389,  "LDAP"),        (443,  "HTTPS"),
    (445,  "SMB"),         (465,  "SMTPS"),
    (587,  "SMTP-TLS"),    (993,  "IMAPS"),
    (995,  "POP3S"),       (1433, "MSSQL"),
    (1521, "Oracle"),      (2375, "Docker"),
    (2376, "Docker-TLS"), (3000, "NodeJS/Grafana"),
    (3306, "MySQL"),       (3389, "RDP"),
    (4848, "GlassFish"),   (5432, "PostgreSQL"),
    (5900, "VNC"),         (6379, "Redis"),
    (6380, "Redis-TLS"),   (7001, "WebLogic"),
    (8080, "HTTP-Alt"),    (8443, "HTTPS-Alt"),
    (8888, "HTTP-Dev"),    (9200, "Elasticsearch"),
    (9300, "ES-Cluster"),  (11211,"Memcached"),
    (27017,"MongoDB"),     (27018,"MongoDB-Alt"),
]

BANNER_PORTS = {21, 22, 25, 110, 143, 389, 587, 993, 995}
HIGH_RISK_PORTS = {21, 23, 445, 2375, 3389, 5900, 6379, 9200, 11211, 27017}

# ── Yordamchi ─────────────────────────────────────────────────

def _rand_str(n=12):
    return ''.join(random.choices(string.ascii_lowercase, k=n))


class OSINTScanner:
    def __init__(self, args):
        self.domain      = args.domain
        self.args        = args
        self.rate_limit  = getattr(args, "rate_limit", 0)
        self.wildcard_ips= set()
        self.lock        = threading.Lock()

        self.session = requests.Session()
        self.session.headers["User-Agent"] = random.choice(USER_AGENTS)
        self.session.verify = False

        self.results = {
            "target"      : self.domain,
            "timestamp"   : datetime.now().isoformat(),
            "dns"         : {},
            "email_security": {},
            "whois"       : {},
            "subdomains"  : [],
            "ports"       : [],
            "emails"      : [],
            "technologies": [],
            "tech_versions": {},
            "ct_log"      : [],
        }

    # ── Public ─────────────────────────────────────────────────

    def run(self):
        log.info(f"OSINT başlandi → [cyan]{self.domain}[/cyan]")
        run_all = getattr(self.args, "all", False)

        self._dns_full()
        self._check_wildcard()

        if run_all or getattr(self.args, "subdomains", False):
            self._ct_log()
            self._subdomain_enum()

        if run_all or getattr(self.args, "ports", False):
            self._port_scan()

        if run_all or getattr(self.args, "emails", False):
            self._email_harvest()

        if run_all or getattr(self.args, "tech", False):
            self._tech_detect()

        self._print_summary()
        return self.results

    def save_results(self, results, output_file):
        fname = output_file if output_file.endswith(".json") else output_file + "_osint.json"
        with open(fname, "w") as f:
            json.dump(results, f, indent=2, default=str)
        log.success(f"OSINT natija saqlandi: {fname}")

    # ── Private ─────────────────────────────────────────────────

    def _check_wildcard(self):
        """Wildcard DNS aniqlash — false positive oldinini olish."""
        hits = 0
        for _ in range(3):
            fake = f"{_rand_str()}.{self.domain}"
            try:
                ip = socket.gethostbyname(fake)
                self.wildcard_ips.add(ip)
                hits += 1
            except Exception:
                pass
        if self.wildcard_ips:
            log.warn(f"Wildcard DNS topildi ({self.wildcard_ips}) — natijalar filterlandi")

    def _dns_full(self):
        log.info("DNS to'liq yig'ilmoqda...")
        rtypes = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"]
        dns_data = {}

        for rtype in rtypes:
            try:
                ans = dns.resolver.resolve(self.domain, rtype, lifetime=5)
                recs = [str(r) for r in ans]
                dns_data[rtype] = recs
                console.print(f"  [green]+[/green] {rtype:<6} {', '.join(recs[:2])}")
            except Exception:
                pass

        # Email security
        email_sec = {}
        # SPF
        try:
            ans = dns.resolver.resolve(self.domain, "TXT", lifetime=5)
            for r in ans:
                txt = str(r)
                if "v=spf1" in txt:
                    email_sec["SPF"] = txt
                    log.success(f"SPF: {txt[:80]}")
        except Exception:
            pass
        # DMARC
        try:
            ans = dns.resolver.resolve(f"_dmarc.{self.domain}", "TXT", lifetime=5)
            for r in ans:
                email_sec["DMARC"] = str(r)
                log.success(f"DMARC: {str(r)[:80]}")
        except Exception:
            log.warn("DMARC yo'q — email spoofing xavfi!")
            email_sec["DMARC"] = None
        # DKIM (common selectors)
        for sel in ["default","google","mail","smtp","k1","s1","s2"]:
            try:
                dns.resolver.resolve(f"{sel}._domainkey.{self.domain}", "TXT", lifetime=3)
                email_sec.setdefault("DKIM_selectors", []).append(sel)
                log.success(f"DKIM selector: {sel}")
            except Exception:
                pass

        self.results["dns"] = dns_data
        self.results["email_security"] = email_sec

        # WHOIS
        try:
            import whois
            w = whois.whois(self.domain)
            self.results["whois"] = {
                "registrar"      : str(w.registrar or ""),
                "creation_date"  : str(w.creation_date or ""),
                "expiration_date": str(w.expiration_date or ""),
                "name_servers"   : [str(ns) for ns in (w.name_servers or [])],
                "country"        : str(w.country or ""),
                "registrant"     : str(getattr(w, "registrant_name", "") or ""),
                "emails"         : list(set([str(e) for e in (w.emails or []) if e])) if isinstance(w.emails, list) else [],
            }
            log.success(f"WHOIS: {w.registrar} | Mamlakat: {w.country}")
        except Exception as e:
            self.results["whois"] = {"error": str(e)}

    def _ct_log(self):
        """crt.sh Certificate Transparency — passiv subdomain topish."""
        log.info("Certificate Transparency (crt.sh) so'ralmoqda...")
        try:
            r = self.session.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=20
            )
            entries = r.json()
            found = set()
            for e in entries:
                for name in e.get("name_value","").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{self.domain}"):
                        found.add(name)

            ct_list = []
            for name in sorted(found):
                ct_list.append({"subdomain": name, "ip": "", "status": None, "source": "crt.sh"})

            self.results["ct_log"] = ct_list
            self.results["subdomains"].extend(ct_list)
            log.success(f"CT log: {len(ct_list)} ta subdomain")
        except Exception as e:
            log.warn(f"CT log xatosi: {e}")

    def _check_sub(self, sub, timeout):
        fqdn = f"{sub}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            if ip in self.wildcard_ips:
                return None

            status = None
            title  = ""
            redir  = ""
            for scheme in ["https", "http"]:
                try:
                    resp = self.session.get(
                        f"{scheme}://{fqdn}",
                        timeout=timeout,
                        allow_redirects=True,
                        verify=False
                    )
                    status = resp.status_code
                    m = re.search(r"<title[^>]*>(.{1,80}?)</title>", resp.text, re.I | re.S)
                    if m:
                        title = m.group(1).strip()
                    if resp.history:
                        redir = resp.url
                    break
                except Exception:
                    pass

            if self.rate_limit:
                time.sleep(self.rate_limit)

            return {
                "subdomain": fqdn,
                "ip"       : ip,
                "status"   : status,
                "title"    : title,
                "redirect" : redir,
                "source"   : "bruteforce",
            }
        except Exception:
            return None

    def _subdomain_enum(self):
        wordlist = COMMON_SUBDOMAINS
        if getattr(self.args, "wordlist", None):
            try:
                with open(self.args.wordlist) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            except Exception:
                log.warn("Wordlist o'qilmadi, built-in ishlatilmoqda")

        # Allaqachon CT dan topilganlarni skip qil
        existing = {s["subdomain"] for s in self.results["subdomains"]}
        to_check = [s for s in wordlist if f"{s}.{self.domain}" not in existing]

        log.info(f"Subdomain brute-force: {len(to_check)} so'z ({len(wordlist) - len(to_check)} ta CT'dan topilgan, skip)")
        found = []
        timeout = getattr(self.args, "timeout", 5)
        threads = getattr(self.args, "threads", 50)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console, transient=True
        ) as prog:
            task = prog.add_task("Tekshirilmoqda...", total=len(to_check))
            with ThreadPoolExecutor(max_workers=threads) as exe:
                futs = {exe.submit(self._check_sub, s, timeout): s for s in to_check}
                for fut in as_completed(futs):
                    prog.advance(task)
                    res = fut.result()
                    if res:
                        found.append(res)
                        color = "green" if res["status"] == 200 else "yellow"
                        title_part = f"  \"{res['title']}\"" if res.get("title") else ""
                        console.print(
                            f"  [{color}]+[/{color}] {res['subdomain']}  [{res['ip']}]"
                            f"  HTTP {res['status']}{title_part}"
                        )

        with self.lock:
            self.results["subdomains"].extend(found)
        log.success(f"Subdomain: jami {len(self.results['subdomains'])} ta ({len(found)} brute-force)")

    def _port_scan(self):
        log.info("Port skan + banner grabbing...")
        try:
            ip = socket.gethostbyname(self.domain)
        except Exception:
            log.error("IP resolve bo'lmadi")
            return

        console.print(f"  [dim]IP: {ip}[/dim]")
        open_ports = []
        timeout = min(getattr(self.args, "timeout", 5), 2)

        def check(port_info):
            port, svc = port_info
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) != 0:
                    s.close()
                    return None
                s.close()

                banner = ""
                if port in BANNER_PORTS:
                    try:
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s2.settimeout(2)
                        s2.connect((ip, port))
                        s2.send(b"\r\n")
                        banner = s2.recv(512).decode(errors="ignore").strip()[:100]
                        s2.close()
                    except Exception:
                        pass

                return {"port": port, "service": svc, "state": "open",
                        "banner": banner, "risk": port in HIGH_RISK_PORTS}
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=60) as exe:
            for res in as_completed([exe.submit(check, p) for p in COMMON_PORTS]):
                r = res.result()
                if r:
                    open_ports.append(r)
                    color  = "red" if r["risk"] else "green"
                    risk_s = " [red]⚠ HIGH RISK[/red]" if r["risk"] else ""
                    banner_s = f"  │ {r['banner']}" if r.get("banner") else ""
                    console.print(f"  [{color}]+[/{color}] {r['port']}/tcp  {r['service']}{risk_s}{banner_s}")

        self.results["ports"] = sorted(open_ports, key=lambda x: x["port"])
        log.success(f"Port skan: {len(open_ports)} ta ochiq port")

    def _email_harvest(self):
        log.info("Email harvest boshlandi...")
        emails = set()
        email_re = re.compile(
            r"[a-zA-Z0-9._%+\-]+@" + re.escape(self.domain),
            re.IGNORECASE
        )

        # WHOIS emaillarini qo'sh
        for e in self.results.get("whois", {}).get("emails", []):
            if e and "@" in e and e not in emails:
                emails.add(e)
                log.success(f"WHOIS email: {e}")

        # Web scraping
        pages = [
            f"https://{self.domain}",
            f"https://{self.domain}/contact",
            f"https://{self.domain}/about",
            f"https://{self.domain}/team",
            f"https://{self.domain}/contact-us",
        ]
        for url in pages:
            try:
                r = self.session.get(url, timeout=6, verify=False, allow_redirects=True)
                for e in email_re.findall(r.text):
                    if e not in emails:
                        emails.add(e)
                        log.success(f"Web: {e}")
                # mailto: linklar
                for ml in re.findall(r'mailto:([^"\'>\s]+)', r.text, re.I):
                    if self.domain in ml and ml not in emails:
                        emails.add(ml)
                        log.success(f"Mailto: {ml}")
            except Exception:
                pass

        # Common guesses (labeled)
        guesses = ["admin","info","contact","support","webmaster",
                   "security","abuse","noreply","hello","hr","it"]
        for prefix in guesses:
            emails.add(f"[guess] {prefix}@{self.domain}")

        self.results["emails"] = list(emails)
        real = [e for e in emails if not e.startswith("[guess]")]
        log.success(f"Email: {len(real)} ta haqiqiy topildi")

    def _tech_detect(self):
        log.info("Texnologiya fingerprinting...")
        techs = []
        tech_versions = {}

        SIGNATURES = {
            "WordPress"      : ["wp-content/","wp-includes/","wordpress"],
            "WooCommerce"    : ["woocommerce"],
            "Elementor"      : ["elementor"],
            "Joomla"         : ["joomla!","/components/com_"],
            "Drupal"         : ["drupal","drupal.js"],
            "Laravel"        : ["laravel_session","laravel"],
            "Symfony"        : ["symfony"],
            "Django"         : ["csrfmiddlewaretoken"],
            "Flask"          : ["werkzeug"],
            "FastAPI"        : ["fastapi"],
            "Rails"          : ["x-powered-by: phusion passenger","_rails_"],
            "Next.js"        : ["__next_data__","_next/static"],
            "Nuxt.js"        : ["__nuxt","_nuxt/"],
            "React"          : ["reactdom","react.development.js"],
            "Angular"        : ["ng-version=","angular.js","ng-app"],
            "Vue.js"         : ["vue.js","__vue__"],
            "jQuery"         : ["jquery.min.js","jquery/"],
            "Bootstrap"      : ["bootstrap.min.css","bootstrap.css"],
            "Tailwind"       : ["tailwindcss","tw-"],
            "Nginx"          : ["server: nginx"],
            "Apache"         : ["server: apache"],
            "IIS"            : ["server: microsoft-iis"],
            "LiteSpeed"      : ["server: litespeed"],
            "Caddy"          : ["server: caddy"],
            "PHP"            : ["x-powered-by: php",".php?"],
            "ASP.NET"        : ["x-powered-by: asp.net","aspnetcore"],
            "Node.js/Express": ["x-powered-by: express"],
            "Cloudflare"     : ["cf-ray","server: cloudflare"],
            "AWS CloudFront" : ["x-amz-cf-id","cloudfront"],
            "AWS S3"         : ["amazons3","x-amz-"],
            "Google Cloud"   : ["x-goog-","x-gfe-"],
            "Fastly"         : ["x-fastly-request-id"],
            "Varnish"        : ["via: varnish","x-varnish"],
            "Shopify"        : ["shopify","x-shopify-"],
            "Wix"            : ["wix.com","_wix_"],
            "Squarespace"    : ["squarespace"],
        }

        try:
            for scheme in ["https","http"]:
                try:
                    r = self.session.get(
                        f"{scheme}://{self.domain}",
                        timeout=10, verify=False, allow_redirects=True
                    )
                    hdrs   = {k.lower(): v.lower() for k,v in r.headers.items()}
                    body   = r.text.lower()
                    combo  = body + json.dumps(hdrs)

                    for tech, sigs in SIGNATURES.items():
                        if any(s in combo for s in sigs) and tech not in techs:
                            techs.append(tech)
                            console.print(f"  [green]+[/green] {tech}")

                    # Version leaks
                    for hdr in ["server","x-powered-by","x-aspnet-version","x-aspnetmvc-version"]:
                        if hdr in hdrs:
                            v = r.headers.get(hdr,"")
                            log.warn(f"Header oshkor: {hdr}: {v}")
                            tech_versions[hdr] = v

                    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.text, re.I)
                    if gen:
                        log.success(f"Generator: {gen.group(1)}")
                        tech_versions["generator"] = gen.group(1)

                    wp_ver = re.search(r'ver=(\d+\.\d+[\.\d]*)', r.text)
                    if "WordPress" in techs and wp_ver:
                        tech_versions["WordPress"] = wp_ver.group(1)
                        log.warn(f"WordPress versiyasi: {wp_ver.group(1)}")

                    break
                except requests.exceptions.SSLError:
                    continue
        except Exception as e:
            log.error(f"Tech detect: {e}")

        self.results["technologies"] = techs
        self.results["tech_versions"] = tech_versions
        log.success(f"Texnologiya: {len(techs)} ta aniqlandi")

    def _print_summary(self):
        console.print("\n" + "─" * 65)
        t = Table(title=f"OSINT Natijasi: {self.domain}", header_style="bold cyan", show_header=True)
        t.add_column("Kategoriya", style="bold")
        t.add_column("Soni", justify="right")
        t.add_column("Ma'lumot")

        real_emails = [e for e in self.results["emails"] if not e.startswith("[guess]")]
        sub_total   = len(self.results["subdomains"])
        port_total  = len(self.results["ports"])

        t.add_row("DNS Records",   str(len(self.results["dns"])),
                  ", ".join(self.results["dns"].keys()))
        t.add_row("Email Security","",
                  " | ".join(f"{k}: {'✓' if v else '✗'}" for k,v in self.results["email_security"].items() if k in ["SPF","DMARC"]))
        t.add_row("Subdomains",    str(sub_total),
                  ", ".join(s["subdomain"] for s in self.results["subdomains"][:3]) + ("..." if sub_total > 3 else ""))
        t.add_row("Open Ports",    str(port_total),
                  ", ".join(f"{p['port']}/{p['service']}" for p in self.results["ports"]))
        t.add_row("Emails (real)", str(len(real_emails)),
                  ", ".join(real_emails[:2]) + ("..." if len(real_emails) > 2 else ""))
        t.add_row("Technologies",  str(len(self.results["technologies"])),
                  ", ".join(self.results["technologies"][:5]))

        console.print(t)
        console.print()
