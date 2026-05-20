# 🛡️ PenTool v2.0 — Professional Web Pentest & OSINT Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-green?style=flat-square&logo=linux" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/Version-2.0-red?style=flat-square" />
  <img src="https://img.shields.io/badge/Use-Authorized%20Targets%20Only-critical?style=flat-square" />
</p>

> **⚠️ Muhim eslatma:** Bu vosita faqat ruxsat berilgan tizimlarda (CTF, bug bounty, penetration testing engagements) ishlatilishi kerak. Ruxsatsiz foydalanish qonunga xilof.

---

## 📋 Mundarija

- [Xususiyatlar](#-xususiyatlar)
- [Arxitektura](#-arxitektura)
- [O'rnatish](#-ornatish)
- [Foydalanish](#-foydalanish)
- [Modullar](#-modullar)
- [Hisobot namunasi](#-hisobot-namunasi)
- [Loyiha haqida](#-loyiha-haqida)

---

## ✨ Xususiyatlar

### 🔍 OSINT / Razvedka
| Modul | Tavsif |
|-------|--------|
| DNS to'liq | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA yig'ish |
| Email Security | SPF, DMARC, DKIM tekshirish — spoofing xavfini aniqlash |
| WHOIS | Ro'yxatdan o'tganlik, muddat, registrar, kontaktlar |
| Subdomain Enum | Brute-force + **Certificate Transparency** (crt.sh) |
| **Wildcard DNS** | False-positive kamaytirish uchun wildcard aniqlash |
| Port Scan | 30+ port — banner grabbing bilan |
| Tech Detect | 30+ texnologiya fingerprinting (versiya leaklar bilan) |
| Email Harvest | Web scraping + mailto + WHOIS + common guess |

### 🕷️ Web Zaiflik Skaneri
| Zaiflik | Texnika |
|---------|---------|
| **SQL Injection** | Error-based, Union-based, Boolean blind, Time-based |
| **XSS** | Reflected (kontekst-aware: HTML/attr/JS), Bypass payloadlar |
| **LFI** | Path traversal, PHP filter, proc/environ, log poisoning |
| **SSRF** | AWS/GCP/DO metadata, internal network, URL bypass |
| **SSTI** | Jinja2, Twig, Freemarker, Spring SpEL, Velocity, ERB |
| **IDOR** | Baseline diff + response size tahlili |
| **Open Redirect** | Protocol-relative, backslash, encoded bypass |
| **CORS** | Wildcard, reflected origin, credentials misconfiguration |
| **Security Headers** | HSTS, CSP, X-Frame-Options, SameSite va boshqalar |
| **Cookie Flags** | HttpOnly, Secure, SameSite tekshirish |

### 📊 Hisobot
- **HTML** — Professional dark-theme hisobot, CVSS score, risk matrix
- **TXT** — Executive summary + texnik batafsil
- **JSON** — Raw natija (boshqa toollar bilan integratsiya uchun)

---

## 🏗️ Arxitektura

```
pentool_v2/
├── pentool.py              # Asosiy kirish nuqtasi (CLI)
├── modules/
│   ├── __init__.py
│   ├── banner.py           # ASCII banner
│   ├── logger.py           # Markazlashtirilgan log
│   ├── osint.py            # OSINT / Recon moduli
│   ├── scanner.py          # Web zaiflik skaneri
│   └── report.py           # Hisobot generatori
├── wordlists/
│   └── subdomains.txt      # 300+ subdomain wordlist
├── requirements.txt
├── install.sh
└── README.md
```

---

## ⚙️ O'rnatish

### Talab qilinadigan tizim
- Python **3.8+**
- Kali Linux / Ubuntu / Debian
- Internet ulanish (crt.sh uchun)

### Tezkor o'rnatish

```bash
git clone https://github.com/YOUR_USERNAME/pentool.git
cd pentool
chmod +x install.sh
./install.sh
```

### Global o'rnatish (`pentool` buyrug'i sifatida)

```bash
./install.sh --global
pentool --help
```

### Manual o'rnatish

```bash
pip3 install -r requirements.txt --break-system-packages
python3 pentool.py --help
```

---

## 🚀 Foydalanish

### 1. To'liq avtomatik skan (tavsiya etiladi)

```bash
python3 pentool.py full -d example.com \
    -o pentest_report \
    --client "ACME Corp" \
    --tester "John Doe"
```

### 2. Faqat OSINT

```bash
# Barcha OSINT modullari
python3 pentool.py osint -d example.com --all

# Faqat subdomainlar va portlar
python3 pentool.py osint -d example.com --subdomains --ports

# Custom wordlist bilan
python3 pentool.py osint -d example.com --subdomains \
    --wordlist wordlists/subdomains.txt \
    --threads 100

# Natijani saqlash
python3 pentool.py osint -d example.com --all -o osint_results
```

### 3. Web Skanerlash

```bash
# Barcha zaifliklar + crawling
python3 pentool.py scan -u https://example.com --all --crawl

# Faqat SQLi va XSS
python3 pentool.py scan -u https://example.com --sqli --xss --crawl

# Autentifikatsiya bilan (cookie)
python3 pentool.py scan -u https://example.com --all --crawl \
    --cookie "session=abc123; auth=xyz"

# Custom header bilan
python3 pentool.py scan -u https://example.com --all \
    --header "Authorization: Bearer TOKEN" \
    --header "X-Custom: value"

# Burp Suite proxy orqali
python3 pentool.py scan -u https://example.com --all \
    --proxy http://127.0.0.1:8080

# Rate limiting (tez bloklanishni oldini olish)
python3 pentool.py scan -u https://example.com --all \
    --rate-limit 0.5 --threads 5

# Natijani saqlash
python3 pentool.py scan -u https://example.com --all -o scan_results
```

### 4. Hisobot yaratish (mavjud JSON dan)

```bash
python3 pentool.py report \
    -i pentest_report_raw.json \
    -o final_report \
    --format both \
    --client "ACME Corp" \
    --tester "John Doe"
```

---

## 📦 Modullar

### OSINT moduli (`osint.py`)

**Wildcard DNS aniqlash** — Eng muhim qo'shimcha. Agar domen `*.example.com` ni har qanday IP'ga resolve qilsa, minglab "false positive" subdomain chiqadi. Bu modul avval 3 ta random subdomain tekshirib, wildcard IP'larni aniqlaydi va filterlaydi.

**Certificate Transparency** — `crt.sh` SSL sertifikat log'idan passiv (trafik yubormasdan) subdomain topish. Ko'pincha brute-force'dan ko'ra ko'proq natija beradi.

**Email Security** — SPF/DMARC yo'q bo'lsa, domain nomidan email jo'natish mumkin (phishing xavfi). Bu tez-tez bug bounty'da medium/high topilma bo'ladi.

### Web Scanner (`scanner.py`)

**Kontekst-aware XSS** — Payload HTML kontekstida mi, atributda mi, JS'da mi ekanini aniqlaydi. False positive kamroq, aniqroq natija.

**SQLi baseline** — Avval normal request yuborib baseline oladi. Keyin payload bilan response'ni solishtiradi. Har qanday SQL error'ni zaiflik deb hisoblamaydi.

**SSTI** — `{{7*7}}` → `49` kabi matematik ifodalar template engine tomonidan bajarilsa, RCE (Remote Code Execution) mumkin. Juda yuqori xavf.

**SSRF** — AWS Instance Metadata Service (`169.254.169.254`), GCP, DigitalOcean metadata endpointlarini tekshiradi. Cloud serverlar uchun kritik.

### Hisobot (`report.py`)

**CVSS Scoring** — Har bir zaiflikka CVSS v3.1 asosidagi xavf bali beriladi (0.0–9.8).

**Executive Summary** — Texnik bo'lmagan mijozlar uchun umumiy xavf darajasi va tavsiyalar.

**Tuzatish muddati** — Critical → 24 soat, High → 1 hafta, Medium → 1 oy.

---

## 📄 Hisobot namunasi

Hisobot ikki formatda yaratiladi:

**HTML** — Dark theme, interaktiv jadvallar, rang-barang zaiflik badge'lari, CVSS scorelar, risk gauge.

**TXT** — Terminal'da o'qish va email orqali yuborish uchun qulay plain-text format.

---

## 🔧 Kengaytirish

Yangi modul qo'shish uchun:

1. `modules/` papkasida yangi `.py` fayl yarating
2. `pentool.py` `run_full()` funksiyasiga qo'shing
3. `argparse` da yangi subcommand yoki flag qo'shing

Yangi payload qo'shish uchun `scanner.py` ichidagi payload ro'yxatlarini kengaytiring.

---

## 🎓 Loyiha haqida

Bu loyiha Cybersecurity yo'nalishida tahsil olayotgan 4-kurs talabasi tomonidan **Red Team** amaliyoti sifatida yaratilgan. Loyihada quyidagi bilimlar qo'llanilgan:

- Web application security (OWASP Top 10)
- Network reconnaissance va OSINT metodologiyasi  
- Python multithreading va asenkron dasturlash
- Penetration testing metodologiyasi (PTES, OWASP Testing Guide)
- False positive kamaytirish texnikalari
- Professional hisobot yozish

### Foydalanilgan texnologiyalar
`Python 3` · `requests` · `BeautifulSoup4` · `dnspython` · `python-whois` · `Rich` · `concurrent.futures`

---

## ⚖️ Litsenziya & Mas'uliyat

MIT License — batafsil [LICENSE](LICENSE) faylida.

**Muhim:** Bu vosita faqat qonuniy penetration testing, CTF musobaqalari va bug bounty dasturlarida ishlatilishi kerak. Muallif ruxsatsiz foydalanishdan kelib chiqadigan hech qanday oqibat uchun mas'ul emas.

---

<p align="center">
  <strong>PenTool v2.0</strong> · Made with ❤️ for learning & ethical hacking
</p>
