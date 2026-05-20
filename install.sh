#!/bin/bash
# PenTool v2.0 — Kali Linux / Ubuntu install skripti

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}"
echo " ██████╗ ███████╗███╗   ██╗████████╗ ██████╗  ██████╗ ██╗      "
echo " ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║      "
echo " ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║      "
echo " ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║   ██║██║      "
echo " ██║     ███████╗██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗ "
echo " ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝"
echo -e "${NC}"
echo -e "${BOLD}${YELLOW}         Web Scanner + OSINT Framework  v2.0  — Install${NC}"
echo ""

# ── Python versiyasini tekshirish ──────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] Python3 topilmadi — o'rnatilmoqda...${NC}"
    sudo apt-get install -y python3 python3-pip
fi

PY_VER=$(python3 -c 'import sys; print(sys.version_info[:2] >= (3,8))')
if [ "$PY_VER" != "True" ]; then
    echo -e "${RED}[!] Python 3.8+ kerak. Hozirgi versiya eskirgan.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Python: $(python3 --version)${NC}"

# ── pip yangilash ──────────────────────────────────────────────────
echo -e "${YELLOW}[*] pip yangilanmoqda...${NC}"
python3 -m pip install --upgrade pip --break-system-packages -q 2>/dev/null || \
python3 -m pip install --upgrade pip -q

# ── Kutubxonalar ───────────────────────────────────────────────────
echo -e "${YELLOW}[*] Kutubxonalar o'rnatilmoqda...${NC}"
pip3 install -r requirements.txt --break-system-packages -q 2>/dev/null || \
pip3 install -r requirements.txt -q

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] O'rnatish xato. Manual sinab ko'ring:${NC}"
    echo "    pip3 install -r requirements.txt --break-system-packages"
    exit 1
fi
echo -e "${GREEN}[+] Barcha kutubxonalar o'rnatildi${NC}"

# ── Executable ─────────────────────────────────────────────────────
chmod +x pentool.py
echo -e "${GREEN}[+] pentool.py ishga tayyor (chmod +x)${NC}"

# ── Global o'rnatish (ixtiyoriy) ───────────────────────────────────
if [ "$1" == "--global" ]; then
    sudo ln -sf "$(pwd)/pentool.py" /usr/local/bin/pentool
    echo -e "${GREEN}[+] Global o'rnatildi: 'pentool' buyrug'i ishlaydi${NC}"
fi

# ── Tekshirish ─────────────────────────────────────────────────────
echo ""
python3 pentool.py --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}[✓]  O'rnatish muvaffaqiyatli yakunlandi!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
else
    echo -e "${RED}[!] Biror muammo bor — python3 pentool.py --help ni sinang${NC}"
fi

echo ""
echo -e "${BOLD}Ishlatish namunalari:${NC}"
echo -e "  ${CYAN}python3 pentool.py osint -d example.com --all${NC}"
echo -e "  ${CYAN}python3 pentool.py scan  -u https://example.com --all --crawl${NC}"
echo -e "  ${CYAN}python3 pentool.py full  -d example.com -o pentest_report --client ACME --tester YourName${NC}"
echo -e "  ${CYAN}python3 pentool.py report -i pentest_report_raw.json -o final_report${NC}"
echo ""
echo -e "${RED}[!] Faqat ruxsat berilgan tizimlarda foydalaning!${NC}"
