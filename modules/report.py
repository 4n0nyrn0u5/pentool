"""
ReportGenerator v2.0
Yaxshilanishlar:
  - Executive Summary (non-technical)
  - CVSS v3.1 score hisoblash (simplified)
  - Risk matrix vizualizatsiyasi
  - Full vulnerability detail bilan HTML
  - Professional TXT
  - Timeline va statistika
"""

import json
from datetime import datetime
from rich.console import Console

console = Console()

# CVSS v3.1 simplified score (AV:N/AC:L/PR:N/UI:N/S:U)
CVSS_BASE = {
    "critical": 9.8,
    "high"    : 8.1,
    "medium"  : 6.1,
    "low"     : 3.7,
    "info"    : 0.0,
}

REMEDIATION_EFFORT = {
    "critical": "Darhol (24 soat ichida)",
    "high"    : "Tez (1 hafta ichida)",
    "medium"  : "O'rta (1 oy ichida)",
    "low"     : "Rejalashtirilgan (keyingi sprint)",
    "info"    : "Ma'lumot uchun",
}


class ReportGenerator:

    def generate(self, data, output_name, fmt="both", client="N/A", tester="Pentester"):
        if fmt in ("txt","both"):
            self._txt(data, output_name, client, tester)
        if fmt in ("html","both"):
            self._html(data, output_name, client, tester)

    # ── TXT ────────────────────────────────────────────────────

    def _txt(self, data, name, client, tester):
        fname = name + "_report.txt"
        now   = datetime.now().strftime("%Y-%m-%d %H:%M")
        target= data.get("target") or data.get("osint",{}).get("target","")
        osint = data.get("osint") or data
        scan  = data.get("scan")  or data
        vulns = scan.get("vulnerabilities",[])

        L = []
        sep = "═" * 65
        L += [sep, "    PENETRATION TEST HISOBOTI — PenTool v2.0", sep,
              f"  Mijoz     : {client}",
              f"  Pentester : {tester}",
              f"  Sana      : {now}",
              f"  Target    : {target}", sep, ""]

        # Executive Summary
        counts = {s: sum(1 for v in vulns if v["severity"]==s)
                  for s in ["critical","high","medium","low","info"]}
        risk = "KRITIK" if counts["critical"] else "YUQORI" if counts["high"] else "O'RTA" if counts["medium"] else "PAST"
        L += ["[ IJROCHI XULOSA ]",
              f"  Umumiy xavf darajasi : {risk}",
              f"  Jami zaifliklar      : {len(vulns)} ta",
              f"  Critical             : {counts['critical']}",
              f"  High                 : {counts['high']}",
              f"  Medium               : {counts['medium']}",
              f"  Low                  : {counts['low']}", ""]

        # OSINT
        if osint.get("dns"):
            L += ["[ DNS RECORDS ]"]
            for rt, vals in osint["dns"].items():
                L.append(f"  {rt:<8}: {', '.join(vals[:3])}")
            L.append("")

        if osint.get("email_security"):
            L += ["[ EMAIL XAVFSIZLIGI ]"]
            es = osint["email_security"]
            L.append(f"  SPF   : {'✓ Mavjud' if es.get('SPF') else '✗ YO\'Q — email spoofing mumkin'}")
            L.append(f"  DMARC : {'✓ Mavjud' if es.get('DMARC') else '✗ YO\'Q — email spoofing mumkin'}")
            L.append("")

        if osint.get("subdomains"):
            L += [f"[ SUBDOMAINLAR ] ({len(osint['subdomains'])} ta)"]
            for s in osint["subdomains"][:20]:
                L.append(f"  + {s['subdomain']:<40} {s['ip']:<16} HTTP {s.get('status','?')}")
            if len(osint["subdomains"]) > 20:
                L.append(f"  ... va yana {len(osint['subdomains'])-20} ta")
            L.append("")

        if osint.get("ports"):
            L += [f"[ OCHIQ PORTLAR ] ({len(osint['ports'])} ta)"]
            for p in osint["ports"]:
                risk_s = " ⚠ HIGH RISK" if p.get("risk") else ""
                banner = f"  [{p.get('banner','')}]" if p.get("banner") else ""
                L.append(f"  {p['port']}/tcp  {p['service']:<16}{risk_s}{banner}")
            L.append("")

        if osint.get("technologies"):
            L += ["[ TEXNOLOGIYALAR ]",
                  "  " + ", ".join(osint["technologies"]), ""]

        # Vulnerabilities
        L += [f"[ TOPILGAN ZAIFLIKLAR ] ({len(vulns)} ta)", "─" * 65]
        if not vulns:
            L.append("  ✓ Zaiflik topilmadi")
        for i, v in enumerate(vulns, 1):
            cvss = CVSS_BASE.get(v["severity"], 0.0)
            effort = REMEDIATION_EFFORT.get(v["severity"],"")
            L += ["",
                  f"  [{i}] {v['type']}  [{v['severity'].upper()}]  CVSS: {cvss}",
                  f"      URL      : {v['url']}",
                  f"      Parametr : {v['parameter']}",
                  f"      Payload  : {v['payload'][:70]}",
                  f"      Dalil    : {v['evidence'][:100]}",
                  f"      Tavsif   : {v['description']}",
                  f"      Tuzatish : {v['remediation']}",
                  f"      Muddati  : {effort}"]

        L += ["", sep, "  PenTool v2.0  |  " + now + "  |  Faqat ruxsat berilgan targetlarda",
              sep]

        with open(fname, "w", encoding="utf-8") as f:
            f.write("\n".join(L))
        console.print(f"[green][+][/green] TXT hisobot: [cyan]{fname}[/cyan]")

    # ── HTML ───────────────────────────────────────────────────

    def _html(self, data, name, client, tester):
        fname  = name + "_report.html"
        now    = datetime.now().strftime("%Y-%m-%d %H:%M")
        target = data.get("target") or data.get("osint",{}).get("target","")
        osint  = data.get("osint") or data
        scan   = data.get("scan")  or data
        vulns  = scan.get("vulnerabilities",[])

        sev_color = {
            "critical": "#e74c3c",
            "high"    : "#e67e22",
            "medium"  : "#f39c12",
            "low"     : "#3498db",
            "info"    : "#95a5a6",
        }
        counts = {s: sum(1 for v in vulns if v["severity"]==s)
                  for s in ["critical","high","medium","low","info"]}
        total  = len(vulns)
        risk   = ("KRITIK" if counts["critical"] else
                  "YUQORI" if counts["high"] else
                  "O'RTA"  if counts["medium"] else "PAST")
        risk_color = ("#e74c3c" if risk=="KRITIK" else
                      "#e67e22" if risk=="YUQORI" else
                      "#f39c12" if risk=="O'RTA" else "#2ecc71")

        # ── Vuln rows ──
        vuln_rows = ""
        for i, v in enumerate(vulns, 1):
            c    = sev_color.get(v["severity"],"#888")
            cvss = CVSS_BASE.get(v["severity"], 0.0)
            eff  = REMEDIATION_EFFORT.get(v["severity"],"")
            vuln_rows += f"""
            <tr>
              <td class="num">{i}</td>
              <td><span class="badge" style="background:{c}20;color:{c};border:1px solid {c}60">{v['severity'].upper()}</span></td>
              <td><strong>{v['type']}</strong></td>
              <td class="mono small">{v['url'][:65]}</td>
              <td class="mono small">{v['parameter']}</td>
              <td class="cvss" style="color:{c}">{cvss}</td>
              <td class="small">{eff}</td>
            </tr>
            <tr class="detail-row">
              <td colspan="7">
                <div class="detail-box">
                  <div><span class="label">Payload:</span> <code>{v['payload'][:100]}</code></div>
                  <div><span class="label">Dalil:</span> {v['evidence'][:150]}</div>
                  <div><span class="label">Tavsif:</span> {v['description']}</div>
                  <div><span class="label">Tuzatish:</span> <span class="fix">{v['remediation']}</span></div>
                </div>
              </td>
            </tr>"""

        # ── Subdomain rows ──
        sub_rows = ""
        for s in osint.get("subdomains",[]):
            st = s.get("status")
            sc = "#2ecc71" if st==200 else "#e67e22" if st in [301,302] else "#e74c3c" if st==403 else "#95a5a6"
            src = s.get("source","")
            title = s.get("title","")
            sub_rows += f"""<tr>
              <td>{s['subdomain']}</td>
              <td class="mono small">{s.get('ip','')}</td>
              <td style="color:{sc}">{st or '?'}</td>
              <td class="small">{src}</td>
              <td class="small">{title}</td>
            </tr>"""

        # ── Port rows ──
        port_rows = ""
        for p in osint.get("ports",[]):
            danger = p.get("risk",False)
            c = "#e74c3c" if danger else "#2ecc71"
            risk_s = "⚠ HIGH RISK" if danger else "Normal"
            banner = p.get("banner","")
            port_rows += f"""<tr>
              <td style="color:{c}"><strong>{p['port']}/tcp</strong></td>
              <td>{p['service']}</td>
              <td style="color:{c}">{risk_s}</td>
              <td class="mono small">{banner}</td>
            </tr>"""

        # ── Tech pills ──
        tech_html = "".join(
            f'<span class="pill">{t}</span>'
            for t in osint.get("technologies",[])
        )
        tech_ver = osint.get("tech_versions",{})
        tech_ver_html = "".join(
            f'<span class="pill warn">⚠ {k}: {v}</span>'
            for k,v in tech_ver.items()
        ) if tech_ver else ""

        # ── Email security ──
        es = osint.get("email_security",{})
        es_html = ""
        for k in ["SPF","DMARC"]:
            v = es.get(k)
            if v is None and k in es:
                es_html += f'<div class="es-item bad">✗ {k} yo\'q — email spoofing mumkin!</div>'
            elif v:
                es_html += f'<div class="es-item good">✓ {k} mavjud</div>'

        # ── Risk gauge (CSS) ──
        gauge_pct = {"KRITIK":100,"YUQORI":75,"O'RTA":50,"PAST":25}.get(risk,25)

        html = f"""<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pentest Hisoboti — {target}</title>
<style>
:root {{
  --bg      : #0d1117;
  --surface : #161b22;
  --border  : #21262d;
  --accent  : #00d4aa;
  --text    : #c9d1d9;
  --dim     : #8b949e;
  --red     : #e74c3c;
  --orange  : #e67e22;
  --yellow  : #f39c12;
  --green   : #2ecc71;
  --blue    : #3498db;
}}
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ font-family:'Segoe UI',Arial,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; font-size:14px; }}
.container {{ max-width:1200px; margin:0 auto; padding:30px 20px; }}

/* Header */
.header {{ background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:30px; margin-bottom:24px; }}
.logo {{ font-size:26px; font-weight:800; color:var(--accent); letter-spacing:4px; margin-bottom:4px; }}
.logo span {{ color:#fff; }}
.subtitle {{ color:var(--dim); font-size:12px; letter-spacing:2px; text-transform:uppercase; margin-bottom:20px; }}
.meta-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-top:16px; }}
.meta-item {{ background:var(--bg); border-radius:8px; padding:12px 16px; }}
.meta-label {{ font-size:10px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; }}
.meta-val {{ font-size:15px; font-weight:600; color:var(--accent); margin-top:2px; }}

/* Risk banner */
.risk-banner {{ background:var(--surface); border:1px solid {risk_color}; border-left:4px solid {risk_color}; border-radius:8px; padding:16px 24px; margin-bottom:24px; display:flex; align-items:center; gap:20px; }}
.risk-label {{ font-size:11px; color:var(--dim); text-transform:uppercase; }}
.risk-val {{ font-size:24px; font-weight:800; color:{risk_color}; }}
.risk-gauge {{ flex:1; height:8px; background:var(--border); border-radius:4px; overflow:hidden; }}
.risk-gauge-fill {{ height:100%; width:{gauge_pct}%; background:{risk_color}; border-radius:4px; }}

/* Stats */
.stats {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-bottom:24px; }}
.stat {{ background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:16px; text-align:center; }}
.stat-num {{ font-size:32px; font-weight:700; }}
.stat-lbl {{ font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; margin-top:4px; }}

/* Section */
.section {{ background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:24px; margin-bottom:20px; }}
.section-title {{ font-size:16px; font-weight:700; color:var(--accent); margin-bottom:16px; display:flex; align-items:center; gap:8px; }}

/* Table */
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ text-align:left; padding:8px 12px; color:var(--dim); font-size:11px; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid var(--border); white-space:nowrap; }}
td {{ padding:8px 12px; border-bottom:1px solid var(--border); }}
tr:last-child td {{ border-bottom:none; }}
tbody tr:hover td {{ background:rgba(255,255,255,0.02); }}
.num {{ width:36px; color:var(--dim); text-align:center; }}
.mono {{ font-family:'Courier New',monospace; font-size:12px; }}
.small {{ font-size:12px; color:var(--dim); }}
.cvss {{ font-weight:700; font-size:14px; text-align:center; }}

/* Badge */
.badge {{ display:inline-block; padding:2px 10px; border-radius:20px; font-size:11px; font-weight:700; letter-spacing:0.5px; }}

/* Detail row */
.detail-row td {{ padding:0 12px 12px; }}
.detail-box {{ background:var(--bg); border-radius:6px; padding:12px 16px; border-left:2px solid var(--border); display:flex; flex-direction:column; gap:6px; font-size:12px; }}
.detail-box .label {{ color:var(--dim); font-weight:600; margin-right:8px; }}
code {{ font-family:'Courier New',monospace; background:#ffffff10; padding:1px 6px; border-radius:3px; font-size:11px; }}
.fix {{ color:var(--green); }}

/* Pills */
.pill {{ display:inline-block; background:#00d4aa20; color:var(--accent); border:1px solid #00d4aa40; padding:3px 10px; border-radius:20px; font-size:12px; margin:3px; }}
.pill.warn {{ background:#e67e2220; color:var(--orange); border-color:#e67e2240; }}

/* Email security */
.es-item {{ padding:6px 12px; border-radius:6px; margin:4px 0; font-size:13px; }}
.es-item.good {{ background:#2ecc7115; color:var(--green); }}
.es-item.bad  {{ background:#e74c3c15; color:var(--red); }}

footer {{ text-align:center; padding:24px; color:var(--dim); font-size:12px; border-top:1px solid var(--border); margin-top:20px; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="logo">PEN<span>TOOL</span></div>
    <div class="subtitle">Professional Penetration Testing Report · v2.0</div>
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-label">Target</div><div class="meta-val">{target}</div></div>
      <div class="meta-item"><div class="meta-label">Mijoz</div><div class="meta-val">{client}</div></div>
      <div class="meta-item"><div class="meta-label">Pentester</div><div class="meta-val">{tester}</div></div>
      <div class="meta-item"><div class="meta-label">Sana</div><div class="meta-val">{now}</div></div>
    </div>
  </div>

  <!-- Risk Banner -->
  <div class="risk-banner">
    <div><div class="risk-label">Umumiy Xavf</div><div class="risk-val">{risk}</div></div>
    <div class="risk-gauge"><div class="risk-gauge-fill"></div></div>
    <div><div class="risk-label">Zaifliklar</div><div class="risk-val">{total}</div></div>
  </div>

  <!-- Stats -->
  <div class="stats">
    <div class="stat"><div class="stat-num" style="color:#e74c3c">{counts['critical']}</div><div class="stat-lbl">Critical</div></div>
    <div class="stat"><div class="stat-num" style="color:#e67e22">{counts['high']}</div><div class="stat-lbl">High</div></div>
    <div class="stat"><div class="stat-num" style="color:#f39c12">{counts['medium']}</div><div class="stat-lbl">Medium</div></div>
    <div class="stat"><div class="stat-num" style="color:#3498db">{counts['low']}</div><div class="stat-lbl">Low</div></div>
    <div class="stat"><div class="stat-num" style="color:#95a5a6">{len(osint.get('subdomains',[]))}</div><div class="stat-lbl">Subdomains</div></div>
  </div>

  <!-- Zaifliklar -->
  <div class="section">
    <div class="section-title">⚠ Topilgan Zaifliklar ({total} ta)</div>
    {'<table><thead><tr><th>#</th><th>Jiddiylik</th><th>Zaiflik</th><th>URL</th><th>Param</th><th>CVSS</th><th>Muddati</th></tr></thead><tbody>' + vuln_rows + '</tbody></table>' if vulns else '<p style="color:var(--green);text-align:center;padding:20px;font-size:15px">✓ Hech qanday zaiflik topilmadi</p>'}
  </div>

  <!-- OSINT: Subdomainlar -->
  {'<div class="section"><div class="section-title">🌐 Subdomainlar (' + str(len(osint.get("subdomains",[]))) + ' ta)</div><table><thead><tr><th>Subdomain</th><th>IP</th><th>HTTP</th><th>Manba</th><th>Title</th></tr></thead><tbody>' + sub_rows + '</tbody></table></div>' if osint.get('subdomains') else ''}

  <!-- OSINT: Portlar -->
  {'<div class="section"><div class="section-title">🔌 Ochiq Portlar (' + str(len(osint.get("ports",[]))) + ' ta)</div><table><thead><tr><th>Port</th><th>Servis</th><th>Xavf</th><th>Banner</th></tr></thead><tbody>' + port_rows + '</tbody></table></div>' if osint.get('ports') else ''}

  <!-- OSINT: Texnologiyalar -->
  {'<div class="section"><div class="section-title">🛠 Texnologiyalar</div><div>' + tech_html + tech_ver_html + '</div></div>' if osint.get('technologies') else ''}

  <!-- Email Security -->
  {'<div class="section"><div class="section-title">📧 Email Xavfsizligi</div>' + es_html + '</div>' if es_html else ''}

  <footer>
    PenTool v2.0 &nbsp;|&nbsp; {now} &nbsp;|&nbsp;
    <span style="color:#e74c3c">⚠ Faqat ruxsat berilgan tizimlarda foydalaning</span>
  </footer>
</div>
</body>
</html>"""

        with open(fname, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"[green][+][/green] HTML hisobot: [cyan]{fname}[/cyan]")
