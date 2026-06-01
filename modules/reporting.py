"""
Professional Reporting Module – CYS-ILM v3.0
Generates Text, HTML (self-contained), and JSON reports.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List

from jinja2 import Template

logger = logging.getLogger(__name__)

# ── severity colours ─────────────────────────────────────────────
_SEV_COLOUR = {
    "HIGH":   "#dc3545",
    "MEDIUM": "#fd7e14",
    "LOW":    "#28a745",
    "INFO":   "#17a2b8",
}
_RISK_COLOUR = {
    "HIGH":   "#dc3545",
    "MEDIUM": "#fd7e14",
    "LOW":    "#28a745",
    "INFO":   "#17a2b8",
}


class ReportGenerator:
    """Generate professional security assessment reports."""

    def __init__(self, results: Dict[str, Any], output_dir: str = "outputs") -> None:
        self.results    = results
        self.output_dir = output_dir
        self.ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.target     = results["metadata"]["target"]
        os.makedirs(output_dir, exist_ok=True)

    # ── public methods ────────────────────────────────────────────
    def generate_text_report(self) -> str:
        path = os.path.join(self.output_dir, f"recon_{self.target}_{self.ts}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self._text())
        logger.info(f"Text report  → {path}")
        return path

    def generate_html_report(self) -> str:
        path = os.path.join(self.output_dir, f"recon_{self.target}_{self.ts}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self._html())
        logger.info(f"HTML report  → {path}")
        return path

    def generate_json_report(self) -> str:
        path = os.path.join(self.output_dir, f"recon_{self.target}_{self.ts}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, default=str)
        logger.info(f"JSON report  → {path}")
        return path

    # ── text report ───────────────────────────────────────────────
    def _text(self) -> str:
        W  = 80
        ln = "=" * W

        def h1(t): return f"\n{ln}\n  {t}\n{ln}"
        def h2(t): return f"\n  {t}\n  {'─'*40}"
        def kv(k,v, indent=4): return f"{' '*indent}{k:<28}: {v}"

        meta    = self.results["metadata"]
        risk    = self.results.get("risk_assessment", {})
        passive = self.results.get("passive", {})
        active  = self.results.get("active",  {})
        finds   = self.results.get("findings", [])

        lines: List[str] = []
        lines += [
            ln,
            "  CYS-ILM SECURITY RECONNAISSANCE REPORT",
            "  Confidential — For Authorized Use Only",
            ln,
            kv("Target",       meta.get("target")),
            kv("Scan ID",      meta.get("scan_id")),
            kv("Operator",     meta.get("operator","N/A")),
            kv("Privileged",   meta.get("privileged", False)),
            kv("Start",        meta.get("start_time")),
            kv("End",          meta.get("end_time","N/A")),
            kv("Tool Version", meta.get("tool_version")),
        ]

        # Risk summary
        lines.append(h1("RISK ASSESSMENT"))
        lines += [
            kv("Risk Level",       risk.get("risk_level","N/A")),
            kv("Risk Score",       f"{risk.get('risk_score',0)}/100"),
            kv("Total Findings",   risk.get("total_findings",0)),
            kv("High",             risk.get("high_count",0)),
            kv("Medium",           risk.get("medium_count",0)),
            kv("Low",              risk.get("low_count",0)),
        ]

        # Passive
        if passive:
            lines.append(h1("PASSIVE RECONNAISSANCE"))

            if w := passive.get("whois"):
                lines.append(h2("WHOIS"))
                for k, v in w.items():
                    if v and k != "error":
                        val = ", ".join(v) if isinstance(v, list) else str(v)
                        lines.append(kv(k, val[:100]))

            if dns := passive.get("dns", {}).get("records"):
                lines.append(h2("DNS RECORDS"))
                for rtype, recs in dns.items():
                    if recs:
                        lines.append(f"    [{rtype}]")
                        for r in recs:
                            lines.append(f"      • {r}")

            if subs := passive.get("subdomains", {}):
                lines.append(h2("SUBDOMAINS"))
                lines.append(kv("Discovered", subs.get("total_discovered",0)))
                lines.append(kv("Valid",       subs.get("total_valid",0)))
                for s in (subs.get("validated_subdomains") or [])[:30]:
                    lines.append(f"      • {s['subdomain']:<45} {s.get('ip_address','')}")

            if ei := passive.get("email_info"):
                lines.append(h2("EMAIL INTELLIGENCE"))
                lines.append(kv("MX",    ", ".join(ei.get("mx_records") or ["-"])))
                lines.append(kv("SPF",   ei.get("spf") or "NOT FOUND"))
                lines.append(kv("DMARC", ei.get("dmarc") or "NOT FOUND"))
                if ei.get("dkim"):
                    lines.append(kv("DKIM", f"{len(ei['dkim'])} selector(s) found"))

        # Active
        if active:
            lines.append(h1("ACTIVE RECONNAISSANCE"))

            if ps := active.get("port_scan", {}):
                lines.append(h2("PORT SCAN"))
                lines.append(kv("Scan type",  ps.get("scan_type")))
                lines.append(kv("Ports",      ps.get("ports_scanned")))
                lines.append(kv("Open ports", len(ps.get("open_ports",[]))))
                for p in (ps.get("open_ports") or []):
                    risk_flag = "  ⚠" if p.get("risk") else ""
                    lines.append(
                        f"      {p['port']:>5}/{p['protocol']:<4}  "
                        f"{p['service']:<15}  {p.get('product','')} "
                        f"{p.get('version','')}{risk_flag}"
                    )

            if hdrs := active.get("http_headers"):
                lines.append(h2("HTTP SECURITY HEADERS"))
                lines.append(kv("Grade",   hdrs.get("grade","N/A")))
                lines.append(kv("Missing", ", ".join(hdrs.get("missing_headers",[]) or ["-"])))
                for issue in hdrs.get("issues",[]):
                    lines.append(f"      ⚠  {issue}")

            if techs := active.get("technologies"):
                lines.append(h2("TECHNOLOGIES"))
                for cat, items in techs.items():
                    if isinstance(items, list) and items:
                        lines.append(f"      {cat.replace('_',' ').title():<22}: "
                                     f"{', '.join(items)}")

            if vulns := active.get("vulnerability_checks"):
                lines.append(h2("VULNERABILITY CHECKS"))
                for issue in vulns.get("issues",[]):
                    lines.append(f"      [ISSUE]   {issue}")
                for warn in vulns.get("warnings",[]):
                    lines.append(f"      [WARN]    {warn}")
                for info in vulns.get("info",[]):
                    lines.append(f"      [INFO]    {info}")

        # Findings
        lines.append(h1("FINDINGS & RECOMMENDATIONS"))
        for f in finds:
            sev = f.get("severity","INFO")
            lines += [
                f"\n  [{sev}]  {f.get('title','')}",
                f"  Category   : {f.get('category','')}",
                f"  Description: {f.get('description','')}",
                f"  Action     : {f.get('recommendation','')}",
                "  " + "─"*60,
            ]

        # Footer
        lines += [
            f"\n{ln}",
            "  END OF REPORT",
            f"  Generated by CYS-ILM Recon Tool v{meta.get('tool_version')}",
            f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ln,
        ]
        return "\n".join(lines)

    # ── HTML report ───────────────────────────────────────────────
    def _html(self) -> str:
        meta    = self.results["metadata"]
        risk    = self.results.get("risk_assessment", {})
        passive = self.results.get("passive", {})
        active  = self.results.get("active",  {})
        finds   = self.results.get("findings", [])

        rc = _RISK_COLOUR.get(risk.get("risk_level","INFO"), "#17a2b8")

        open_ports_count = len(active.get("port_scan",{}).get("open_ports",[]))
        sub_count        = passive.get("subdomains",{}).get("total_valid", 0)
        tech_count       = sum(
            len(v) for v in (active.get("technologies") or {}).values()
            if isinstance(v, list)
        )
        issues_count     = risk.get("high_count",0) + risk.get("medium_count",0)

        # Build dynamic sections
        def badge(sev):
            c = _SEV_COLOUR.get(sev,"#17a2b8")
            return (f'<span style="background:{c};color:#fff;padding:2px 8px;'
                    f'border-radius:10px;font-size:.8em;font-weight:700">{sev}</span>')

        # ── Passive section HTML
        passive_html = ""
        if passive:
            # WHOIS
            if w := passive.get("whois"):
                rows = ""
                for k, v in w.items():
                    if v and k != "error":
                        val = ", ".join(v) if isinstance(v,list) else str(v)
                        rows += f"<tr><td><b>{k}</b></td><td>{val[:200]}</td></tr>"
                if rows:
                    passive_html += f"""
                    <div class="card">
                      <h3>WHOIS Information</h3>
                      <table>{rows}</table>
                    </div>"""

            # DNS
            if dns := passive.get("dns", {}).get("records"):
                rows = ""
                for rtype, recs in dns.items():
                    if recs:
                        rows += (f"<tr><td><code>{rtype}</code></td>"
                                 f"<td>{'<br>'.join(str(r) for r in recs)}</td></tr>")
                if rows:
                    passive_html += f"""
                    <div class="card">
                      <h3>DNS Records</h3>
                      <table><tr><th>Type</th><th>Records</th></tr>{rows}</table>
                    </div>"""

            # Subdomains
            if subs := passive.get("subdomains", {}):
                rows = ""
                for s in (subs.get("validated_subdomains") or [])[:50]:
                    rows += (f"<tr><td>{s['subdomain']}</td>"
                             f"<td>{s.get('ip_address','')}</td>"
                             f"<td>{', '.join(s.get('sources',[]))}</td></tr>")
                if rows:
                    passive_html += f"""
                    <div class="card">
                      <h3>Subdomains
                        <span class="pill">{subs.get('total_valid',0)} valid</span>
                      </h3>
                      <table>
                        <tr><th>Subdomain</th><th>IP</th><th>Source</th></tr>
                        {rows}
                      </table>
                    </div>"""

            # Email
            if ei := passive.get("email_info"):
                passive_html += f"""
                <div class="card">
                  <h3>Email Intelligence</h3>
                  <table>
                    <tr><td><b>MX</b></td><td>{', '.join(ei.get('mx_records') or ['-'])}</td></tr>
                    <tr><td><b>SPF</b></td><td>{ei.get('spf') or '<span class="warn">NOT FOUND</span>'}</td></tr>
                    <tr><td><b>DMARC</b></td><td>{ei.get('dmarc') or '<span class="warn">NOT FOUND</span>'}</td></tr>
                    <tr><td><b>DKIM</b></td><td>{len(ei.get('dkim') or [])} selector(s)</td></tr>
                  </table>
                </div>"""

        # ── Active section HTML
        active_html = ""
        if active:
            if ps := active.get("port_scan", {}):
                rows = ""
                for p in ps.get("open_ports",[]):
                    flag = "🔴" if p.get("risk") else "🟢"
                    rows += (f"<tr><td>{p['port']}/{p['protocol']}</td>"
                             f"<td>{p['service']}</td>"
                             f"<td>{p.get('product','')} {p.get('version','')}</td>"
                             f"<td>{flag}</td></tr>")
                stats = ps.get("scan_stats",{})
                active_html += f"""
                <div class="card">
                  <h3>Port Scan
                    <span class="pill">{len(ps.get('open_ports',[]))} open</span>
                  </h3>
                  <p><b>Mode:</b> {ps.get('scan_type','N/A')} &nbsp;
                     <b>Range:</b> {ps.get('ports_scanned','N/A')}</p>
                  {"<table><tr><th>Port</th><th>Service</th><th>Product/Version</th><th>Risk</th></tr>" + rows + "</table>" if rows else "<p>No open ports found.</p>"}
                </div>"""

            if hdrs := active.get("http_headers"):
                g = hdrs.get("grade","F")
                gc = {"A":"#28a745","B":"#5cb85c","C":"#f0ad4e","D":"#e67e22","F":"#dc3545"}.get(g,"#dc3545")
                rows = ""
                for hdr, info in hdrs.get("security_headers",{}).items():
                    chk = "✅" if info.get("present") else "❌"
                    val = (info.get("value") or "")[:80] or "—"
                    rows += (f"<tr><td>{chk} {hdr}</td>"
                             f"<td>{val}</td>"
                             f"<td>{info.get('description','')}</td></tr>")
                issues_html = "".join(
                    f'<li class="warn">⚠ {i}</li>'
                    for i in hdrs.get("issues",[])
                )
                active_html += f"""
                <div class="card">
                  <h3>HTTP Security Headers
                    <span class="pill" style="background:{gc}">{g}</span>
                  </h3>
                  {"<table><tr><th>Header</th><th>Value</th><th>Purpose</th></tr>" + rows + "</table>" if rows else ""}
                  {"<ul>" + issues_html + "</ul>" if issues_html else ""}
                </div>"""

            if techs := active.get("technologies"):
                tags = "".join(
                    f'<span class="tag">{t}</span>'
                    for items in techs.values() if isinstance(items,list)
                    for t in items
                )
                if tags:
                    active_html += f"""
                    <div class="card">
                      <h3>Detected Technologies</h3>
                      <div style="display:flex;flex-wrap:wrap;gap:6px">{tags}</div>
                    </div>"""

            if vulns := active.get("vulnerability_checks"):
                vuln_html = ""
                for issue in vulns.get("issues",[]):
                    vuln_html += f'<li style="color:#dc3545">🔴 {issue}</li>'
                for warn in vulns.get("warnings",[]):
                    vuln_html += f'<li style="color:#fd7e14">🟡 {warn}</li>'
                for info in vulns.get("info",[]):
                    vuln_html += f'<li style="color:#17a2b8">ℹ️ {info}</li>'
                if vuln_html:
                    active_html += f"""
                    <div class="card">
                      <h3>Vulnerability Checks</h3>
                      <ul>{vuln_html}</ul>
                    </div>"""

        # ── Findings table
        findings_html = ""
        if finds:
            rows = ""
            for f in finds:
                sev = f.get("severity","INFO")
                rows += (f"<tr>"
                         f"<td>{badge(sev)}</td>"
                         f"<td>{f.get('category','')}</td>"
                         f"<td><b>{f.get('title','')}</b><br>"
                         f"<small>{f.get('description','')}</small></td>"
                         f"<td>{f.get('recommendation','')}</td>"
                         f"</tr>")
            findings_html = f"""
            <div class="card">
              <table>
                <tr>
                  <th>Severity</th><th>Category</th>
                  <th>Finding</th><th>Recommendation</th>
                </tr>
                {rows}
              </table>
            </div>"""

        # ── Assemble full HTML ────────────────────────────────────
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYS-ILM Recon Report – {meta.get('target')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',system-ui,sans-serif}}
body{{background:#0d1117;color:#c9d1d9;line-height:1.6;padding:20px}}
a{{color:#58a6ff}}
.wrap{{max-width:1200px;margin:0 auto}}
/* header */
header{{background:linear-gradient(135deg,#161b22 0%,#1f2937 100%);
       border:1px solid #30363d;border-radius:12px;padding:32px;margin-bottom:20px}}
header h1{{font-size:2rem;color:#58a6ff;margin-bottom:6px}}
header p{{color:#8b949e;font-size:.95rem}}
/* meta grid */
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
      gap:12px;margin-bottom:20px}}
.meta-item{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px}}
.meta-item .lbl{{font-size:.75rem;text-transform:uppercase;letter-spacing:.5px;color:#8b949e}}
.meta-item .val{{font-size:1.1rem;color:#e6edf3;margin-top:4px;font-weight:600}}
/* stat cards */
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;
      padding:20px;text-align:center;transition:transform .2s}}
.stat:hover{{transform:translateY(-3px)}}
.stat .num{{font-size:2.4rem;font-weight:700;color:#58a6ff}}
.stat .lbl{{font-size:.8rem;text-transform:uppercase;color:#8b949e;margin-top:4px}}
/* section */
.section{{margin-bottom:28px}}
.section h2{{font-size:1.3rem;color:#e6edf3;margin-bottom:12px;
            padding-bottom:8px;border-bottom:1px solid #30363d;
            display:flex;align-items:center;gap:8px}}
/* card */
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
      padding:20px;margin-bottom:14px}}
.card h3{{font-size:1rem;color:#e6edf3;margin-bottom:12px;
         display:flex;align-items:center;gap:8px}}
/* table */
table{{width:100%;border-collapse:collapse;font-size:.9rem}}
th{{background:#21262d;padding:10px 12px;text-align:left;
   color:#8b949e;font-weight:600;font-size:.8rem;text-transform:uppercase}}
td{{padding:9px 12px;border-bottom:1px solid #21262d;color:#c9d1d9}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#21262d55}}
/* misc */
.pill{{background:#388bfd33;color:#58a6ff;border-radius:12px;
      padding:2px 10px;font-size:.8rem;font-weight:600}}
.tag{{background:#21262d;border:1px solid #30363d;color:#79c0ff;
     padding:3px 10px;border-radius:20px;font-size:.82rem}}
.warn{{color:#f0883e}}
code{{background:#21262d;padding:1px 6px;border-radius:4px;font-size:.85rem}}
ul{{list-style:none;padding-left:0}}
ul li{{padding:4px 0;font-size:.9rem}}
footer{{text-align:center;color:#8b949e;font-size:.85rem;margin-top:30px;
       padding-top:20px;border-top:1px solid #30363d}}
@media(max-width:600px){{.stats{{grid-template-columns:repeat(2,1fr)}}}}
</style>
</head>
<body>
<div class="wrap">
  <!-- header -->
  <header>
    <h1>🔍 CYS-ILM Reconnaissance Report</h1>
    <p>Professional Security Assessment – Confidential</p>
  </header>

  <!-- metadata -->
  <div class="meta">
    <div class="meta-item"><div class="lbl">Target</div><div class="val">{meta.get('target')}</div></div>
    <div class="meta-item"><div class="lbl">Scan ID</div><div class="val" style="font-size:.9rem">{meta.get('scan_id')}</div></div>
    <div class="meta-item"><div class="lbl">Started</div><div class="val" style="font-size:.9rem">{meta.get('start_time','')[:19].replace('T',' ')}</div></div>
    <div class="meta-item">
      <div class="lbl">Risk Level</div>
      <div class="val" style="color:{rc}">{risk.get('risk_level','N/A')}
        <small style="font-size:.7rem;color:#8b949e"> ({risk.get('risk_score',0)}/100)</small>
      </div>
    </div>
    <div class="meta-item"><div class="lbl">Operator</div><div class="val">{meta.get('operator','N/A')}</div></div>
    <div class="meta-item"><div class="lbl">Privileged</div><div class="val">{"Yes" if meta.get("privileged") else "No"}</div></div>
  </div>

  <!-- stat cards -->
  <div class="stats">
    <div class="stat"><div class="num">{open_ports_count}</div><div class="lbl">Open Ports</div></div>
    <div class="stat"><div class="num">{sub_count}</div><div class="lbl">Subdomains</div></div>
    <div class="stat"><div class="num">{tech_count}</div><div class="lbl">Technologies</div></div>
    <div class="stat"><div class="num" style="color:#dc3545">{risk.get('high_count',0)}</div><div class="lbl">High Findings</div></div>
    <div class="stat"><div class="num" style="color:#fd7e14">{risk.get('medium_count',0)}</div><div class="lbl">Medium Findings</div></div>
    <div class="stat"><div class="num">{risk.get('total_findings',0)}</div><div class="lbl">Total Findings</div></div>
  </div>

  <!-- passive -->
  {"<div class='section'><h2>🕵️ Passive Reconnaissance</h2>" + passive_html + "</div>" if passive_html else ""}

  <!-- active -->
  {"<div class='section'><h2>⚡ Active Reconnaissance</h2>" + active_html + "</div>" if active_html else ""}

  <!-- findings -->
  {"<div class='section'><h2>⚠️ Findings &amp; Recommendations</h2>" + findings_html + "</div>" if findings_html else ""}

  <footer>
    <p>Generated by CYS-ILM Reconnaissance Tool v{meta.get('tool_version')}</p>
    <p>CYS-ILM Security Team — For Authorized Testing Only</p>
    <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
  </footer>
</div>
</body>
</html>"""
