"""Reports: JSON, CSV, HTML (executive + technical), and a static dashboard
built from scan history. Findings are Finding objects or plain dicts.
All user-controlled values are HTML-escaped.
"""
from __future__ import annotations
import csv, html, json, os
from datetime import datetime

from core.finding import Finding, dedupe
from core.correlation import correlate, risk_score
from core.taxonomy import enrich

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _norm(result):
    if isinstance(result, Finding):
        return result
    if isinstance(result, dict):
        if "type" in result:
            return Finding.from_dict({**result, "type": result.get("type", "Unknown")})
        return Finding(type=result.get("type", "Unknown"), title=str(result)[:120],
                       evidence=json.dumps(result, default=str)[:500])
    return Finding(type="Unknown", evidence=str(result)[:500])


class ReportGenerator:
    def __init__(self, report_dir="reports"):
        self.results = []          # Finding objects
        self.report_dir = report_dir
        self.target = ""
        self.ai_analysis = None
        self.correlation = None
        os.makedirs(self.report_dir, exist_ok=True)

    # -- backwards-compatible API ---------------------------------------
    def add_result(self, result):
        if result:
            self.results.append(_norm(result))

    def add_results(self, results):
        if isinstance(results, list):
            for r in results:
                self.add_result(r)
        elif results:
            self.add_result(results)

    def findings(self):
        return dedupe(self.results)

    def severity_counts(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _stamp(self):
        return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def _payload(self):
        findings = sorted(self.findings(), key=lambda f: (SEV_ORDER[f.severity], f.type))
        for f in findings:
            enrich(f)
        corr = self.correlation or correlate(findings)
        return {
            "generated_at": datetime.now().isoformat(),
            "target": self.target,
            "total_findings": len(findings),
            "severity_counts": self.severity_counts(),
            "attack_paths": corr["attack_paths"],
            "ai_analysis": self.ai_analysis,
            "findings": [{**f.to_dict(), "risk_score": risk_score(f)} for f in findings],
        }

    def generate_json_report(self, filename=None):
        path = os.path.join(self.report_dir, filename or f"report_{self._stamp()}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self._payload(), fh, indent=2, ensure_ascii=False)
        print(f"[+] JSON Report Saved: {path}")
        return path

    def generate_csv_report(self, filename=None):
        path = os.path.join(self.report_dir, filename or f"report_{self._stamp()}.csv")
        fields = ["id", "type", "title", "severity", "cvss", "cwe", "owasp", "confidence",
                  "risk_score", "url", "method", "param", "payload", "evidence", "remediation", "scanner"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for f in sorted(self.findings(), key=lambda x: SEV_ORDER[x.severity]):
                row = f.to_dict(); row["risk_score"] = risk_score(f)
                w.writerow({k: row.get(k, "") for k in fields})
        print(f"[+] CSV Report Saved: {path}")
        return path

    def generate_html_report(self, filename=None):
        path = os.path.join(self.report_dir, filename or f"report_{self._stamp()}.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.build_html_report())
        print(f"[+] HTML Report Saved: {path}")
        return path

    def build_html_report(self):
        data = self._payload()
        esc = html.escape
        counts = data["severity_counts"]
        rows = ""
        for f in data["findings"]:
            rows += (f'<div class="card {esc(f["severity"])}"><h3>{esc(f["title"])}</h3>'
                     f'<p><b>Severity:</b> {esc(f["severity"])} | <b>CVSS≈:</b> {f["cvss"]} | '
                     f'<b>CWE:</b> {esc(str(f["cwe"]))} | <b>OWASP:</b> {esc(str(f["owasp"]))} | '
                     f'<b>Confidence:</b> {esc(f["confidence"])} | <b>Risk:</b> {f["risk_score"]}</p>'
                     f'<p><b>URL:</b> {esc(f["url"])} <b>Method:</b> {esc(f["method"])} '
                     f'<b>Param:</b> {esc(str(f["param"]))}</p>'
                     f'<p><b>Payload:</b> <code>{esc(str(f["payload"]))}</code></p>'
                     f'<p><b>Evidence:</b></p><pre>{esc(str(f["evidence"]))}</pre>'
                     f'<p><b>Remediation:</b> {esc(str(f["remediation"]))}</p></div>')
        paths = ""
        for ap in data["attack_paths"]:
            steps = " → ".join(esc(s["type"]) for s in ap["steps"])
            paths += f'<div class="card high"><h3>Attack path: {esc(ap["description"])}</h3><p>{steps}</p><p>Entry: {esc(ap["entry_point"])}</p></div>'
        ai = ""
        if data["ai_analysis"]:
            ai = f'<h2>AI Analysis</h2><pre>{esc(json.dumps(data["ai_analysis"], indent=2, ensure_ascii=False))}</pre>'
        return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Spyder-Strick Report — {esc(data["target"])}</title><style>
body{{background:#111;color:#eee;font-family:Arial;padding:20px}}h1{{color:#00ff99}}
.card{{background:#1b1b1b;border:1px solid #333;padding:15px;margin-bottom:15px;border-radius:10px}}
.critical{{border-left:5px solid #ff0044}}.high{{border-left:5px solid red}}
.medium{{border-left:5px solid orange}}.low{{border-left:5px solid yellow}}.info{{border-left:5px solid #888}}
pre{{white-space:pre-wrap;word-wrap:break-word}}</style></head><body>
<h1>Spyder-Strick Security Assessment Report</h1>
<p><b>Target:</b> {esc(data["target"])} &nbsp; <b>Generated:</b> {esc(data["generated_at"])}</p>
<h2>Executive Summary</h2>
<p>Total findings: {data["total_findings"]} — Critical {counts["critical"]}, High {counts["high"]},
Medium {counts["medium"]}, Low {counts["low"]}, Info {counts["info"]}.
Attack paths identified: {len(data["attack_paths"])}.</p>
<h2>Methodology &amp; Scope</h2><p>Authorized crawl + non-destructive dynamic testing
(SQLi/XSS/traversal/redirect/header/API/enterprise checks), SAST where requested, and
optional AI correlation. Destructive payloads are never sent. Findings are evidence-based;
confidence is confirmed only where a response proves the issue.</p>
<h2>Limitations</h2><p>No headless-browser JS execution (static JS analysis only);
no authenticated SSO flow testing beyond safe GET probes; AI output is advisory only.</p>
<h2>Attack Paths</h2>{paths or "<p>None identified.</p>"}{ai}
<h2>Detailed Findings</h2>{rows or "<p>No findings.</p>"}</body></html>"""

    def generate_all(self):
        return {"json": self.generate_json_report(),
                "html": self.generate_html_report(),
                "csv": self.generate_csv_report()}

    def calculate_severity(self, result):
        f = _norm(result)
        return f.severity.upper()

    def print_summary(self):
        counts = self.severity_counts()
        print("\n========== Scan Summary ==========")
        print(f"Total Findings: {len(self.findings())}")
        for k, v in counts.items():
            print(f"{k.upper():8} {v}")
        print("==================================")


def build_dashboard(store_path="reports/spyder.db", out_path="reports/dashboard.html"):
    """Static dashboard from SQLite history; inline SVG bar chart, no external JS."""
    from core.store import ScanStore
    store = ScanStore(store_path)
    scans = store.list_scans(20)
    total_scans = len(scans)
    total_findings = sum(s["total_findings"] for s in scans)
    crit = sum(s["critical"] for s in scans); high = sum(s["high"] for s in scans)
    rows = ""
    for s in scans:
        rows += (f"<tr><td>{s['id']}</td><td>{html.escape(s['target'] or '')}</td>"
                 f"<td>{html.escape(str(s['started_at']))}</td><td>{s['total_findings']}</td>"
                 f"<td>{s['critical']}</td><td>{s['high']}</td></tr>")
    # most vulnerable endpoints from latest scan
    endpoints = ""
    if scans:
        from collections import Counter
        c = Counter()
        for f in store.findings_for_scan(scans[0]["id"]):
            c[f["url"]] += 1
        for url, n in c.most_common(10):
            endpoints += f"<li>{html.escape(url)} — {n} finding(s)</li>"
    store.close()
    maxv = max(crit, high, 1)
    svg = (f'<svg width="400" height="80"><rect x="10" y="10" width="{300*crit/maxv:.0f}" height="20" fill="#ff0044"/>'
           f'<text x="10" y="55" fill="#eee">Critical: {crit}</text>'
           f'<rect x="10" y="30" width="{300*high/maxv:.0f}" height="20" fill="red"/>'
           f'<text x="10" y="75" fill="#eee">High: {high}</text></svg>')
    doc = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Spyder-Strick Dashboard</title>
<style>body{{background:#111;color:#eee;font-family:Arial;padding:20px}}table{{border-collapse:collapse}}td,th{{border:1px solid #444;padding:6px}}</style></head>
<body><h1>Spyder-Strick Dashboard</h1>
<p>Total scans: {total_scans} &nbsp; Total findings: {total_findings}</p>{svg}
<h2>Recent scans</h2><table><tr><th>ID</th><th>Target</th><th>Started</th><th>Findings</th><th>Critical</th><th>High</th></tr>{rows}</table>
<h2>Most vulnerable endpoints (latest scan)</h2><ul>{endpoints or "<li>—</li>"}</ul></body></html>"""
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return out_path
