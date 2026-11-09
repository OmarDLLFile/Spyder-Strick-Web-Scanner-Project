"""Reflected + stored XSS via a unique marker (no alert() execution needed:
reflection of the marker in an executable context is the evidence).
Per-input testing; DOM-based XSS is out of scope without a JS engine (see README).
"""
from __future__ import annotations
import secrets
from urllib.parse import urljoin, urlparse, parse_qs

from core.finding import Finding
from core.taxonomy import enrich
from scanners.common import submit_form, build_param_url

REMEDIATION = "Context-encode all user input on output, set a strict Content-Security-Policy, and use framework auto-escaping."


class XSS_Scanner:
    def __init__(self, requester):
        self.requester = requester
        self.payloads = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
                         "'><svg onload=alert(1)>"]

    def _marker(self):
        return "spyderxss" + secrets.token_hex(4)

    def _check(self, response, url, method, param, payload, marker):
        if not response or not response.text:
            return None
        if marker in response.text:
            f = Finding(type="Cross-Site Scripting", url=url, method=method, param=param, payload=payload,
                        evidence=f"Unique marker '{marker}' reflected verbatim in response (HTTP {response.status_code})",
                        severity="medium", confidence="strong", remediation=REMEDIATION, scanner="xss")
            enrich(f)
            return f
        return None

    def scan_form(self, url, form):
        findings = []
        target = urljoin(url, form.get("action") or "") or url
        method = (form.get("method") or "get").upper()
        fields = [i for i in form.get("inputs", []) if i.get("name") and i.get("type") != "submit"]
        if not fields:
            return findings
        for field in fields:  # per-input, not all-at-once
            marker = self._marker()
            payload = f"<script>{marker}</script>"
            data = {i["name"]: ("test" if i["name"] != field["name"] else payload) for i in fields}
            try:
                resp = submit_form(self.requester, url, form, data)
            except Exception:
                continue
            f = self._check(resp, target, method, field["name"], payload, marker)
            if f:
                findings.append(f)
                # stored check: re-fetch the page; marker still present => stored
                try:
                    again = self.requester.get(target)
                    if again and marker in (again.text or ""):
                        f2 = Finding(type="Stored Cross-Site Scripting", url=target, method=method,
                                     param=field["name"], payload=payload,
                                     evidence=f"Marker '{marker}' persisted across a fresh GET of {target}",
                                     severity="high", confidence="strong",
                                     remediation=REMEDIATION, scanner="xss")
                        enrich(f2); findings.append(f2)
                except Exception:
                    pass
        return findings

    def scan_url(self, url):
        findings = []
        for param in parse_qs(urlparse(url).query):
            marker = self._marker()
            payload = f"<script>{marker}</script>"
            resp = self.requester.get(build_param_url(url, param, payload))
            f = self._check(resp, url, "GET", param, payload, marker)
            if f:
                findings.append(f)
        return findings
