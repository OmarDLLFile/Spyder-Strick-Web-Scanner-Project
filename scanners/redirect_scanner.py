"""Open redirect via the shared Requester (no raw requests, scope enforced)."""
from __future__ import annotations
from urllib.parse import urlparse, parse_qs

from core.finding import Finding
from core.taxonomy import enrich
from scanners.common import build_param_url

REDIRECT_PARAMS = {"next", "url", "redirect", "redirect_url", "redir", "return",
                   "return_url", "continue", "dest", "destination"}
PAYLOADS = ["https://evil.example", "//evil.example", "https:evil.example"]
REMEDIATION = "Validate redirect targets against an allowlist of local paths; never redirect to user-supplied absolute URLs."


class OpenRedirectScanner:
    def __init__(self, requester):
        self.requester = requester
        self.payloads = PAYLOADS
        self.redirect_params = sorted(REDIRECT_PARAMS)

    def scan_url(self, url):
        findings = []
        for param in parse_qs(urlparse(url).query):
            if param.lower() not in REDIRECT_PARAMS:
                continue
            for payload in self.payloads:
                test_url = build_param_url(url, param, payload)
                try:
                    resp = self.requester.get(test_url, allow_redirects=False)
                except Exception:
                    continue
                if not resp:
                    continue
                loc = resp.headers.get("Location", "")
                if loc and "evil.example" in loc:
                    f = Finding(type="Open Redirect", url=test_url, method="GET", param=param, payload=payload,
                                evidence=f"Location header redirects to attacker-controlled host: {loc} (HTTP {resp.status_code})",
                                severity="medium", confidence="confirmed", remediation=REMEDIATION, scanner="redirect")
                    enrich(f); findings.append(f)
        return findings
