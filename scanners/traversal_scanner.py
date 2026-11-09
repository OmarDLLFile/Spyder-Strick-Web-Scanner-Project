"""Local File Inclusion / path traversal via the shared Requester (scope + rate limit)."""
from __future__ import annotations
from urllib.parse import urlparse, parse_qs

from core.finding import Finding
from core.taxonomy import enrich
from scanners.common import load_payloads, payloads_dir, build_param_url, redact

INDICATORS = {"Linux": ["root:x:", "/bin/bash", "/usr/sbin"],
              "Windows": ["[extensions]", "for 16-bit app support", "[fonts]"]}
REMEDIATION = "Never use user input in file paths; use an allowlist of files, canonicalise paths and enforce a base directory."


class DirectoryTraversalScanner:
    def __init__(self, requester, limit: int = 8):
        self.requester = requester
        self.payloads = load_payloads(f"{payloads_dir()}/traversal.txt", limit) or [
            "../../../../../../etc/passwd", "/etc/passwd"]

    def scan_url(self, url):
        findings = []
        for param in parse_qs(urlparse(url).query):
            for payload in self.payloads:
                test_url = build_param_url(url, param, payload)
                try:
                    resp = self.requester.get(test_url)
                except Exception:
                    continue
                if not resp or not resp.text:
                    continue
                for os_name, indicators in INDICATORS.items():
                    for ind in indicators:
                        if ind.lower() in resp.text.lower():
                            f = Finding(type="Directory Traversal", url=test_url, method="GET", param=param,
                                        payload=payload, evidence=f"Indicator '{ind}' ({os_name}) in response, HTTP {resp.status_code}",
                                        severity="high", confidence="confirmed", remediation=REMEDIATION,
                                        scanner="traversal")
                            enrich(f); findings.append(f); break
                    else:
                        continue
                    break
        return findings
