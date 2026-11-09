"""Advanced injection / auth checks, all non-destructive and evidence-based:
NoSQL injection, command injection (safe echo markers only), SSTI (safe math
marker {{7*7}}), SSRF (potential only, never exfiltrates), JWT, CSRF,
sensitive-data exposure (values redacted), rate-limit probe.
"""
from __future__ import annotations
import base64, json, re, secrets
from urllib.parse import urlparse, parse_qs

from core.finding import Finding
from core.taxonomy import enrich
from scanners.common import build_param_url, redact, submit_form

SENSITIVE_PATTERNS = {
    "AWS access key": r"AKIA[0-9A-Z]{16}",
    "Private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Generic API key": r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    "Password in response": r"(?i)\"password\"\s*:\s*\"[^\"]{4,}\"",
    "JWT token": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "Credit card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b",
}


class AdvancedScanner:
    def __init__(self, requester):
        self.requester = requester

    # -- NoSQL -----------------------------------------------------------
    def scan_nosql(self, url):
        out = []
        for param in parse_qs(urlparse(url).query):
            for payload in ('{"$ne": ""}', '{"$gt": ""}', "' || '1'=='1"):
                resp = self.requester.get(build_param_url(url, param, payload))
                if resp and resp.status_code == 200 and len(resp.text or "") > 0:
                    # Only a *change* vs baseline counts as a strong indicator.
                    base = self.requester.get(url)
                    if base and resp.text != base.text:
                        f = Finding(type="NoSQL Injection", url=url, method="GET", param=param, payload=payload,
                                    evidence="Response differs from baseline for NoSQL operator payload (length "
                                             f"{len(resp.text)} vs {len(base.text)}); manual verification required.",
                                    severity="high", confidence="potential",
                                    remediation="Use typed queries / parameterised MongoDB queries; never pass raw user input as a query object.",
                                    scanner="advanced")
                        enrich(f); out.append(f); break
        return out

    # -- Command injection (safe markers only) ---------------------------
    def scan_command_injection(self, url):
        out = []
        marker = "spyder" + secrets.token_hex(3)
        for param in parse_qs(urlparse(url).query):
            for payload in (f"; echo {marker}", f"| echo {marker}", f"$(echo {marker})"):
                resp = self.requester.get(build_param_url(url, param, payload))
                if resp and marker in (resp.text or ""):
                    f = Finding(type="Command Injection", url=url, method="GET", param=param, payload=payload,
                                evidence=f"Echo marker '{marker}' appeared in response — input reaches a shell command.",
                                severity="critical", confidence="confirmed",
                                remediation="Never pass user input to a shell; use exec-file APIs with argument arrays.",
                                scanner="advanced")
                    enrich(f); out.append(f); break
        return out

    # -- SSTI (safe math marker) -----------------------------------------
    def scan_ssti(self, url):
        out = []
        for param in parse_qs(urlparse(url).query):
            resp = self.requester.get(build_param_url(url, param, "{{7*7}}"))
            if resp and "49" in (resp.text or "") and "{{7*7}}" not in resp.text:
                f = Finding(type="Server-Side Template Injection", url=url, method="GET", param=param,
                            payload="{{7*7}}",
                            evidence="Template expression {{7*7}} was evaluated to 49 in the response.",
                            severity="critical", confidence="strong",
                            remediation="Never render user input as a template; use logic-less templates with auto-escaping.",
                            scanner="advanced")
                enrich(f); out.append(f)
        return out

    # -- SSRF: potential only --------------------------------------------
    def scan_ssrf(self, url):
        out = []
        ssrf_params = {"url", "uri", "redirect", "next", "fetch", "src", "file", "image", "webhook"}
        for param in parse_qs(urlparse(url).query):
            if param.lower() not in ssrf_params:
                continue
            # Probe only the local metadata hostname string; we never fetch
            # internal resources or exfiltrate — a redirect/response difference
            # is reported as potential, for manual verification.
            resp = self.requester.get(build_param_url(url, param, "http://169.254.169.254/latest/meta-data/"))
            if resp and resp.status_code in (200, 302):
                f = Finding(type="Server-Side Request Forgery", url=url, method="GET", param=param,
                            payload="http://169.254.169.254/latest/meta-data/",
                            evidence=f"Server accepted an internal metadata URL in '{param}' (HTTP {resp.status_code}); "
                                     "verify manually whether the server fetched it — no internal data was retrieved by this scan.",
                            severity="high", confidence="potential",
                            remediation="Allowlist fetchable hosts, block RFC1918/link-local ranges, disable redirects on server-side fetches.",
                            scanner="advanced")
                enrich(f); out.append(f)
        return out

    # -- JWT ---------------------------------------------------------------
    def scan_jwt(self, url, response=None):
        out = []
        auth = (response.headers.get("Authorization") if response else "") or ""
        tokens = re.findall(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", (response.text if response else "") + " " + auth)
        for token in tokens:
            try:
                header_b64 = token.split(".")[0]
                header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
            except Exception:
                continue
            if header.get("alg") == "none":
                f = Finding(type="JWT Weakness", url=url, method="GET",
                            evidence="JWT uses alg=none (unsigned token accepted in response).",
                            severity="high", confidence="strong",
                            remediation="Reject alg=none; verify signatures with a strong algorithm (RS256/ES256) and a server-side key.",
                            scanner="advanced")
                enrich(f); out.append(f)
            elif header.get("alg") in ("HS256", "HS384", "HS512"):
                f = Finding(type="JWT Weakness", url=url, method="GET",
                            evidence=f"JWT uses symmetric {header.get('alg')}; verify the secret is strong and not shared/public.",
                            severity="medium", confidence="informational",
                            remediation="Use asymmetric signing where possible; rotate secrets; enforce exp/aud/iss validation.",
                            scanner="advanced")
                enrich(f); out.append(f)
        return out

    # -- CSRF / auth ---------------------------------------------------------
    def scan_csrf(self, page_url, forms):
        out = []
        for entry in forms:
            form = entry.get("form", entry) if isinstance(entry, dict) else entry
            if (form.get("method") or "get").lower() != "post":
                continue
            if not form.get("has_csrf_token"):
                f = Finding(type="Cross-Site Request Forgery", url=form.get("action") or page_url, method="POST",
                            evidence=f"POST form on {page_url} has no CSRF token field.",
                            severity="medium", confidence="potential",
                            remediation="Add per-session CSRF tokens to state-changing forms and validate them server-side.",
                            scanner="advanced")
                enrich(f); out.append(f)
        return out

    def scan_auth_forms(self, page_url, forms, response=None):
        out = []
        for entry in forms:
            form = entry.get("form", entry) if isinstance(entry, dict) else entry
            if form.get("is_login") and page_url.startswith("http://"):
                f = Finding(type="Insecure Authentication", url=page_url, method="GET",
                            evidence="Login form served over plain HTTP — credentials would be sent in cleartext.",
                            severity="high", confidence="confirmed",
                            remediation="Serve login over HTTPS only (HSTS) and set Secure cookies.", scanner="advanced")
                enrich(f); out.append(f)
        return out

    # -- Sensitive data ------------------------------------------------------
    def scan_sensitive_data(self, url, response):
        out = []
        if not response or not response.text:
            return out
        for name, pat in SENSITIVE_PATTERNS.items():
            m = re.search(pat, response.text)
            if m:
                # Never include the matched secret value in evidence — name the pattern only.
                f = Finding(type="Sensitive Data Exposure", url=url, method="GET",
                            evidence=f"Response contains a {name} pattern (matched value redacted; response length {len(response.text)} chars)",
                            severity="medium", confidence="potential",
                            remediation="Never return secrets/tokens in responses; rotate any exposed credential.",
                            scanner="advanced")
                enrich(f); out.append(f)
        return out

    # -- Rate limiting (light, informational) --------------------------------
    def scan_rate_limit(self, url):
        statuses = []
        for _ in range(6):
            resp = self.requester.get(url)
            statuses.append(resp.status_code if resp else None)
        if 429 not in statuses and 403 not in statuses:
            f = Finding(type="Rate Limiting Missing", url=url, method="GET",
                        evidence=f"6 rapid requests to {url} produced no 429/403 response (statuses: {statuses}).",
                        severity="medium", confidence="informational",
                        remediation="Add per-IP/per-user rate limiting and lockout on sensitive endpoints.",
                        scanner="advanced")
            enrich(f); return [f]
        return []
