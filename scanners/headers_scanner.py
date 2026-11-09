"""Security headers + cookies + clickjacking + CORS checks. Returns Findings."""
from __future__ import annotations
from core.finding import Finding
from core.taxonomy import enrich

REQUIRED_HEADERS = ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security",
                    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
REMEDIATION = ("Set missing headers: Content-Security-Policy, X-Frame-Options: DENY (or CSP frame-ancestors), "
               "Strict-Transport-Security, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy.")


class HeaderScanner:
    REQUIRED_HEADERS = REQUIRED_HEADERS

    def __init__(self, requester=None):
        self.requester = requester

    def scan(self, response):
        """Backwards-compatible: return list of missing header names."""
        if not response:
            return []
        return [h for h in REQUIRED_HEADERS if h not in response.headers]

    def scan_findings(self, url, response):
        findings = []
        if not response:
            return findings
        missing = self.scan(response)
        if missing:
            f = Finding(type="Missing Security Headers", url=url, method="GET",
                        evidence=f"Missing headers: {', '.join(missing)} (HTTP {response.status_code})",
                        severity="low", confidence="confirmed", remediation=REMEDIATION, scanner="headers")
            enrich(f); findings.append(f)
        # Clickjacking: neither X-Frame-Options nor CSP frame-ancestors
        csp = response.headers.get("Content-Security-Policy", "")
        if "X-Frame-Options" not in response.headers and "frame-ancestors" not in csp:
            f = Finding(type="Clickjacking", url=url, method="GET",
                        evidence="No X-Frame-Options header and no CSP frame-ancestors directive",
                        severity="low", confidence="confirmed",
                        remediation="Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.", scanner="headers")
            enrich(f); findings.append(f)
        # HSTS only meaningful over HTTPS; flag weak value
        hsts = response.headers.get("Strict-Transport-Security", "")
        if url.startswith("https://") and hsts and "max-age=0" in hsts:
            f = Finding(type="Missing Security Headers", url=url, method="GET", param="Strict-Transport-Security",
                        evidence="HSTS max-age=0 disables HSTS", severity="low", confidence="confirmed",
                        remediation=REMEDIATION, scanner="headers")
            enrich(f); findings.append(f)
        return findings

    def scan_cookies(self, url, response):
        findings = []
        if not response:
            return findings
        for cookie in response.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure")
            if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie._rest).lower():
                issues.append("missing HttpOnly")
            if "samesite" not in str(cookie._rest).lower():
                issues.append("missing SameSite")
            if issues:
                f = Finding(type="Insecure Cookie", url=url, method="GET", param=cookie.name,
                            evidence=f"Cookie '{cookie.name}': {', '.join(issues)}",
                            severity="low", confidence="confirmed",
                            remediation="Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
                            scanner="headers")
                enrich(f); findings.append(f)
        return findings

    def scan_cors(self, url, response=None):
        """Origin-reflection check: send a cross-origin Origin header; reflection + credentials = misconfig."""
        findings = []
        try:
            resp = self.requester.get(url, headers={"Origin": "https://evil.example"}) if hasattr(self, "requester") else None
        except Exception:
            return findings
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            if acao == "https://evil.example" and creds:
                f = Finding(type="CORS Misconfiguration", url=url, method="GET",
                            evidence="Access-Control-Allow-Origin reflects arbitrary Origin and Allow-Credentials is true",
                            severity="medium", confidence="confirmed",
                            remediation="Allowlist trusted origins; never reflect Origin with credentials.",
                            scanner="headers")
                enrich(f); findings.append(f)
            elif acao == "*":
                f = Finding(type="CORS Misconfiguration", url=url, method="GET",
                            evidence="Access-Control-Allow-Origin: *", severity="low", confidence="potential",
                            remediation="Restrict CORS to trusted origins.", scanner="headers")
                enrich(f); findings.append(f)
        return findings
