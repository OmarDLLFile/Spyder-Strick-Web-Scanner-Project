"""Enterprise auth / tenant checks — safe GET probes only.

Detects SSO/SAML/OAuth/OIDC discovery endpoints, admin interface exposure,
cross-tenant IDOR (same safe BOLA logic as the API scanner), and reports
weak-SSO items as an informational checklist (actively testing a SAML
response signature is out of scope for a non-destructive scan).
"""
from __future__ import annotations
from urllib.parse import urljoin

from core.finding import Finding
from core.taxonomy import enrich
from scanners.api_scanner import APIScanner

SSO_PATHS = ["/.well-known/openid-configuration", "/saml", "/adfs", "/oauth/authorize",
             "/oauth2/authorize", "/login/sso", "/sso", "/auth/saml", "/.well-known/saml"]
ADMIN_PATHS = ["/admin", "/admin/", "/dashboard", "/management", "/console", "/internal"]


class EnterpriseScanner:
    def __init__(self, requester):
        self.requester = requester
        self._api = APIScanner(requester)

    def scan_sso_discovery(self, base_url):
        findings, found = [], []
        for path in SSO_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = self.requester.get(url)
            except Exception:
                continue
            if resp and resp.status_code == 200:
                found.append(path)
        if found:
            f = Finding(type="SSO Misconfiguration", url=base_url, method="GET",
                        evidence=f"SSO/identity discovery endpoints reachable: {', '.join(found)}. "
                                 "Review: enforce MFA, validate SAML/OIDC signatures, restrict redirect URIs. "
                                 "Signature validation was NOT actively tested (out of scope for safe scanning).",
                        severity="medium", confidence="informational",
                        remediation="Harden SSO: require MFA, validate signatures/audiences, allowlist redirect URIs, monitor SSO failures.",
                        scanner="enterprise")
            enrich(f); findings.append(f)
        return findings

    def scan_admin_exposure(self, base_url):
        findings = []
        for path in ADMIN_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = self.requester.get(url, allow_redirects=False)
            except Exception:
                continue
            if resp and resp.status_code == 200 and len(resp.text or "") > 50:
                body = (resp.text or "").lower()
                if any(k in body for k in ("admin", "dashboard", "management", "user")):
                    f = Finding(type="Admin Interface Exposed", url=url, method="GET",
                                evidence=f"Admin path {path} returned 200 without authentication ({len(resp.text)} bytes, admin-like content).",
                                severity="high", confidence="strong",
                                remediation="Require authentication + RBAC on admin interfaces; restrict by network/IP where possible.",
                                scanner="enterprise")
                    enrich(f); findings.append(f)
        return findings

    def scan_cross_tenant(self, url):
        """Vary tenant_id / org id query params; different tenant data = strong indicator."""
        from urllib.parse import urlparse, parse_qs
        from scanners.common import build_param_url
        findings = []
        for param in parse_qs(urlparse(url).query):
            if param.lower() not in ("tenant_id", "tenant", "org_id", "organization_id", "customer_id"):
                continue
            r1 = self.requester.get(url)
            r2 = self.requester.get(build_param_url(url, param, "999999"))
            if r1 and r2 and r1.status_code == 200 and r2.status_code == 200 and r1.text != r2.text:
                f = Finding(type="Cross-Tenant Data Exposure", url=url, method="GET", param=param,
                            evidence=f"Changing {param} returned different data (200) with no authorization change.",
                            severity="high", confidence="strong",
                            remediation="Enforce tenant isolation server-side: always scope queries to the caller's tenant.",
                            scanner="enterprise")
                enrich(f); findings.append(f)
        return findings
