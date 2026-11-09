"""API security: OpenAPI/Swagger parsing, BOLA/IDOR (safe GETs, ID variation),
missing auth, mass-assignment probe, GraphQL introspection, excessive data
exposure. Non-destructive: no state-changing requests except a single
extra-field POST only when --authorize and intensity allows (opt-in via
`allow_write_probe`); by default write probes are skipped.
"""
from __future__ import annotations
import json, re
from urllib.parse import urljoin, urlparse

from core.finding import Finding
from core.taxonomy import enrich
from scanners.common import redact

SENSITIVE_KEYS = ("password", "ssn", "credit_card", "api_key", "secret", "token", "email", "phone")


class APIScanner:
    def __init__(self, requester, allow_write_probe: bool = False):
        self.requester = requester
        self.allow_write_probe = allow_write_probe

    def load_spec(self, url_or_path: str):
        """Load an OpenAPI spec from a URL (in-scope) or a local file."""
        if url_or_path.startswith(("http://", "https://")):
            resp = self.requester.get(url_or_path)
            if not resp:
                return None
            try:
                return resp.json()
            except Exception:
                return None
        with open(url_or_path, encoding="utf-8") as fh:
            text = fh.read()
            try:
                return json.loads(text)
            except Exception:
                try:
                    import yaml
                    return yaml.safe_load(text)
                except Exception:
                    return None

    def endpoints_from_spec(self, spec, base_url):
        out = []
        if not isinstance(spec, dict):
            return out
        for path, ops in (spec.get("paths") or {}).items():
            for method in (ops or {}):
                out.append({"url": urljoin(base_url, path), "method": method.upper(), "path": path})
        return out

    def scan_endpoints(self, endpoints, base_url):
        findings = []
        for ep in endpoints:
            url, method = ep["url"], ep.get("method", "GET")
            if method != "GET":
                continue
            try:
                findings.extend(self._test_missing_auth(url))
                findings.extend(self._test_bola(url))
                findings.extend(self._test_excessive_data(url))
            except Exception:
                continue  # one endpoint failing must never kill the scan
        return findings

    def _test_missing_auth(self, url):
        resp = self.requester.get(url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            if any(k in body.lower() for k in SENSITIVE_KEYS) and len(body) > 100:
                f = Finding(type="Missing Authentication", url=url, method="GET",
                            evidence=f"Unauthenticated GET returned 200 with sensitive-looking keys ({len(body)} bytes).",
                            severity="high", confidence="strong",
                            remediation="Require authentication on all API endpoints; return 401 without a valid token.",
                            scanner="api")
                enrich(f); return [f]
        return []

    def _test_bola(self, url):
        """Vary a numeric ID in the path; a different user's data (different
        body, same 200) is a strong IDOR indicator. Only safe GETs."""
        parsed = urlparse(url)
        m = re.search(r"/(\d+)(/|$)", parsed.path)
        if not m:
            return []
        orig_id = m.group(1)
        other_id = "1" if orig_id != "1" else "2"
        # Replace only in the path — never in the host (e.g. 127.0.0.1 contains "1").
        new_path = re.sub(r"/\d+(/|$)", f"/{other_id}\\1", parsed.path, count=1)
        other_url = parsed._replace(path=new_path).geturl()
        if other_url == url:
            return []
        r1 = self.requester.get(url)
        r2 = self.requester.get(other_url)
        if r1 and r2 and r1.status_code == 200 and r2.status_code == 200 and r1.text != r2.text:
            # Different content for a different ID without auth change.
            if any(k in (r2.text or "").lower() for k in ("email", "name", "user", "account")):
                f = Finding(type="Broken Object Level Authorization", url=other_url, method="GET", param="id",
                            evidence=f"Changing object ID {orig_id} -> {other_id} returned different user-like data (200, "
                                     f"{len(r2.text)} bytes) with no authorization change.",
                            severity="high", confidence="strong",
                            remediation="Enforce per-object authorization: verify the caller owns the requested object.",
                            scanner="api")
                enrich(f); return [f]
        return []

    def _test_excessive_data(self, url):
        resp = self.requester.get(url)
        if not resp or resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except Exception:
            return []
        flat = json.dumps(data).lower()
        hits = [k for k in SENSITIVE_KEYS if k in flat]
        if len(flat) > 5000 and len(hits) >= 3:
            f = Finding(type="Excessive Data Exposure", url=url, method="GET",
                        evidence=f"API response ({len(flat)} chars) exposes sensitive fields: {', '.join(hits)}.",
                        severity="medium", confidence="potential",
                        remediation="Return only the fields the client needs; use DTOs / field filtering.",
                        scanner="api")
            enrich(f); return [f]
        return []

    def scan_graphql(self, endpoint_url):
        """Introspection query — only if a GraphQL endpoint was discovered."""
        query = {"query": "{ __schema { types { name } } }"}
        try:
            resp = self.requester.post(endpoint_url, json=query)
        except Exception:
            return []
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                return []
            if isinstance(data, dict) and "data" in data and data["data"]:
                f = Finding(type="GraphQL Introspection Enabled", url=endpoint_url, method="POST",
                            evidence=f"Introspection query returned schema data ({str(data)[:200]}).",
                            severity="medium", confidence="confirmed",
                            remediation="Disable introspection in production; require authentication.",
                            scanner="api")
                enrich(f); return [f]
        return []

    def scan_mass_assignment(self, url):
        """Only when allow_write_probe is True (explicit, authorised)."""
        if not self.allow_write_probe:
            return []
        resp = self.requester.post(url, json={"role": "admin", "is_admin": True, "spyder_probe": True})
        if resp and resp.status_code in (200, 201):
            f = Finding(type="Mass Assignment", url=url, method="POST", param="role/is_admin",
                        evidence=f"POST with extra fields 'role'/'is_admin' accepted (HTTP {resp.status_code}). "
                                 "Verify whether the fields were persisted — do not rely on this alone.",
                        severity="medium", confidence="potential",
                        remediation="Use an allowlist of bindable fields; never bind request bodies directly to models.",
                        scanner="api")
            enrich(f); return [f]
        return []
