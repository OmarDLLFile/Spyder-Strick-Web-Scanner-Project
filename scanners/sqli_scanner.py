"""SQL injection: error-based + boolean-based blind (true/false comparison).
Safe payloads only — destructive entries from payloads/sqli.txt are filtered
out by scanners.common.load_payloads. Returns Finding objects.
"""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse, parse_qs

from core.finding import Finding
from core.taxonomy import enrich
from scanners.common import load_payloads, payloads_dir, submit_form, build_param_url

SQL_ERRORS = {
    "MySQL": [r"you have an error in your sql syntax", r"warning.*mysql", r"mysql_fetch", r"mysql_num_rows"],
    "PostgreSQL": [r"postgresql.*error", r"warning.*pg_", r"pg_query"],
    "MSSQL": [r"unclosed quotation mark", r"microsoft sql server", r"odbc sql server driver"],
    "SQLite": [r"sqlite error", r"sqlite3\.operationalerror"],
    "Oracle": [r"oracle error", r"ora-\d+"],
}
DEFAULT_PAYLOADS = ["'", '"', "' OR '1'='1", '" OR "1"="1', "'--", "' OR 1=1 --"]
REMEDIATION = "Use parameterised queries / prepared statements everywhere; never build SQL by string concatenation; apply least-privilege DB accounts."


class SQLiScanner:
    def __init__(self, requester, limit: int = 8):
        self.requester = requester
        self.payloads = load_payloads(f"{payloads_dir()}/sqli.txt", limit) or DEFAULT_PAYLOADS
        self.sql_errors = SQL_ERRORS

    def detect_sql_errors(self, html):
        html = (html or "").lower()
        for dbms, patterns in self.sql_errors.items():
            for pat in patterns:
                if re.search(pat, html):
                    return dbms, pat
        return None, None

    def _check_response(self, response, url, method, param, payload):
        if not response or not response.text:
            return None
        dbms, pat = self.detect_sql_errors(response.text)
        if dbms:
            f = Finding(type="SQL Injection", url=url, method=method, param=param, payload=payload,
                        evidence=f"DB error pattern '{pat}' matched ({dbms}); HTTP {response.status_code}",
                        severity="high", confidence="confirmed",
                        remediation=REMEDIATION, scanner="sqli")
            enrich(f)
            return f
        return None

    def scan_form(self, url, form):
        findings, seen = [], set()
        method = (form.get("method") or "get").upper()
        target = urljoin(url, form.get("action") or "") or url
        for payload in self.payloads:
            data = {i["name"]: payload for i in form.get("inputs", [])
                    if i.get("name") and i.get("type") != "submit"}
            if not data:
                continue
            try:
                resp = submit_form(self.requester, url, form, data)
            except Exception:
                continue
            for param in data:
                f = self._check_response(resp, target, method, param, payload)
                if f and f.dedup_key not in seen:
                    seen.add(f.dedup_key); findings.append(f)
            # boolean-based blind: true vs false condition must differ
            blind = self._blind_check(url, form, data)
            findings.extend(blind)
        return findings

    def _blind_check(self, url, form, data):
        """One true/false pair per form; confirmed only if responses differ consistently."""
        out = []
        try:
            true_data = dict(data); false_data = dict(data)
            key = next(iter(data))
            true_data[key] = "1' AND '1'='1"
            false_data[key] = "1' AND '1'='2"
            r_true = submit_form(self.requester, url, form, true_data)
            r_false = submit_form(self.requester, url, form, false_data)
            if r_true and r_false and r_true.text != r_false.text:
                # baseline: repeat true to rule out dynamic content
                r_true2 = submit_form(self.requester, url, form, true_data)
                if r_true2 and r_true2.text == r_true.text:
                    f = Finding(type="Blind SQL Injection", url=urljoin(url, form.get("action") or ""),
                                method=(form.get("method") or "get").upper(), param=key,
                                payload="1' AND '1'='1 vs 1' AND '1'='2",
                                evidence=f"True-condition response ({len(r_true.text)} bytes) differs from "
                                         f"false-condition response ({len(r_false.text)} bytes); repeat true matches.",
                                severity="high", confidence="strong", remediation=REMEDIATION, scanner="sqli")
                    enrich(f); out.append(f)
        except Exception:
            pass
        return out

    def scan_url(self, url):
        """Test query params of a URL directly."""
        findings = []
        params = parse_qs(urlparse(url).query)
        for param in params:
            for payload in self.payloads[:4]:
                test_url = build_param_url(url, param, payload)
                resp = self.requester.get(test_url)
                f = self._check_response(resp, test_url, "GET", param, payload)
                if f:
                    findings.append(f)
        return findings
