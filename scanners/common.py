"""Shared scanner helpers: safe payload loading, form submission, redaction."""
from __future__ import annotations
import os, re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# Never sent, even if present in payloads/*.txt
FORBIDDEN = ("drop table", "delete from", "update ", "insert into", "xp_cmdshell",
             "shutdown", "sleep(", "pg_sleep", "benchmark(", "waitfor delay", "exec ",
             "rm -rf", "os.system", "; rm", "format c:")

SECRET_RE = re.compile(r"(?i)(api[_-]?key|password|secret|token|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./]{8,})")


def redact(text: str) -> str:
    """Redact secret-looking values from evidence before storing/reporting."""
    if not text:
        return ""
    return SECRET_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", str(text))[:2000]


def load_payloads(path: str, limit: int = 20):
    """Load payloads from a file, dropping destructive / time-based entries."""
    payloads = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                p = line.strip()
                if not p or p.startswith("#"):
                    continue
                if any(f in p.lower() for f in FORBIDDEN):
                    continue
                payloads.append(p)
    except FileNotFoundError:
        pass
    return payloads[:limit]


def payloads_dir():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "payloads")


def submit_form(requester, page_url, form, data: dict):
    """Submit a form correctly for its method — GET sends data as query params (the old SQLi bug)."""
    target = urljoin(page_url, form.get("action") or "") or page_url
    method = (form.get("method") or "get").lower()
    if method == "post":
        return requester.post(target, data=data)
    return requester.get(target, params=data)


def build_param_url(url, param, value):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    return parsed._replace(query=urlencode(qs, doseq=True)).geturl()


def form_field_values(form, payload):
    data = {}
    for inp in form.get("inputs", []):
        name = inp.get("name")
        if not name or inp.get("type") == "submit":
            continue
        data[name] = inp.get("value") or payload if inp.get("type") in ("hidden",) else payload
    return data
