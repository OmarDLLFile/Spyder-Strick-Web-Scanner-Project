"""Finding model: every vulnerability report carries evidence + confidence.

Confidence levels (never label 'confirmed' without response evidence):
  confirmed      - response proves the vulnerability (e.g. error text / reflected payload / file contents)
  strong         - strong indicator, e.g. boolean-blind difference or auth bypass on GET
  potential      - suspicious behaviour, needs manual verification
  informational  - hardening / exposure note, not a vulnerability by itself
"""
from __future__ import annotations
import hashlib, uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

CONFIDENCES = ("confirmed", "strong", "potential", "informational")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _norm_url(url: str) -> str:
    try:
        p = urlparse(url)
        qs = sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True))
        return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/") or "/", "", urlencode(qs), ""))
    except Exception:
        return url


@dataclass
class Finding:
    type: str
    title: str = ""
    url: str = ""
    method: str = "GET"
    param: str = ""
    payload: str = ""
    evidence: str = ""
    severity: str = "medium"
    cvss: float | None = None
    cwe: str = ""
    owasp: str = ""
    confidence: str = "potential"
    remediation: str = ""
    scanner: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self):
        self.severity = (self.severity or "medium").lower()
        if self.severity not in SEVERITIES:
            self.severity = "medium"
        self.confidence = (self.confidence or "potential").lower()
        if self.confidence not in CONFIDENCES:
            self.confidence = "potential"
        if not self.title:
            self.title = self.type
        # AI / humans must never upgrade to confirmed without evidence.
        if self.confidence == "confirmed" and not self.evidence:
            self.confidence = "potential"

    @property
    def dedup_key(self) -> str:
        raw = f"{self.type}|{_norm_url(self.url)}|{self.param or ''}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["dedup_key"] = self.dedup_key
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**d)


def dedupe(findings):
    """Drop duplicate findings (same type + normalised URL + param)."""
    seen, out = set(), []
    for f in findings:
        if isinstance(f, dict):
            f = Finding.from_dict(f)
        if f.dedup_key in seen:
            continue
        seen.add(f.dedup_key)
        out.append(f)
    return out
