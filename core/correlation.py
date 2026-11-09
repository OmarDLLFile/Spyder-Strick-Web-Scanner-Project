"""Vulnerability correlation + risk scoring + attack-path construction."""
from __future__ import annotations
from collections import defaultdict
from urllib.parse import urlparse

from core.finding import Finding
from core.taxonomy import lookup

CONFIDENCE_WEIGHT = {"confirmed": 1.0, "strong": 0.8, "potential": 0.5, "informational": 0.2}
SEVERITY_WEIGHT = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}


def risk_score(f: Finding) -> float:
    """0-10 score: CVSS approx + severity + confidence + exposure."""
    base = f.cvss if f.cvss is not None else SEVERITY_WEIGHT.get(f.severity, 5.0)
    conf = CONFIDENCE_WEIGHT.get(f.confidence, 0.5)
    score = base * (0.5 + 0.5 * conf)
    return round(min(10.0, max(0.0, score)), 1)


# Chains the correlator recognises (ordered type sequences).
CHAINS = [
    (["Missing Authentication", "Broken Object Level Authorization", "Excessive Data Exposure"],
     "Unauthenticated IDOR leading to data exposure"),
    (["Broken Object Level Authorization", "Excessive Data Exposure"],
     "IDOR leading to another user's data"),
    (["Missing Security Headers", "Cross-Site Scripting"],
     "Missing framing/CSP controls amplify XSS impact"),
    (["Cross-Site Scripting", "Insecure Cookie"],
     "XSS can steal session cookies lacking HttpOnly/Secure"),
    (["Missing Authentication", "Admin Interface Exposed"],
     "Unauthenticated access to an administrative interface"),
    (["SQL Injection", "Sensitive Data Exposure"],
     "Injection combined with sensitive data in responses"),
    (["Open Redirect", "Cross-Site Scripting"],
     "Open redirect usable to lend credibility to phishing / XSS delivery"),
    (["Server-Side Request Forgery", "Sensitive Data Exposure"],
     "SSRF can reach internal services and leak data"),
    (["JWT Weakness", "Broken Object Level Authorization"],
     "Weak JWT validation enables forged identities and IDOR"),
]


def correlate(findings):
    """Group by endpoint; detect attack paths where types chain on the same host/path."""
    by_endpoint = defaultdict(list)
    for f in findings:
        by_endpoint[urlparse(f.url).path or "/"].append(f)
    attack_paths = []
    for path, group in by_endpoint.items():
        types = [f.type for f in group]
        for chain, description in CHAINS:
            if all(t in types for t in chain):
                steps = [next(f for f in group if f.type == t) for t in chain]
                attack_paths.append({
                    "entry_point": steps[0].url,
                    "endpoint": path,
                    "description": description,
                    "steps": [{"type": s.type, "url": s.url, "severity": s.severity,
                               "confidence": s.confidence, "evidence": s.evidence[:300]} for s in steps],
                    "impact": " / ".join(s.type for s in steps),
                    "max_severity": max((s.severity for s in steps),
                                        key=lambda s: SEVERITY_WEIGHT.get(s, 0)),
                    "remediation": steps[-1].remediation or "Fix each step in the chain, starting with the entry point.",
                })
    # de-duplicate identical chains on the same endpoint
    seen, uniq = set(), []
    for ap in attack_paths:
        key = (ap["endpoint"], ap["description"])
        if key not in seen:
            seen.add(key)
            uniq.append(ap)
    return {"by_endpoint": {k: [f.to_dict() for f in v] for k, v in by_endpoint.items()},
            "attack_paths": uniq}
