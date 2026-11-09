"""OWASP / CWE / CVSS-approx / MITRE ATT&CK mapping table.

CVSS values here are *approximate base scores for the vulnerability class*,
used only for prioritisation; they are not a full CVSS 4.0 vector calculation.
"""
from __future__ import annotations

TAXONOMY = {
    "SQL Injection": {"cwe": "CWE-89", "owasp": "A03:2021 Injection", "cvss": 8.6, "severity": "high", "attack": "T1190"},
    "Blind SQL Injection": {"cwe": "CWE-89", "owasp": "A03:2021 Injection", "cvss": 8.6, "severity": "high", "attack": "T1190"},
    "NoSQL Injection": {"cwe": "CWE-943", "owasp": "A03:2021 Injection", "cvss": 8.6, "severity": "high", "attack": "T1190"},
    "Cross-Site Scripting": {"cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 6.1, "severity": "medium", "attack": "T1189"},
    "Stored Cross-Site Scripting": {"cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 7.2, "severity": "high", "attack": "T1189"},
    "Directory Traversal": {"cwe": "CWE-22", "owasp": "A01:2021 Broken Access Control", "cvss": 7.5, "severity": "high", "attack": "T1083"},
    "Local File Inclusion": {"cwe": "CWE-98", "owasp": "A01:2021 Broken Access Control", "cvss": 7.5, "severity": "high", "attack": "T1083"},
    "Open Redirect": {"cwe": "CWE-601", "owasp": "A01:2021 Broken Access Control", "cvss": 6.1, "severity": "medium", "attack": "T1566"},
    "Server-Side Template Injection": {"cwe": "CWE-94", "owasp": "A03:2021 Injection", "cvss": 9.8, "severity": "critical", "attack": "T1190"},
    "Command Injection": {"cwe": "CWE-78", "owasp": "A03:2021 Injection", "cvss": 9.8, "severity": "critical", "attack": "T1059"},
    "Server-Side Request Forgery": {"cwe": "CWE-918", "owasp": "A10:2021 SSRF", "cvss": 8.6, "severity": "high", "attack": "T1090"},
    "Missing Security Headers": {"cwe": "CWE-693", "owasp": "A05:2021 Security Misconfiguration", "cvss": 4.3, "severity": "low", "attack": ""},
    "Clickjacking": {"cwe": "CWE-1021", "owasp": "A05:2021 Security Misconfiguration", "cvss": 4.3, "severity": "low", "attack": "T1189"},
    "Cross-Site Request Forgery": {"cwe": "CWE-352", "owasp": "A01:2021 Broken Access Control", "cvss": 6.5, "severity": "medium", "attack": "T1204"},
    "CORS Misconfiguration": {"cwe": "CWE-942", "owasp": "A05:2021 Security Misconfiguration", "cvss": 5.3, "severity": "medium", "attack": ""},
    "Insecure Cookie": {"cwe": "CWE-614", "owasp": "A07:2021 Identification and Authentication Failures", "cvss": 4.3, "severity": "low", "attack": ""},
    "Broken Object Level Authorization": {"cwe": "CWE-639", "owasp": "API1:2023 Broken Object Level Authorization", "cvss": 8.1, "severity": "high", "attack": "T1213"},
    "Broken Function Level Authorization": {"cwe": "CWE-862", "owasp": "API5:2023 Broken Function Level Authorization", "cvss": 7.5, "severity": "high", "attack": "T1078"},
    "Excessive Data Exposure": {"cwe": "CWE-200", "owasp": "API3:2023 Broken Object Property Level Authorization", "cvss": 6.5, "severity": "medium", "attack": "T1213"},
    "Mass Assignment": {"cwe": "CWE-915", "owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows", "cvss": 6.5, "severity": "medium", "attack": "T1078"},
    "Missing Authentication": {"cwe": "CWE-306", "owasp": "API2:2023 Broken Authentication", "cvss": 7.5, "severity": "high", "attack": "T1078"},
    "GraphQL Introspection Enabled": {"cwe": "CWE-200", "owasp": "API8:2023 Security Misconfiguration", "cvss": 5.3, "severity": "medium", "attack": "T1595"},
    "JWT Weakness": {"cwe": "CWE-327", "owasp": "A07:2021 Identification and Authentication Failures", "cvss": 7.5, "severity": "high", "attack": "T1550"},
    "Sensitive Data Exposure": {"cwe": "CWE-200", "owasp": "A02:2021 Cryptographic Failures", "cvss": 6.5, "severity": "medium", "attack": "T1552"},
    "Insecure Authentication": {"cwe": "CWE-307", "owasp": "A07:2021 Identification and Authentication Failures", "cvss": 7.5, "severity": "high", "attack": "T1110"},
    "Admin Interface Exposed": {"cwe": "CWE-862", "owasp": "A01:2021 Broken Access Control", "cvss": 7.5, "severity": "high", "attack": "T1078"},
    "Cross-Tenant Data Exposure": {"cwe": "CWE-639", "owasp": "A01:2021 Broken Access Control", "cvss": 8.6, "severity": "high", "attack": "T1213"},
    "SSO Misconfiguration": {"cwe": "CWE-287", "owasp": "A07:2021 Identification and Authentication Failures", "cvss": 5.3, "severity": "medium", "attack": "T1550"},
    "Rate Limiting Missing": {"cwe": "CWE-770", "owasp": "API4:2023 Unrestricted Resource Consumption", "cvss": 5.3, "severity": "medium", "attack": "T1499"},
    "Technology Fingerprint": {"cwe": "", "owasp": "", "cvss": 0.0, "severity": "info", "attack": "T1595"},
}


def lookup(vuln_type: str) -> dict:
    return TAXONOMY.get(vuln_type, {"cwe": "", "owasp": "", "cvss": None, "severity": "medium", "attack": ""})


def enrich(finding) -> None:
    """Fill CWE/OWASP/CVSS/severity from the taxonomy when the finding lacks them."""
    meta = lookup(finding.type)
    if not finding.cwe:
        finding.cwe = meta["cwe"]
    if not finding.owasp:
        finding.owasp = meta["owasp"]
    if finding.cvss is None:
        finding.cvss = meta["cvss"]
    if finding.severity == "medium" and meta["severity"] != "medium":
        finding.severity = meta["severity"]
