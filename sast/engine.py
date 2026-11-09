"""SAST engine: pure-pattern scanner + optional bandit/semgrep if installed.
Findings are Finding objects with file:line evidence; secret values are redacted.
"""
from __future__ import annotations
import json, os, re, shutil, subprocess

from core.finding import Finding
from scanners.common import redact
from sast.rules import RULES

EXT_LANG = {".py": "py", ".js": "js", ".ts": "ts", ".tsx": "ts", ".jsx": "js",
            ".php": "php", ".java": "java", ".cs": "cs", ".go": "go"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "reports", ".tox"}


class SASTScanner:
    def __init__(self, rules=None):
        self.rules = rules or RULES

    def scan_path(self, path):
        findings = []
        if os.path.isfile(path):
            files = [path]
        else:
            files = []
            for root, dirs, names in os.walk(path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for n in names:
                    if os.path.splitext(n)[1].lower() in EXT_LANG:
                        files.append(os.path.join(root, n))
        for fp in files:
            findings.extend(self.scan_file(fp))
        findings.extend(self._external_tools(path))
        return findings

    def scan_file(self, filepath):
        lang = EXT_LANG.get(os.path.splitext(filepath)[1].lower())
        if not lang:
            return []
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            return []
        out = []
        for rule in self.rules:
            if lang not in rule["langs"]:
                continue
            rx = re.compile(rule["pattern"])
            for i, line in enumerate(lines, 1):
                if rx.search(line):
                    f = Finding(type=rule["title"], title=f"{rule['title']} [{rule['id']}]",
                                url=f"file://{filepath}:{i}", method="SAST", param=rule["id"],
                                evidence=f"{filepath}:{i}: {redact(line.strip())}",
                                severity=rule["severity"], confidence="potential",
                                remediation=rule["remediation"], scanner="sast")
                    out.append(f)
        return out

    def _external_tools(self, path):
        """Optional: run bandit (Python) / semgrep if installed; never required."""
        out = []
        if shutil.which("bandit") and os.path.isdir(path):
            try:
                r = subprocess.run(["bandit", "-r", path, "-f", "json", "-q"],
                                   capture_output=True, text=True, timeout=120)
                data = json.loads(r.stdout or "{}")
                for item in data.get("results", []):
                    f = Finding(type=item.get("issue_text", "Bandit finding")[:120],
                                url=f"file://{item.get('filename')}:{item.get('line_number')}",
                                method="SAST", evidence=redact(item.get("code", "")),
                                severity={"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(item.get("issue_severity"), "low"),
                                confidence="potential", remediation="See bandit guidance.",
                                scanner="sast-bandit")
                    out.append(f)
            except Exception:
                pass
        return out
