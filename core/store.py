"""SQLite scan history (scans + findings tables)."""
from __future__ import annotations
import json, os, sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, started_at TEXT,
  finished_at TEXT, total_findings INTEGER, critical INTEGER, high INTEGER,
  medium INTEGER, low INTEGER, info INTEGER);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, type TEXT, title TEXT,
  url TEXT, method TEXT, param TEXT, payload TEXT, evidence TEXT,
  severity TEXT, cvss REAL, cwe TEXT, owasp TEXT, confidence TEXT,
  remediation TEXT, scanner TEXT, dedup_key TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(id));
"""


class ScanStore:
    def __init__(self, path: str = "reports/spyder.db"):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def save_scan(self, target: str, findings, started_at: str = "") -> int:
        counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        cur = self.conn.execute(
            "INSERT INTO scans(target,started_at,finished_at,total_findings,critical,high,medium,low,info)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (target, started_at, datetime.now(timezone.utc).isoformat(), len(findings),
             counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"]))
        scan_id = cur.lastrowid
        for f in findings:
            self.conn.execute(
                "INSERT INTO findings(scan_id,type,title,url,method,param,payload,evidence,severity,"
                "cvss,cwe,owasp,confidence,remediation,scanner,dedup_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, f.type, f.title, f.url, f.method, f.param, f.payload, f.evidence,
                 f.severity, f.cvss, f.cwe, f.owasp, f.confidence, f.remediation, f.scanner, f.dedup_key))
        self.conn.commit()
        return scan_id

    def list_scans(self, limit: int = 20):
        cur = self.conn.execute(
            "SELECT id,target,started_at,finished_at,total_findings,critical,high,medium,low,info"
            " FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def findings_for_scan(self, scan_id: int):
        cur = self.conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY severity", (scan_id,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self):
        self.conn.close()
