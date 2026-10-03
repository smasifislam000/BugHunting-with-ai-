"""
core/database.py
----------------
SQLite manager for the framework.
Tables: scans, hosts, findings, reports.
Thread-safe via per-call connections.
"""

import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

from core.logger import get_logger
from core.utils import ensure_dir

log = get_logger("database")


# ─────────────────────────────────────────
# Schema
# ─────────────────────────────────────────
SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    started_at  DATETIME NOT NULL,
    finished_at DATETIME,
    status      TEXT DEFAULT 'running',
    notes       TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    hostname    TEXT NOT NULL,
    ip          TEXT,
    status_code INTEGER,
    title       TEXT,
    tech        TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    UNIQUE(scan_id, hostname)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    host        TEXT,
    vuln_type   TEXT NOT NULL,
    severity    TEXT DEFAULT 'info',
    url         TEXT,
    param       TEXT,
    payload     TEXT,
    evidence    TEXT,
    status      TEXT DEFAULT 'pending',
    confidence  INTEGER DEFAULT 0,
    created_at  DATETIME NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL,
    format      TEXT,
    path        TEXT,
    created_at  DATETIME NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan   ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_hosts_scan      ON hosts(scan_id);
"""


# ─────────────────────────────────────────
# DB Class
# ─────────────────────────────────────────
class Database:
    def __init__(self, db_path: str = "bug_bounty.db"):
        self.db_path = db_path
        ensure_dir(Path(db_path).parent)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init(self):
        try:
            with self._conn() as c:
                c.executescript(SCHEMA)
            log.debug(f"DB ready: {self.db_path}")
        except Exception as e:
            log.error(f"DB init failed: {e}")

    # ── Scans ─────────────────────────────
    def start_scan(self, target: str) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO scans (target, started_at, status) VALUES (?, ?, 'running')",
                (target, datetime.utcnow())
            )
            return cur.lastrowid

    def finish_scan(self, scan_id: int, status: str = "done", notes: str = ""):
        with self._conn() as c:
            c.execute(
                "UPDATE scans SET finished_at=?, status=?, notes=? WHERE id=?",
                (datetime.utcnow(), status, notes, scan_id)
            )

    def get_scan(self, scan_id: int) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            return dict(row) if row else None

    # ── Hosts ─────────────────────────────
    def add_host(self, scan_id: int, hostname: str, ip: str = "",
                 status_code: int = 0, title: str = "", tech: str = "") -> Optional[int]:
        try:
            with self._conn() as c:
                cur = c.execute("""
                    INSERT INTO hosts (scan_id, hostname, ip, status_code, title, tech)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id, hostname) DO UPDATE SET
                        ip=excluded.ip,
                        status_code=excluded.status_code,
                        title=excluded.title,
                        tech=excluded.tech
                """, (scan_id, hostname, ip, status_code, title, tech))
                return cur.lastrowid
        except Exception as e:
            log.debug(f"add_host failed: {e}")
            return None

    def add_hosts_bulk(self, scan_id: int, hosts: List[Dict]) -> int:
        count = 0
        for h in hosts:
            if self.add_host(scan_id, h.get("hostname", ""), h.get("ip", ""),
                             h.get("status_code", 0), h.get("title", ""),
                             h.get("tech", "")):
                count += 1
        return count

    def get_hosts(self, scan_id: int) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()
            return [dict(r) for r in rows]

    # ── Findings ──────────────────────────
    def add_finding(self, scan_id: int, vuln_type: str, severity: str = "info",
                    url: str = "", param: str = "", payload: str = "",
                    evidence: str = "", host: str = "",
                    confidence: int = 0) -> Optional[int]:
        try:
            with self._conn() as c:
                cur = c.execute("""
                    INSERT INTO findings
                    (scan_id, host, vuln_type, severity, url, param, payload,
                     evidence, status, confidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """, (scan_id, host, vuln_type, severity, url, param, payload,
                      evidence, confidence, datetime.utcnow()))
                return cur.lastrowid
        except Exception as e:
            log.debug(f"add_finding failed: {e}")
            return None

    def update_finding_status(self, finding_id: int, status: str,
                              confidence: Optional[int] = None):
        with self._conn() as c:
            if confidence is not None:
                c.execute("UPDATE findings SET status=?, confidence=? WHERE id=?",
                          (status, confidence, finding_id))
            else:
                c.execute("UPDATE findings SET status=? WHERE id=?",
                          (status, finding_id))

    def get_findings(self, scan_id: int, status: Optional[str] = None) -> List[Dict]:
        q = "SELECT * FROM findings WHERE scan_id=?"
        args: List[Any] = [scan_id]
        if status:
            q += " AND status=?"
            args.append(status)
        q += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 " \
             "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, id"
        with self._conn() as c:
            rows = c.execute(q, args).fetchall()
            return [dict(r) for r in rows]

    def finding_exists(self, scan_id: int, vuln_type: str, url: str,
                       param: str = "") -> bool:
        """Dedupe check."""
        with self._conn() as c:
            row = c.execute("""
                SELECT 1 FROM findings
                WHERE scan_id=? AND vuln_type=? AND url=? AND param=?
                LIMIT 1
            """, (scan_id, vuln_type, url, param)).fetchone()
            return row is not None

    def stats(self, scan_id: int) -> Dict[str, int]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT severity, COUNT(*) as cnt FROM findings
                WHERE scan_id=? GROUP BY severity
            """, (scan_id,)).fetchall()
            out = {r["severity"]: r["cnt"] for r in rows}
            out["total"] = sum(out.values())
            return out

    # ── Reports ───────────────────────────
    def add_report(self, finding_id: int, path: str, format: str = "hackerone") -> Optional[int]:
        with self._conn() as c:
            cur = c.execute("""
                INSERT INTO reports (finding_id, format, path, created_at)
                VALUES (?, ?, ?, ?)
            """, (finding_id, format, path, datetime.utcnow()))
            return cur.lastrowid

    def get_reports(self, scan_id: int) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT r.*, f.url, f.vuln_type, f.severity
                FROM reports r
                JOIN findings f ON f.id = r.finding_id
                WHERE f.scan_id = ?
            """, (scan_id,)).fetchall()
            return [dict(r) for r in rows]


# ─────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────
_db_instance: Optional[Database] = None

def get_db(db_path: str = "bug_bounty.db", reload: bool = False) -> Database:
    global _db_instance
    if _db_instance is None or reload:
        _db_instance = Database(db_path)
    return _db_instance