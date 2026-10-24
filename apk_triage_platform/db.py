"""
Defensive Android APK Triage Platform - SQLite Forensic Storage
Persistent evidentiary case storage for investigated APK artifacts.
"""

import json
import sqlite3
from typing import Any, Dict, List, Optional


def init_db(db_path: str = "forensics.db") -> sqlite3.Connection:
    """Initialize the SQLite database schema if not present."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS triage_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                sha256 TEXT UNIQUE NOT NULL,
                md5 TEXT NOT NULL,
                sha1 TEXT NOT NULL,
                size INTEGER NOT NULL,
                score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                signing_status TEXT NOT NULL,
                data_json TEXT NOT NULL,
                html_report TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON triage_reports(sha256)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_risk ON triage_reports(risk_level)")
    return conn


def save_report(conn: sqlite3.Connection, result: Dict[str, Any], html_report: str) -> int:
    """Save or update an analyzed report in the SQLite database."""
    name = result.get("name", "Unknown")
    hashes = result.get("hashes", {})
    sha256 = hashes.get("sha256", "")
    md5 = hashes.get("md5", "")
    sha1 = hashes.get("sha1", "")
    size = hashes.get("size", 0)
    sc = result.get("scoring", {})
    score_val = sc.get("total_score", 0)
    risk_level = sc.get("risk_level", "Unknown")
    signing = result.get("signing", {}).get("status", "Unknown")

    # Serialize analysis data without un-serializable objects
    clean_result = {k: v for k, v in result.items() if k not in ("dex_strings",)}
    data_json = json.dumps(clean_result)

    with conn:
        cursor = conn.execute(
            """
            INSERT INTO triage_reports (
                name, sha256, md5, sha1, size, score, risk_level, signing_status, data_json, html_report
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
                name = excluded.name,
                score = excluded.score,
                risk_level = excluded.risk_level,
                signing_status = excluded.signing_status,
                data_json = excluded.data_json,
                html_report = excluded.html_report
            """,
            (name, sha256, md5, sha1, size, score_val, risk_level, signing, data_json, html_report),
        )
        # Fetch the row id
        row = conn.execute("SELECT id FROM triage_reports WHERE sha256 = ?", (sha256,)).fetchone()
        return row["id"] if row else cursor.lastrowid


def get_report(conn: sqlite3.Connection, report_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve full analysis report by ID."""
    row = conn.execute("SELECT * FROM triage_reports WHERE id = ?", (report_id,)).fetchone()
    if not row:
        return None
    data = json.loads(row["data_json"])
    data["id"] = row["id"]
    data["created_at"] = row["created_at"]
    return data


def get_html_report(conn: sqlite3.Connection, report_id: int) -> Optional[str]:
    """Retrieve rendered printable HTML report by ID."""
    row = conn.execute("SELECT html_report FROM triage_reports WHERE id = ?", (report_id,)).fetchone()
    return row["html_report"] if row else None


def list_reports(
    conn: sqlite3.Connection,
    risk_level: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List historic investigation reports with optional risk filtering."""
    query = "SELECT id, name, sha256, size, score, risk_level, signing_status, created_at FROM triage_reports"
    params = []
    if risk_level:
        query += " WHERE risk_level = ?"
        params.append(risk_level)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, tuple(params)).fetchall()
    return [dict(r) for r in rows]
