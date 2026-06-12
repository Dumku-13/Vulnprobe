"""
db.py — VulnProbe SQLite persistence layer

Owns the SQLite connection and schema. Two tables:

    users  — credentials (bcrypt hashes), migrated from users.json on first init
    scans  — one row per scan run (findings stored as JSON, plus pdf path + timestamp)

Auth helpers (verify/create) live in auth.py and call into this module so the
import signatures used by app.py and seed_user.py stay unchanged.
"""

import os
import json
import sqlite3
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "vulnprobe.db")
USERS_JSON = os.path.join(SCRIPT_DIR, "users.json")

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _now() -> str:
    """UTC ISO-8601 timestamp, second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_conn() -> sqlite3.Connection:
    """Open a connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Create tables if missing and migrate users.json on first run."""
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                role          TEXT    NOT NULL DEFAULT 'admin',
                created_at    TEXT    NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                username         TEXT    NOT NULL,
                target           TEXT    NOT NULL,
                scanner          TEXT    NOT NULL,
                findings_json    TEXT    NOT NULL,
                findings_count   INTEGER NOT NULL,
                severity_summary TEXT    NOT NULL,
                pdf_path         TEXT,
                created_at       TEXT    NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_user_time "
            "ON scans (username, created_at DESC)"
        )

    _migrate_users_json()


def _migrate_users_json() -> None:
    """If the users table is empty and users.json exists, import it once."""
    with get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if count:
            return
        if not os.path.exists(USERS_JSON):
            return
        try:
            with open(USERS_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return
        for username, rec in data.items():
            conn.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    username,
                    rec.get("password_hash", ""),
                    rec.get("role", "admin"),
                    _now(),
                ),
            )


# ── Users ─────────────────────────────────────────────────────────────────────

def get_user(username: str):
    """Return the user row (sqlite3.Row) or None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def add_user(username: str, password_hash: str, role: str = "admin") -> None:
    """Insert or replace a user record."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(username) DO UPDATE SET "
            "password_hash = excluded.password_hash, role = excluded.role",
            (username, password_hash, role, _now()),
        )


def all_users() -> dict:
    """Return users as {username: {password_hash, role}} (users.json shape)."""
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM users").fetchall()
    return {
        r["username"]: {"password_hash": r["password_hash"], "role": r["role"]}
        for r in rows
    }


# ── Scans ─────────────────────────────────────────────────────────────────────

def severity_summary(findings: list) -> dict:
    """Count findings by severity, ordered Critical→Info."""
    summary = {s: 0 for s in SEVERITY_ORDER}
    for f in findings or []:
        sev = str(f.get("severity", "Info")).title()
        if sev not in summary:
            summary[sev] = 0
        summary[sev] += 1
    return summary


def save_scan(username, scanner, target, findings, pdf_path=None) -> int:
    """Persist one scan run; return the new scan id."""
    findings = findings or []
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans "
            "(username, target, scanner, findings_json, findings_count, "
            " severity_summary, pdf_path, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                username,
                target,
                scanner,
                json.dumps(findings),
                len(findings),
                json.dumps(severity_summary(findings)),
                pdf_path,
                _now(),
            ),
        )
        return cur.lastrowid


def set_scan_pdf(scan_id: int, pdf_path: str) -> None:
    """Attach a generated PDF path to an existing scan row."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET pdf_path = ? WHERE id = ?", (pdf_path, scan_id)
        )


def get_scan(scan_id: int):
    """Return a single scan row (with findings parsed) or None."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _scan_to_dict(row) if row else None


def get_scans(username: str, limit: int = 50) -> list:
    """Return recent scans for a user, newest first."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE username = ? "
            "ORDER BY created_at DESC, id DESC LIMIT ?",
            (username, limit),
        ).fetchall()
    return [_scan_to_dict(r) for r in rows]


def get_stats(username: str) -> dict:
    """Aggregate dashboard stats for a user."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT findings_count, severity_summary FROM scans WHERE username = ?",
            (username,),
        ).fetchall()

    total_findings = 0
    severity = {s: 0 for s in SEVERITY_ORDER}
    for r in rows:
        total_findings += r["findings_count"]
        try:
            for sev, n in json.loads(r["severity_summary"]).items():
                severity[sev] = severity.get(sev, 0) + n
        except (json.JSONDecodeError, TypeError):
            continue

    return {
        "total_scans": len(rows),
        "total_findings": total_findings,
        "severity": severity,
    }


def _scan_to_dict(row) -> dict:
    """Convert a scans row to a plain dict with parsed JSON fields."""
    try:
        findings = json.loads(row["findings_json"])
    except (json.JSONDecodeError, TypeError):
        findings = []
    try:
        summary = json.loads(row["severity_summary"])
    except (json.JSONDecodeError, TypeError):
        summary = {}
    return {
        "id": row["id"],
        "username": row["username"],
        "target": row["target"],
        "scanner": row["scanner"],
        "findings": findings,
        "findings_count": row["findings_count"],
        "severity_summary": summary,
        "pdf_path": row["pdf_path"],
        "created_at": row["created_at"],
    }
