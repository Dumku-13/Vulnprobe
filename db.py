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
                email         TEXT,
                password_hash TEXT    NOT NULL,
                role          TEXT    NOT NULL DEFAULT 'admin',
                created_at    TEXT    NOT NULL
            )
            """
        )
        _ensure_user_columns(conn)
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    NOT NULL,
                target      TEXT    NOT NULL,
                scanner     TEXT    NOT NULL,
                frequency   TEXT    NOT NULL,          -- once | daily | weekly
                params_json TEXT    NOT NULL DEFAULT '{}',
                next_run    TEXT    NOT NULL,          -- naive UTC 'YYYY-MM-DDTHH:MM:SS'
                last_run    TEXT,
                status      TEXT    NOT NULL DEFAULT 'active',  -- active|paused|done
                created_at  TEXT    NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sched_due "
            "ON scheduled_scans (status, next_run)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT    NOT NULL,
                key        TEXT    UNIQUE NOT NULL,
                created_at TEXT    NOT NULL,
                last_used  TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT    NOT NULL,
                message    TEXT    NOT NULL,
                link       TEXT,
                read       INTEGER NOT NULL DEFAULT 0,
                created_at TEXT    NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_notif_user "
            "ON notifications (username, read, created_at DESC)"
        )

    _migrate_users_json()


def _ensure_user_columns(conn) -> None:
    """Add columns introduced after the initial schema to pre-existing DBs."""
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "email" not in existing:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "role" not in existing:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")


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


def add_user(username: str, password_hash: str, role: str = "admin", email: str = None) -> None:
    """Insert or replace a user record."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(username) DO UPDATE SET "
            "email = excluded.email, password_hash = excluded.password_hash, "
            "role = excluded.role",
            (username, email, password_hash, role, _now()),
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

def active_findings(findings: list) -> list:
    """Findings excluding those marked as false positives."""
    return [f for f in (findings or []) if not f.get("false_positive")]


def severity_summary(findings: list) -> dict:
    """Count findings by severity, ordered Critical→Info.

    False-positive findings are excluded so dashboard, trend, and report
    totals all reflect confirmed issues only.
    """
    summary = {s: 0 for s in SEVERITY_ORDER}
    for f in active_findings(findings):
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
                len(active_findings(findings)),
                json.dumps(severity_summary(findings)),
                pdf_path,
                _now(),
            ),
        )
        return cur.lastrowid


def update_scan_findings(scan_id: int, findings: list) -> None:
    """Overwrite a scan's findings JSON and recompute count + severity summary.

    Used when a finding is edited in place (false-positive toggle, analyst note).
    """
    findings = findings or []
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET findings_json = ?, findings_count = ?, "
            "severity_summary = ? WHERE id = ?",
            (
                json.dumps(findings),
                len(active_findings(findings)),
                json.dumps(severity_summary(findings)),
                scan_id,
            ),
        )


def set_scan_pdf(scan_id: int, pdf_path: str) -> None:
    """Attach a generated PDF path to an existing scan row."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET pdf_path = ? WHERE id = ?", (pdf_path, scan_id)
        )


def delete_scan(scan_id: int) -> None:
    """Permanently remove a scan row."""
    with get_conn() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


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


# ── Scheduled scans ────────────────────────────────────────────────────────────

def _row_to_sched(row) -> dict:
    try:
        params = json.loads(row["params_json"])
    except (json.JSONDecodeError, TypeError):
        params = {}
    return {
        "id": row["id"],
        "username": row["username"],
        "target": row["target"],
        "scanner": row["scanner"],
        "frequency": row["frequency"],
        "params": params,
        "next_run": row["next_run"],
        "last_run": row["last_run"],
        "status": row["status"],
        "created_at": row["created_at"],
    }


def create_scheduled_scan(username, target, scanner, frequency, next_run, params=None) -> int:
    """Insert a new scheduled scan; return its id."""
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scheduled_scans "
            "(username, target, scanner, frequency, params_json, next_run, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
            (
                username,
                target,
                scanner,
                frequency,
                json.dumps(params or {}),
                next_run,
                _now(),
            ),
        )
        return cur.lastrowid


def get_scheduled_scans(username=None) -> list:
    """All scheduled scans (admin view) when username is None, else one user's."""
    with get_conn() as conn:
        if username is None:
            rows = conn.execute(
                "SELECT * FROM scheduled_scans ORDER BY next_run ASC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scheduled_scans WHERE username = ? ORDER BY next_run ASC",
                (username,),
            ).fetchall()
    return [_row_to_sched(r) for r in rows]


def get_scheduled_scan(sched_id: int):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scheduled_scans WHERE id = ?", (sched_id,)
        ).fetchone()
    return _row_to_sched(row) if row else None


def get_due_scheduled_scans(now_str: str) -> list:
    """Active schedules whose next_run has passed."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scheduled_scans "
            "WHERE status = 'active' AND next_run <= ? ORDER BY next_run ASC",
            (now_str,),
        ).fetchall()
    return [_row_to_sched(r) for r in rows]


def mark_scheduled_run(sched_id: int, last_run: str, next_run: str, status: str) -> None:
    """Record a completed run: update last_run, the new next_run, and status."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE scheduled_scans SET last_run = ?, next_run = ?, status = ? WHERE id = ?",
            (last_run, next_run, status, sched_id),
        )


def set_scheduled_status(sched_id: int, status: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE scheduled_scans SET status = ? WHERE id = ?", (status, sched_id)
        )


def delete_scheduled_scan(sched_id: int) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM scheduled_scans WHERE id = ?", (sched_id,))


# ── API keys ───────────────────────────────────────────────────────────────────

def create_api_key(username: str, key: str) -> int:
    """Store a new API key for a user (one active key per user — older are removed)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM api_keys WHERE username = ?", (username,))
        cur = conn.execute(
            "INSERT INTO api_keys (username, key, created_at) VALUES (?, ?, ?)",
            (username, key, _now()),
        )
        return cur.lastrowid


def get_api_key_for_user(username: str):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM api_keys WHERE username = ? ORDER BY id DESC LIMIT 1",
            (username,),
        ).fetchone()


def get_user_by_api_key(key: str):
    """Return the user row owning *key*, or None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT u.* FROM api_keys k JOIN users u ON u.username = k.username "
            "WHERE k.key = ?",
            (key,),
        ).fetchone()
    return row


def touch_api_key(key: str) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE api_keys SET last_used = ? WHERE key = ?", (_now(), key))


def revoke_api_key(username: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM api_keys WHERE username = ?", (username,))


# ── Notifications ──────────────────────────────────────────────────────────────

def create_notification(username: str, message: str, link: str = None) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO notifications (username, message, link, read, created_at) "
            "VALUES (?, ?, ?, 0, ?)",
            (username, message, link, _now()),
        )
        return cur.lastrowid


def get_unread_notifications(username: str) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE username = ? AND read = 0 "
            "ORDER BY created_at DESC, id DESC",
            (username,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_recent_notifications(username: str, limit: int = 15) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE username = ? "
            "ORDER BY created_at DESC, id DESC LIMIT ?",
            (username, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def mark_notification_read(notif_id: int, username: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE notifications SET read = 1 WHERE id = ? AND username = ?",
            (notif_id, username),
        )


def mark_all_notifications_read(username: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE notifications SET read = 1 WHERE username = ?", (username,)
        )


def get_role(username: str) -> str:
    """Convenience: role for a username ('user' if unknown)."""
    user = get_user(username)
    return (user["role"] if user else "user") or "user"
