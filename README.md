# VulnProbe

A modular black-box web vulnerability scanner with a session-authenticated
dashboard, per-user scan history, and automated PDF reporting. Built in Python
with Flask + SQLite.

> ⚠️ **Authorized testing only.** Run VulnProbe against targets you own or have
> explicit written permission to test.

---

## Features

- **Nine scanner modules** — each a standalone Python module returning a uniform
  list of finding dicts (`vuln_type`, `payload`, `evidence`, `severity`):
  - SQL Injection (error-based, boolean-based, OR/UNION-based)
  - Reflected XSS
  - Local File Inclusion (path traversal)
  - IDOR (parameter manipulation)
  - Port scan + banner grabbing
  - Malicious file upload (extension-bypass)
  - Directory enumeration (threaded wordlist)
  - CSRF (token + security-header checks)
  - Auth (default-credential brute force, weak session tokens)
- **Full Scan mode** — point at one URL, fire all nine modules, get a single
  aggregated PDF report.
- **Session auth** — bcrypt-hashed credentials stored in SQLite.
- **Operator dashboard** — user info, severity breakdown, and full scan history.
- **Scan persistence** — every run is saved per user (findings as JSON, severity
  summary, timestamp, report path).
- **PDF reports** (ReportLab) — executive summary, per-finding remediation,
  GDPR & SOC 2 control mapping, and nonprofit-focused business impact.

---

## Architecture

```
app.py                  Flask app — auth, scan endpoints, dashboard, reports
db.py                   SQLite layer (users + scans tables)
auth.py                 bcrypt verify/create (delegates storage to db.py)
report_generator.py     ReportLab PDF builder
<module>_scanner.py     One file per scanner; importable + CLI
templates/
  login.html            Login page
  dashboard.html        Operator dashboard
  index.html            Single-page scanner UI (tab per module + Full Scan)
```

Each scanner is importable (used by `app.py`) and runnable standalone
(`python lfi_scanner.py`). The Flask app imports them and exposes each as a
`POST /api/scan/<module>` endpoint; results are normalized and persisted to the
`scans` table.

---

## Setup

```bash
# From the project directory
python -m venv .venv
.venv/Scripts/activate        # Windows
# source .venv/bin/activate   # Linux/macOS

python -m pip install flask bcrypt requests reportlab pillow

# Create the admin user (writes to the SQLite DB)
python seed_user.py

# Run
python app.py
```

The app starts on **http://127.0.0.1:5001**. Default seeded login is
`admin` / `vulnprobe2025` — change it in `seed_user.py` before any real use.

On first run, `db.py` creates `vulnprobe.db` and (if present) migrates an
existing `users.json` into the `users` table.

---

## Usage

1. Log in at `/login`.
2. From the dashboard, open the **Scanner**.
3. Pick a module tab and enter a target, or use **Full Scan** for one URL across
   all modules.
4. Findings render live; download a per-scan or full PDF report.
5. Every scan is recorded in your dashboard history.

---

## Tech

Python · Flask · SQLite · bcrypt · ReportLab · requests
