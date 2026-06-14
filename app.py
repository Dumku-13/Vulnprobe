"""
app.py — VulnProbe Unified Web Interface

Flask backend exposing all scanner modules as API endpoints.
Serves a single-page dark-themed dashboard.
"""

import os
import sys
import io
import csv
import json
import traceback
import secrets
from functools import wraps
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs
from flask import (
    Flask, render_template, request, jsonify, session, redirect, url_for,
    flash, abort, g, Response,
)

# ── Ensure this directory is on the import path ──────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from sqli_scanner import scan_sqli
from xss_scanner import scan as scan_xss
from lfi_scanner import scan_lfi
from idor_scanner import scan as scan_idor
from port_scanner import scan_ports
from file_upload_scanner import scan_file_upload
from dir_enum import scan_dirs
from csrf_scanner import scan_csrf
from auth_scanner import scan_auth
from report_generator import generate_report
from auth import verify_password, load_users, create_user
import db
import tempfile
import uuid

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

db.init_db()


# ── Current user (session OR API key) ─────────────────────────────────────────

def _username() -> str:
    """Resolve the acting user: API-key identity (set on g) takes priority,
    falling back to the session."""
    return getattr(g, "username", None) or session.get("username", "unknown")


def _role() -> str:
    return getattr(g, "role", None) or session.get("role", "user")


def _is_admin() -> bool:
    return _role() == "admin"


# ── Scan response helper ──────────────────────────────────────────────────────

def _finalize(scanner, target, findings):
    """Normalize finding dicts, persist the scan for the current user, and
    return the standard JSON response (including the new scan id)."""
    findings = findings or []
    for f in findings:
        if "vuln_type" not in f and "type" in f:
            f["vuln_type"] = f["type"]
    scan_id = db.save_scan(_username(), scanner, target, findings)
    return jsonify({
        "scanner": scanner,
        "target": target,
        "findings": findings,
        "scan_id": scan_id,
    })


# ── Auth ─────────────────────────────────────────────────────────────────────

def login_required(f):
    """Browser/session auth: redirect to the login page when absent."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        g.username = session.get('username')
        g.role = session.get('role', 'user')
        return f(*args, **kwargs)
    return decorated


def api_auth_required(f):
    """Accept either a valid session OR a valid X-API-Key header.

    Lets every /api/* route be driven from the browser (cookie session) or
    from curl/scripts (`-H "X-API-Key: vp_..."`)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('logged_in'):
            g.username = session.get('username')
            g.role = session.get('role', 'user')
            return f(*args, **kwargs)

        key = (request.headers.get('X-API-Key') or '').strip()
        if key:
            user = db.get_user_by_api_key(key)
            if user:
                db.touch_api_key(key)
                g.username = user['username']
                g.role = user['role'] or 'user'
                return f(*args, **kwargs)

        return jsonify({"error": "authentication required (session or X-API-Key)"}), 401
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if verify_password(username, password):
            session['logged_in'] = True
            session['username'] = username
            session['role'] = db.get_role(username)
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Self-service registration. Creates a role='user' account, then sends the
    user to the login page. The seeded 'admin' account keeps role='admin'."""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not email or not password:
            error = "All fields are required."
        elif password != confirm:
            error = "Passwords do not match."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif db.get_user(username):
            error = "That username is already taken."
        else:
            create_user(username, password, role="user", email=email)
            return redirect(url_for("login"))

    return render_template("register.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route("/favicon.ico")
def favicon():
    """Serve a small shield SVG as the site favicon (avoids 404s in the console)."""
    svg = (
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
        "<text y='.9em' font-size='90'>🛡️</text></svg>"
    )
    return app.response_class(svg, mimetype="image/svg+xml")


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    username = session.get("username", "unknown")
    return render_template(
        "dashboard.html",
        username=username,
        stats=db.get_stats(username),
        scans=db.get_scans(username, limit=25),
    )


@app.route("/reports")
@login_required
def reports():
    """List every scan owned by the current user."""
    username = session.get("username", "unknown")
    return render_template(
        "reports.html",
        username=username,
        scans=db.get_scans(username, limit=200),
    )


@app.route("/reports/<int:scan_id>")
@login_required
def report_detail(scan_id):
    """Full detail page for one scan: every finding with remediation steps."""
    from report_generator import get_vuln_meta

    scan = db.get_scan(scan_id)
    if not scan or scan["username"] != session.get("username"):
        abort(404)

    for f in scan["findings"]:
        vt = f.get("vuln_type") or f.get("type") or ""
        f["remediation"] = get_vuln_meta(vt).get("fix", "No remediation steps available.")

    return render_template("report_detail.html", username=session.get("username"), scan=scan)


@app.route("/react-dashboard")
@login_required
def react_dashboard():
    return render_template("react_dashboard.html", username=session.get("username", "unknown"))


@app.route("/api/stats")
@api_auth_required
def api_stats():
    """Dashboard stats + recent scan history as JSON (for the React dashboard)."""
    username = _username()
    return jsonify({
        "username": username,
        "stats": db.get_stats(username),
        "scans": db.get_scans(username, limit=25),
    })


@app.route("/api/scan/sqli", methods=["POST"])
@api_auth_required
def api_sqli():
    """Run SQLi scan.  Body: {url, param, method?, cookies?}"""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    param = data.get("param", "").strip()
    method = data.get("method", "GET").strip().upper()
    cookies_str = data.get("cookies", "").strip()

    if not url or not param:
        return jsonify({"error": "url and param are required"}), 400

    cookies = _parse_cookies(cookies_str)

    try:
        # scan_sqli returns bool; we'll capture findings by wrapping
        findings = _run_sqli(url, param, method, cookies)
        return _finalize("SQLi", url, findings)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/scan/xss", methods=["POST"])
@api_auth_required
def api_xss():
    """Run XSS scan.  Body: {url, cookies?}"""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    cookies_str = data.get("cookies", "").strip()

    if not url:
        return jsonify({"error": "url is required"}), 400

    cookies = _parse_cookies(cookies_str) or None
    try:
        findings = scan_xss(url, cookies=cookies)
        return _finalize("XSS", url, findings)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/scan/lfi", methods=["POST"])
@api_auth_required
def api_lfi():
    """Run LFI scan.  Body: {url, params (comma-sep), cookies?}"""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    params_str = data.get("params", "").strip()
    cookies_str = data.get("cookies", "").strip()

    if not url or not params_str:
        return jsonify({"error": "url and params are required"}), 400

    params = {p.strip(): "test" for p in params_str.split(",") if p.strip()}
    cookies = _parse_cookies(cookies_str) or None

    try:
        findings = scan_lfi(url, params, cookies=cookies)
        return _finalize("LFI", url, findings)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/scan/idor", methods=["POST"])
@api_auth_required
def api_idor():
    """Run IDOR scan.  Body: {url, cookies?}"""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    cookies_str = data.get("cookies", "").strip()

    if not url:
        return jsonify({"error": "url is required"}), 400

    cookies = _parse_cookies(cookies_str) or None
    try:
        findings = scan_idor(url, cookies=cookies)
        return _finalize("IDOR", url, findings)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/scan/ports", methods=["POST"])
@api_auth_required
def api_ports():
    """Run port scan.  Body: {target, start_port?, end_port?}"""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    start_port = int(data.get("start_port", 1))
    end_port = int(data.get("end_port", 1024))

    if not target:
        return jsonify({"error": "target is required"}), 400
    if end_port - start_port > 5000:
        return jsonify({"error": "Port range too large (max 5000)"}), 400

    try:
        findings = scan_ports(target, start_port, end_port)
        return _finalize("Port Scanner", target, findings)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/scan/file_upload", methods=["POST"])
@api_auth_required
def api_file_upload():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    cookies_str = data.get("cookies", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    cookies = _parse_cookies(cookies_str) or None
    try:
        findings = scan_file_upload(url, cookies=cookies)
        return _finalize("File Upload", url, findings)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/api/scan/dir_enum", methods=["POST"])
@api_auth_required
def api_dir_enum():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    cookies_str = data.get("cookies", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    cookies = _parse_cookies(cookies_str) or None
    try:
        findings = scan_dirs(url, cookies=cookies)
        return _finalize("Directory Enumeration", url, findings)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/api/scan/csrf", methods=["POST"])
@api_auth_required
def api_csrf():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    cookies_str = data.get("cookies", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    cookies = _parse_cookies(cookies_str) or None
    try:
        findings = scan_csrf(url, cookies=cookies)
        return _finalize("CSRF", url, findings)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/api/scan/auth", methods=["POST"])
@api_auth_required
def api_auth():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    cookies_str = data.get("cookies", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    cookies = _parse_cookies(cookies_str) or None
    try:
        findings = scan_auth(url, cookies=cookies)
        return _finalize("Auth", url, findings)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/scan/full", methods=["POST"])
@api_auth_required
def api_full_scan():
    """Full Scan: fire every module at one URL, aggregate findings, build one
    PDF, and persist a single scan record. Body: {url, cookies?, param?}"""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    cookies_str = data.get("cookies", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    cookies = _parse_cookies(cookies_str) or None
    parsed = urlparse(url)
    host = parsed.hostname or url
    query_params = {k: (v[0] if v else "test") for k, v in parse_qs(parsed.query).items()}

    # Parameters to fuzz for SQLi/LFI: those in the URL, else an explicit one,
    # else common defaults.
    explicit_param = data.get("param", "").strip()
    fuzz_params = list(query_params)
    if not fuzz_params and explicit_param:
        fuzz_params = [explicit_param]
    if not fuzz_params:
        fuzz_params = ["id", "page", "file"]

    by_scanner = {}
    errors = {}

    def _run(name, fn):
        try:
            result = fn() or []
            for f in result:
                if "vuln_type" not in f and "type" in f:
                    f["vuln_type"] = f["type"]
            if result:
                by_scanner[name] = result
        except Exception as e:
            errors[name] = str(e)

    # SQLi — run each candidate parameter through the bool-wrapping helper.
    def _sqli():
        out = []
        for p in fuzz_params:
            out.extend(_run_sqli(url, p, "GET", cookies or {}))
        return out

    # LFI — inject into all candidate parameters at once.
    _lfi_params = {p: "test" for p in fuzz_params}

    _run("SQLi", _sqli)
    _run("XSS", lambda: scan_xss(url, cookies=cookies))
    _run("LFI", lambda: scan_lfi(url, _lfi_params, cookies=cookies))
    _run("IDOR", lambda: scan_idor(url, cookies=cookies))
    _run("Port Scanner", lambda: scan_ports(host, 1, 1024))
    _run("File Upload", lambda: scan_file_upload(url, cookies=cookies))
    _run("Directory Enumeration", lambda: scan_dirs(url, cookies=cookies))
    _run("CSRF", lambda: scan_csrf(url, cookies=cookies))
    _run("Auth", lambda: scan_auth(url, cookies=cookies))

    all_findings = [f for findings in by_scanner.values() for f in findings]

    pdf_path = None
    if all_findings:
        try:
            filename = f"vulnprobe_full_{uuid.uuid4().hex[:8]}.pdf"
            pdf_path = os.path.join(tempfile.gettempdir(), filename)
            generate_report(url, all_findings, pdf_path)
        except Exception as e:
            errors["report"] = str(e)
            pdf_path = None

    scan_id = db.save_scan(
        _username(), "Full Scan", url, all_findings, pdf_path
    )

    return jsonify({
        "scanner": "Full Scan",
        "target": url,
        "findings": all_findings,
        "by_scanner": {k: len(v) for k, v in by_scanner.items()},
        "errors": errors,
        "scan_id": scan_id,
        "report_url": url_for("download_scan_report", scan_id=scan_id) if pdf_path else None,
    })


@app.route("/api/report/<int:scan_id>", methods=["GET"])
@api_auth_required
def download_scan_report(scan_id):
    """Download (or regenerate) the PDF for a stored scan owned by the user."""
    scan = db.get_scan(scan_id)
    if not scan or (scan["username"] != _username() and not _is_admin()):
        return jsonify({"error": "Scan not found"}), 404
    if not scan["findings"]:
        return jsonify({"error": "No findings to report"}), 400

    from flask import send_file
    pdf_path = scan["pdf_path"]
    if not pdf_path or not os.path.exists(pdf_path):
        filename = f"vulnprobe_scan_{scan_id}.pdf"
        pdf_path = os.path.join(tempfile.gettempdir(), filename)
        generate_report(scan["target"], scan["findings"], pdf_path)
        db.set_scan_pdf(scan_id, pdf_path)

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"vulnprobe_report_{scan_id}.pdf",
        mimetype="application/pdf",
    )


@app.route("/api/report/<int:scan_id>", methods=["DELETE"])
@api_auth_required
def delete_scan_report(scan_id):
    """Delete a stored scan (and its cached PDF) owned by the current user."""
    scan = db.get_scan(scan_id)
    if not scan or (scan["username"] != _username() and not _is_admin()):
        return jsonify({"error": "Scan not found"}), 404

    pdf_path = scan.get("pdf_path")
    if pdf_path and os.path.exists(pdf_path):
        try:
            os.remove(pdf_path)
        except OSError:
            pass

    db.delete_scan(scan_id)
    return jsonify({"status": "deleted", "scan_id": scan_id})


@app.route("/api/report", methods=["POST"])
@api_auth_required
def api_report():
    """Generate PDF report from findings. Body: {target_url, findings}"""
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "Unknown Target")
    findings = data.get("findings", [])

    if not findings:
        return jsonify({"error": "No findings to report"}), 400

    try:
        filename = f"vulnprobe_report_{uuid.uuid4().hex[:8]}.pdf"
        output_path = os.path.join(tempfile.gettempdir(), filename)
        generate_report(target_url, findings, output_path)
        from flask import send_file
        return send_file(output_path, as_attachment=True, download_name=filename, mimetype="application/pdf")
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


# ── Scanner registry (shared by the scheduler) ───────────────────────────────

SCANNER_LABELS = {
    "full": "Full Scan",
    "sqli": "SQLi",
    "xss": "XSS",
    "lfi": "LFI",
    "idor": "IDOR",
    "ports": "Port Scanner",
    "file_upload": "File Upload",
    "dir_enum": "Directory Enumeration",
    "csrf": "CSRF",
    "auth": "Auth",
}


def _normalize_findings(result):
    result = result or []
    for f in result:
        if "vuln_type" not in f and "type" in f:
            f["vuln_type"] = f["type"]
    return result


def run_named_scan(scanner_key, target, params=None):
    """Run one scanner (or every scanner for 'full') by key.

    Returns (display_label, findings).  Used by both the scheduler and any
    code path that needs to invoke a scanner outside an HTTP handler.
    """
    params = params or {}
    cookies = params.get("cookies") or None
    if isinstance(cookies, str):
        cookies = _parse_cookies(cookies) or None

    parsed = urlparse(target)
    host = parsed.hostname or target
    query_params = {k: (v[0] if v else "test") for k, v in parse_qs(parsed.query).items()}
    explicit = (params.get("param") or "").strip()
    fuzz = list(query_params) or ([explicit] if explicit else ["id", "page", "file"])

    runners = {
        "sqli": lambda: [x for p in fuzz for x in _run_sqli(target, p, "GET", cookies or {})],
        "xss": lambda: scan_xss(target, cookies=cookies),
        "lfi": lambda: scan_lfi(target, {p: "test" for p in fuzz}, cookies=cookies),
        "idor": lambda: scan_idor(target, cookies=cookies),
        "ports": lambda: scan_ports(host, 1, 1024),
        "file_upload": lambda: scan_file_upload(target, cookies=cookies),
        "dir_enum": lambda: scan_dirs(target, cookies=cookies),
        "csrf": lambda: scan_csrf(target, cookies=cookies),
        "auth": lambda: scan_auth(target, cookies=cookies),
    }

    if scanner_key == "full":
        findings = []
        for fn in runners.values():
            try:
                findings.extend(_normalize_findings(fn()))
            except Exception:
                pass
        return SCANNER_LABELS["full"], findings

    fn = runners.get(scanner_key)
    if not fn:
        raise ValueError(f"Unknown scanner: {scanner_key}")
    return SCANNER_LABELS.get(scanner_key, scanner_key), _normalize_findings(fn())


# ── Scheduler engine ──────────────────────────────────────────────────────────

SCHED_FMT = "%Y-%m-%dT%H:%M:%S"
_scheduler = None


def _sched_now() -> str:
    return datetime.now(timezone.utc).strftime(SCHED_FMT)


def _parse_first_run(raw: str) -> str:
    """Parse a datetime-local value (local wall-clock) into a naive UTC string."""
    if raw:
        for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
            try:
                local_dt = datetime.strptime(raw, fmt)
                return local_dt.astimezone(timezone.utc).strftime(SCHED_FMT)
            except ValueError:
                continue
    return _sched_now()


def _advance(next_run_str, frequency):
    """Compute the following run time + resulting status for a frequency."""
    try:
        base = datetime.strptime(next_run_str, SCHED_FMT)
    except (ValueError, TypeError):
        base = datetime.now(timezone.utc).replace(tzinfo=None)
    if frequency == "daily":
        return (base + timedelta(days=1)).strftime(SCHED_FMT), "active"
    if frequency == "weekly":
        return (base + timedelta(weeks=1)).strftime(SCHED_FMT), "active"
    return next_run_str, "done"  # 'once'


def run_due_scheduled_scans():
    """Background tick: execute every active schedule whose time has come."""
    now = _sched_now()
    for sched in db.get_due_scheduled_scans(now):
        try:
            label, findings = run_named_scan(sched["scanner"], sched["target"], sched["params"])
            pdf_path = None
            if findings:
                try:
                    filename = f"vulnprobe_sched_{sched['id']}_{uuid.uuid4().hex[:6]}.pdf"
                    pdf_path = os.path.join(tempfile.gettempdir(), filename)
                    generate_report(sched["target"], findings, pdf_path)
                except Exception:
                    pdf_path = None
            scan_id = db.save_scan(sched["username"], label, sched["target"], findings, pdf_path)
            n = len([f for f in findings if not f.get("false_positive")])
            db.create_notification(
                sched["username"],
                f"Scheduled {label} scan of {sched['target']} finished — {n} finding(s).",
                f"/reports/{scan_id}",
            )
        except Exception as e:
            db.create_notification(
                sched["username"],
                f"Scheduled {sched['scanner']} scan of {sched['target']} failed: {e}",
                None,
            )

        nxt, status = _advance(sched["next_run"], sched["frequency"])
        # Skip any missed windows so a recurring scan doesn't fire repeatedly.
        if status == "active":
            guard = 0
            while nxt <= _sched_now() and guard < 1000:
                nxt, status = _advance(nxt, sched["frequency"])
                guard += 1
        db.mark_scheduled_run(sched["id"], _sched_now(), nxt, status)


def start_scheduler():
    """Start the once-a-minute background scheduler (idempotent)."""
    global _scheduler
    if _scheduler is not None:
        return
    from apscheduler.schedulers.background import BackgroundScheduler

    _scheduler = BackgroundScheduler(daemon=True, timezone="UTC")
    _scheduler.add_job(
        run_due_scheduled_scans, "interval", minutes=1,
        id="due_scans", max_instances=1, coalesce=True,
    )
    _scheduler.start()


# ── Scheduler routes ──────────────────────────────────────────────────────────

@app.route("/scheduler")
@login_required
def scheduler_page():
    username = _username()
    scheduled = db.get_scheduled_scans(None if _is_admin() else username)
    return render_template(
        "scheduler.html",
        username=username,
        is_admin=_is_admin(),
        scheduled=scheduled,
        scanner_labels=SCANNER_LABELS,
    )


@app.route("/scheduler/create", methods=["POST"])
@login_required
def scheduler_create():
    target = request.form.get("target", "").strip()
    scanner = request.form.get("scanner", "full").strip()
    frequency = request.form.get("frequency", "once").strip()
    first_run = request.form.get("first_run", "").strip()
    cookies = request.form.get("cookies", "").strip()
    param = request.form.get("param", "").strip()

    if not target or scanner not in SCANNER_LABELS or frequency not in ("once", "daily", "weekly"):
        flash("Invalid schedule — check target, scanner, and frequency.")
        return redirect(url_for("scheduler_page"))

    db.create_scheduled_scan(
        _username(), target, scanner, frequency,
        _parse_first_run(first_run), {"cookies": cookies, "param": param},
    )
    return redirect(url_for("scheduler_page"))


@app.route("/scheduler/<int:sched_id>/<action>", methods=["POST"])
@login_required
def scheduler_action(sched_id, action):
    sched = db.get_scheduled_scan(sched_id)
    if not sched or (sched["username"] != _username() and not _is_admin()):
        abort(404)

    if action == "pause":
        db.set_scheduled_status(sched_id, "paused")
    elif action == "resume":
        nxt = sched["next_run"]
        if not nxt or nxt <= _sched_now():
            nxt = _sched_now()
        db.mark_scheduled_run(sched_id, sched["last_run"], nxt, "active")
    elif action == "delete":
        db.delete_scheduled_scan(sched_id)
    else:
        abort(400)
    return redirect(url_for("scheduler_page"))


# ── Trend / export / settings / notifications ─────────────────────────────────

@app.route("/api/trend")
@api_auth_required
def api_trend():
    """Last 30 days of scan activity for the current user, grouped by date."""
    username = _username()
    scans = db.get_scans(username, limit=5000)

    today = datetime.now(timezone.utc).date()
    days = [today - timedelta(days=i) for i in range(29, -1, -1)]
    buckets = {
        d.isoformat(): {
            "date": d.isoformat(), "total": 0,
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
        }
        for d in days
    }
    for s in scans:
        key = (s["created_at"] or "")[:10]
        b = buckets.get(key)
        if not b:
            continue
        b["total"] += s["findings_count"]
        for sev, n in (s["severity_summary"] or {}).items():
            if sev in b:
                b[sev] += n
    return jsonify({"days": [buckets[d.isoformat()] for d in days]})


@app.route("/api/export/csv")
@api_auth_required
def api_export_csv():
    """All of the current user's scans as a downloadable CSV."""
    username = _username()
    scans = db.get_scans(username, limit=100000)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "scan id", "scanner", "target", "findings count",
        "critical", "high", "medium", "low", "info", "timestamp",
    ])
    for s in scans:
        ss = s["severity_summary"] or {}
        writer.writerow([
            s["id"], s["scanner"], s["target"], s["findings_count"],
            ss.get("Critical", 0), ss.get("High", 0), ss.get("Medium", 0),
            ss.get("Low", 0), ss.get("Info", 0), s["created_at"],
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnprobe_scans.csv"},
    )


@app.route("/settings")
@login_required
def settings_page():
    username = _username()
    key_row = db.get_api_key_for_user(username)
    return render_template(
        "settings.html",
        username=username,
        api_key=(key_row["key"] if key_row else None),
        key_created=(key_row["created_at"] if key_row else None),
        key_last_used=(key_row["last_used"] if key_row else None),
    )


@app.route("/settings/key/generate", methods=["POST"])
@login_required
def settings_generate_key():
    db.create_api_key(_username(), "vp_" + secrets.token_urlsafe(32))
    return redirect(url_for("settings_page"))


@app.route("/settings/key/revoke", methods=["POST"])
@login_required
def settings_revoke_key():
    db.revoke_api_key(_username())
    return redirect(url_for("settings_page"))


@app.route("/api/notifications")
@api_auth_required
def api_notifications():
    username = _username()
    unread = db.get_unread_notifications(username)
    return jsonify({
        "unread_count": len(unread),
        "notifications": db.get_recent_notifications(username, limit=15),
    })


@app.route("/api/notifications/<int:notif_id>/read", methods=["POST"])
@api_auth_required
def api_notification_read(notif_id):
    db.mark_notification_read(notif_id, _username())
    return jsonify({"status": "ok"})


@app.route("/api/notifications/read-all", methods=["POST"])
@api_auth_required
def api_notifications_read_all():
    db.mark_all_notifications_read(_username())
    return jsonify({"status": "ok"})


# ── Per-finding actions (false positive + analyst note) ───────────────────────

def _load_owned_scan(scan_id):
    """Return a scan dict the current user may modify, or (None, error response)."""
    scan = db.get_scan(scan_id)
    if not scan or (scan["username"] != _username() and not _is_admin()):
        return None, (jsonify({"error": "Scan not found"}), 404)
    return scan, None


@app.route("/api/report/<int:scan_id>/finding/<int:finding_index>/false-positive", methods=["PATCH"])
@api_auth_required
def api_toggle_false_positive(scan_id, finding_index):
    scan, err = _load_owned_scan(scan_id)
    if err:
        return err
    findings = scan["findings"]
    if not (0 <= finding_index < len(findings)):
        return jsonify({"error": "Invalid finding index"}), 400

    new_state = not bool(findings[finding_index].get("false_positive"))
    findings[finding_index]["false_positive"] = new_state
    db.update_scan_findings(scan_id, findings)
    return jsonify({
        "status": "ok",
        "false_positive": new_state,
        "severity_summary": db.severity_summary(findings),
        "findings_count": len(db.active_findings(findings)),
    })


@app.route("/api/report/<int:scan_id>/finding/<int:finding_index>/note", methods=["PATCH"])
@api_auth_required
def api_save_note(scan_id, finding_index):
    data = request.get_json(silent=True) or {}
    note = str(data.get("note", "")).strip()
    scan, err = _load_owned_scan(scan_id)
    if err:
        return err
    findings = scan["findings"]
    if not (0 <= finding_index < len(findings)):
        return jsonify({"error": "Invalid finding index"}), 400

    findings[finding_index]["note"] = note
    db.update_scan_findings(scan_id, findings)
    return jsonify({"status": "ok", "note": note})


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_cookies(raw: str) -> dict:
    """Parse 'key=value; key2=value2' into a dict."""
    if not raw:
        return {}
    cookies = {}
    for pair in raw.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def _run_sqli(url, param, method, cookies):
    """Wrapper around sqli_scanner.scan_sqli to capture structured output.

    scan_sqli() returns a bool and prints to stdout.  We wrap it to
    produce list-of-dict findings compatible with the other modules.
    """
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        vulnerable = scan_sqli(url, param, method=method, cookies=cookies)

    output = buf.getvalue()
    findings = []

    if vulnerable:
        # Parse the printed output for detected vulnerabilities
        for line in output.splitlines():
            if line.startswith("[!]"):
                vuln_type = "SQLi"
                subtype = "Unknown"
                if "ERROR-BASED" in line:
                    subtype = "Error-based"
                elif "UNION/OR-BASED" in line:
                    subtype = "Union/OR-based"
                elif "BOOLEAN-BASED" in line:
                    subtype = "Boolean-based"

                findings.append({
                    "vuln_type": vuln_type,
                    "subtype": subtype,
                    "severity": "Critical" if subtype == "Error-based" else "High",
                    "evidence": line.strip(),
                    "parameter": param,
                })

    if not findings and vulnerable:
        findings.append({
            "vuln_type": "SQLi",
            "subtype": "Detected",
            "severity": "High",
            "evidence": output[:300],
            "parameter": param,
        })

    return findings


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # use_reloader=False so the BackgroundScheduler runs in a single process
    # (the reloader would otherwise spawn a duplicate scheduler).
    start_scheduler()
    app.run(debug=True, host="127.0.0.1", port=5000, use_reloader=False)
