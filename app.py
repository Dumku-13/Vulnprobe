"""
app.py — VulnProbe Unified Web Interface

Flask backend exposing all scanner modules as API endpoints.
Serves a single-page dark-themed dashboard.
"""

import os
import sys
import json
import traceback
import secrets
from functools import wraps
from urllib.parse import urlparse, parse_qs
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, abort

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


# ── Scan response helper ──────────────────────────────────────────────────────

def _finalize(scanner, target, findings):
    """Normalize finding dicts, persist the scan for the current user, and
    return the standard JSON response (including the new scan id)."""
    findings = findings or []
    for f in findings:
        if "vuln_type" not in f and "type" in f:
            f["vuln_type"] = f["type"]
    scan_id = db.save_scan(session.get("username", "unknown"), scanner, target, findings)
    return jsonify({
        "scanner": scanner,
        "target": target,
        "findings": findings,
        "scan_id": scan_id,
    })


# ── Auth ─────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
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
@login_required
def api_stats():
    """Dashboard stats + recent scan history as JSON (for the React dashboard)."""
    username = session.get("username", "unknown")
    return jsonify({
        "username": username,
        "stats": db.get_stats(username),
        "scans": db.get_scans(username, limit=25),
    })


@app.route("/api/scan/sqli", methods=["POST"])
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
        session.get("username", "unknown"), "Full Scan", url, all_findings, pdf_path
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
@login_required
def download_scan_report(scan_id):
    """Download (or regenerate) the PDF for a stored scan owned by the user."""
    scan = db.get_scan(scan_id)
    if not scan or scan["username"] != session.get("username"):
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
@login_required
def delete_scan_report(scan_id):
    """Delete a stored scan (and its cached PDF) owned by the current user."""
    scan = db.get_scan(scan_id)
    if not scan or scan["username"] != session.get("username"):
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
@login_required
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
    app.run(debug=True, host="127.0.0.1", port=5001)
