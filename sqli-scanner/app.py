"""
Flask Web UI for the SQL Injection Scanner.
Wraps the detection functions from scanner.py in a web interface.
Does NOT modify scanner.py — imports its helpers directly.
"""

import os
from flask import Flask, render_template, request, jsonify

# Import detection helpers from scanner.py (no modifications needed)
from scanner import (
    load_payloads,
    build_url,
    send_request,
    detect_error_based,
    is_time_payload,
    detect_time_based,
    write_report,
)

app = Flask(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_FILE = os.path.join(SCRIPT_DIR, "payloads.txt")
REPORT_FILE = os.path.join(SCRIPT_DIR, "report.txt")


@app.route("/")
def index():
    """Render the homepage."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def run_scan():
    """Accept URL + param from the form, run the scan, return JSON results."""
    data = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()
    param = data.get("param", "").strip()

    # ── Validation ────────────────────────────────────────────────────────
    if not target_url:
        return jsonify({"error": "Target URL is required."}), 400
    if not param:
        return jsonify({"error": "Parameter name is required."}), 400
    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    # ── Load payloads ─────────────────────────────────────────────────────
    try:
        payloads = []
        with open(PAYLOAD_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    payloads.append(stripped)
        if not payloads:
            return jsonify({"error": "No payloads found in payloads.txt"}), 500
    except FileNotFoundError:
        return jsonify({"error": "payloads.txt not found."}), 500

    # ── Baseline request ──────────────────────────────────────────────────
    baseline_url = build_url(target_url, param, "1")
    baseline_body, baseline_status, baseline_time = send_request(baseline_url)
    baseline_len = len(baseline_body)

    if baseline_status == 0:
        return jsonify({
            "error": "Could not reach the target. Check the URL and try again."
        }), 502

    # ── Run scan ──────────────────────────────────────────────────────────
    results = []
    findings = []

    for payload in payloads:
        injected_url = build_url(target_url, param, payload)
        body, status, elapsed = send_request(injected_url)

        vuln_types = []

        # 1) Error-based
        errors = detect_error_based(body)
        if errors:
            vuln_types.append("Error-based")

        # 2) Boolean-based (skip time payloads)
        if not is_time_payload(payload):
            length_diff = abs(len(body) - baseline_len)
            if length_diff > 50 and status == baseline_status:
                vuln_types.append("Boolean-based")

        # 3) Time-based
        if is_time_payload(payload) and detect_time_based(elapsed):
            vuln_types.append("Time-based")

        is_vulnerable = len(vuln_types) > 0

        entry = {
            "payload": payload,
            "vulnerable": is_vulnerable,
            "types": vuln_types,
            "status": status,
            "length": len(body),
            "time": round(elapsed, 2),
        }
        if errors:
            entry["errors"] = errors

        results.append(entry)
        if is_vulnerable:
            findings.append(entry)

    # ── Write report.txt (reuse scanner's writer) ─────────────────────────
    write_report(REPORT_FILE, target_url, param, payloads, findings,
                 baseline_status, baseline_len)

    return jsonify({
        "target": target_url,
        "param": param,
        "total_payloads": len(payloads),
        "total_vulnerabilities": len(findings),
        "baseline": {
            "status": baseline_status,
            "length": baseline_len,
            "time": round(baseline_time, 2),
        },
        "results": results,
    })


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
