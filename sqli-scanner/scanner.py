"""
SQL Injection Scanner
=====================
Scans a target URL + parameter by injecting payloads from payloads.txt.
Detects vulnerabilities using three methods:
  1. Error-based  — looks for DBMS error strings in the response
  2. Boolean-based — compares response lengths between true/false payloads
  3. Time-based    — measures response time for SLEEP / WAITFOR payloads

Usage:
    python scanner.py -u "http://target.com/page.php" -p "id"
    python scanner.py --url "http://target.com/page.php" --param "id" --payloads custom.txt

Results are printed to the terminal and saved to report.txt.
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

try:
    import requests
except ImportError:
    print("[!] 'requests' library is required. Install it with:")
    print("    pip install requests")
    sys.exit(1)


# ─── Constants ────────────────────────────────────────────────────────────────

# SQL error signatures that indicate a possible injection (case-insensitive)
SQL_ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*?mysql",
    r"unclosed quotation mark",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"MySqlException",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"valid PostgreSQL result",
    r"unterminated quoted string",
    r"PSQLException",
    # MSSQL
    r"microsoft sql native client error",
    r"mssql_query\(\)",
    r"\bOLE DB\b.*?SQL Server",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"SqlException",
    r"Unclosed quotation mark after the character string",
    # Oracle
    r"ORA-\d{5}",
    r"oracle.*?driver",
    r"quoted string not properly terminated",
    # SQLite
    r"sqlite3\.OperationalError",
    r"SQLITE_ERROR",
    r"unrecognized token",
    # Generic
    r"SQL syntax.*?error",
    r"syntax error.*?SQL",
    r"Division by zero",
    r"SQLSTATE\[",
]

# Compiled regex patterns for performance
ERROR_PATTERNS = [re.compile(sig, re.IGNORECASE) for sig in SQL_ERROR_SIGNATURES]

# Time-based detection threshold in seconds
TIME_THRESHOLD = 4.0

# Boolean-based — keywords present in time payloads (skip them for boolean checks)
TIME_KEYWORDS = ["SLEEP", "WAITFOR", "BENCHMARK", "pg_sleep"]


# ─── Colours (ANSI) ──────────────────────────────────────────────────────────

class C:
    """ANSI colour codes for terminal output."""
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def load_payloads(filepath: str) -> list[str]:
    """Load payloads from a text file, ignoring comments and blank lines."""
    if not os.path.isfile(filepath):
        print(f"{C.RED}[!] Payload file not found: {filepath}{C.RESET}")
        sys.exit(1)

    payloads = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                payloads.append(stripped)

    if not payloads:
        print(f"{C.RED}[!] No payloads found in {filepath}{C.RESET}")
        sys.exit(1)

    return payloads


def build_url(base_url: str, param: str, value: str) -> str:
    """Inject *value* into *param* of *base_url* (GET request)."""
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def send_request(url: str, timeout: int = 15) -> tuple:
    """Send a GET request. Returns (response_text, status_code, elapsed_seconds)."""
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "SQLi-Scanner/1.0"})
        return r.text, r.status_code, r.elapsed.total_seconds()
    except requests.exceptions.Timeout:
        return "", 0, timeout
    except requests.exceptions.RequestException as exc:
        return str(exc), 0, 0.0


# ─── Detection Methods ───────────────────────────────────────────────────────

def detect_error_based(response_text: str) -> list[str]:
    """Check if the response contains known SQL error messages."""
    found = []
    for pattern in ERROR_PATTERNS:
        match = pattern.search(response_text)
        if match:
            found.append(match.group())
    return found


def is_time_payload(payload: str) -> bool:
    """Return True if the payload is designed for time-based detection."""
    upper = payload.upper()
    return any(kw.upper() in upper for kw in TIME_KEYWORDS)


def detect_time_based(elapsed: float) -> bool:
    """Return True if the response time exceeds the threshold."""
    return elapsed >= TIME_THRESHOLD


# ─── Scanner Core ─────────────────────────────────────────────────────────────

def scan(target_url: str, param: str, payloads: list[str], report_path: str) -> None:
    """Run all payloads against the target and report findings."""

    print(f"\n{C.BOLD}{C.CYAN}{'═' * 60}")
    print(f"  SQL Injection Scanner")
    print(f"{'═' * 60}{C.RESET}")
    print(f"  {C.DIM}Target :{C.RESET}  {target_url}")
    print(f"  {C.DIM}Param  :{C.RESET}  {param}")
    print(f"  {C.DIM}Payloads:{C.RESET} {len(payloads)} loaded")
    print(f"  {C.DIM}Report :{C.RESET}  {report_path}")
    print(f"{C.CYAN}{'═' * 60}{C.RESET}\n")

    # ── Baseline request (clean value) ────────────────────────────────────
    print(f"{C.DIM}[*] Sending baseline request …{C.RESET}")
    baseline_url = build_url(target_url, param, "1")
    baseline_body, baseline_status, baseline_time = send_request(baseline_url)
    baseline_len = len(baseline_body)
    print(f"    Baseline: status={baseline_status}, length={baseline_len}, "
          f"time={baseline_time:.2f}s\n")

    if baseline_status == 0:
        print(f"{C.RED}[!] Could not reach the target. Check the URL and try again.{C.RESET}")
        sys.exit(1)

    findings: list[dict] = []
    total = len(payloads)

    for idx, payload in enumerate(payloads, start=1):
        injected_url = build_url(target_url, param, payload)
        label = f"[{idx}/{total}]"

        print(f"  {C.DIM}{label}{C.RESET} Testing: {payload[:60]}", end="", flush=True)

        body, status, elapsed = send_request(injected_url)

        vuln_types = []

        # 1) Error-based detection
        errors = detect_error_based(body)
        if errors:
            vuln_types.append("Error-based")

        # 2) Boolean-based detection (skip for time payloads)
        if not is_time_payload(payload):
            length_diff = abs(len(body) - baseline_len)
            # A significant length difference on a payload that toggles logic
            if length_diff > 50 and status == baseline_status:
                vuln_types.append("Boolean-based")

        # 3) Time-based detection
        if is_time_payload(payload) and detect_time_based(elapsed):
            vuln_types.append("Time-based")

        # ── Print result ──────────────────────────────────────────────────
        if vuln_types:
            tag = ", ".join(vuln_types)
            print(f"  → {C.RED}{C.BOLD}VULNERABLE ({tag}){C.RESET}")
            finding = {
                "payload": payload,
                "types": vuln_types,
                "status": status,
                "length": len(body),
                "time": elapsed,
            }
            if errors:
                finding["errors"] = errors
            findings.append(finding)
        else:
            print(f"  → {C.GREEN}clean{C.RESET}")

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{C.CYAN}{'═' * 60}{C.RESET}")
    if findings:
        print(f"  {C.RED}{C.BOLD}⚠  {len(findings)} potential vulnerability(ies) found!{C.RESET}")
    else:
        print(f"  {C.GREEN}{C.BOLD}✓  No vulnerabilities detected.{C.RESET}")
    print(f"{C.CYAN}{'═' * 60}{C.RESET}\n")

    # ── Write report ──────────────────────────────────────────────────────
    write_report(report_path, target_url, param, payloads, findings,
                 baseline_status, baseline_len)


# ─── Report Writer ────────────────────────────────────────────────────────────

def write_report(path: str, url: str, param: str, payloads: list[str],
                 findings: list[dict], bl_status: int, bl_len: int) -> None:
    """Write a human-readable report to a text file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  SQL Injection Scan Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"  Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Target    : {url}\n")
        f.write(f"  Parameter : {param}\n")
        f.write(f"  Payloads  : {len(payloads)} tested\n")
        f.write(f"  Baseline  : status={bl_status}, length={bl_len}\n\n")
        f.write("-" * 60 + "\n")

        if not findings:
            f.write("\n  [✓] No vulnerabilities detected.\n\n")
        else:
            f.write(f"\n  [!] {len(findings)} POTENTIAL VULNERABILITY(IES) FOUND\n\n")
            for i, finding in enumerate(findings, 1):
                f.write(f"  Finding #{i}\n")
                f.write(f"  {'─' * 40}\n")
                f.write(f"    Payload : {finding['payload']}\n")
                f.write(f"    Type(s) : {', '.join(finding['types'])}\n")
                f.write(f"    Status  : {finding['status']}\n")
                f.write(f"    Length  : {finding['length']}\n")
                f.write(f"    Time    : {finding['time']:.2f}s\n")
                if "errors" in finding:
                    f.write(f"    Errors  : {'; '.join(finding['errors'])}\n")
                f.write("\n")

        f.write("-" * 60 + "\n")
        f.write("  End of Report\n")
        f.write("=" * 60 + "\n")

    print(f"{C.DIM}[*] Report saved to {path}{C.RESET}")


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Scanner — detects error / boolean / time-based SQLi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python scanner.py -u \"http://target.com/page.php\" -p \"id\"",
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (e.g. http://target.com/page.php?id=1)")
    parser.add_argument("-p", "--param", required=True,
                        help="Vulnerable parameter name to test (e.g. id)")
    parser.add_argument("--payloads", default="payloads.txt",
                        help="Path to payloads file (default: payloads.txt)")
    parser.add_argument("--report", default="report.txt",
                        help="Path to output report (default: report.txt)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="HTTP request timeout in seconds (default: 15)")

    args = parser.parse_args()

    # Resolve payload path relative to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    payload_path = args.payloads
    if not os.path.isabs(payload_path):
        payload_path = os.path.join(script_dir, payload_path)

    payloads = load_payloads(payload_path)
    scan(args.url, args.param, payloads, args.report)


if __name__ == "__main__":
    main()
