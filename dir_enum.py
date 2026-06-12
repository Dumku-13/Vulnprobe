"""
dir_enum.py — VulnProbe Directory Enumeration Module

Black-box directory/file brute-forcer that:
  1. Strips the target URL down to scheme + netloc.
  2. Requests each path in a hardcoded wordlist concurrently.
  3. Flags responses that are not 404 as findings with severity
     based on the path and status code.

Dependencies: requests
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEADERS = {
    "User-Agent": "Mozilla/5.0 (VulnProbe Scanner)",
}

TIMEOUT = 5
MAX_WORKERS = 10

WORDLIST = [
    "admin", "admin/", "administrator", "login", "login.php",
    "dashboard", "portal",
    "uploads", "upload", "files", "backup", "backup.zip", "backup.sql",
    "db.sql",
    "config", "config.php", "config.yml", ".env", ".git", ".git/config",
    "wp-admin", "wp-login.php", "phpmyadmin", "phpinfo.php",
    "api", "api/v1", "api/v2", "api/users", "api/admin",
    "console", "shell", "cmd", "test", "test.php", "debug",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "server-status", "server-info", "elmah.axd",
    "user", "users", "account", "accounts", "profile", "register",
    "static", "assets", "js", "css", "images", "img",
    "docs", "documentation", "swagger", "swagger-ui", "swagger.json",
    "openapi.json",
    "health", "status", "metrics", "actuator", "actuator/health",
]

CRITICAL_PATHS = {
    "admin", "admin/", "administrator", "backup", "backup.zip", "backup.sql",
    "db.sql", "config", "config.php", "config.yml", ".env", ".git",
    ".git/config", "shell", "cmd", "phpinfo.php", "phpmyadmin",
    "swagger", "swagger-ui", "swagger.json", "openapi.json", "console",
}

INTERESTING_STATUSES = {200, 201, 202, 301, 302, 403}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _classify_severity(path: str, status: int) -> str:
    """Return severity string based on path and HTTP status."""
    if status == 403:
        return "Medium"
    if status in (301, 302):
        return "Low"
    # status 200/201/202
    if path in CRITICAL_PATHS:
        return "Critical"
    return "Medium"


def _probe(base_url: str, path: str, cookies: dict | None):
    """Send a single GET and return a finding dict or None."""
    target = f"{base_url}/{path}"
    try:
        resp = requests.get(
            target,
            headers=HEADERS,
            cookies=cookies,
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None

    if resp.status_code not in INTERESTING_STATUSES:
        return None

    return {
        "vuln_type": "Directory Enumeration",
        "payload": path,
        "evidence": f"HTTP {resp.status_code} — {target}",
        "severity": _classify_severity(path, resp.status_code),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_dirs(url: str, cookies: dict = None) -> list[dict]:
    """Enumerate common directories/files on *url*.

    Parameters
    ----------
    url : str
        Target URL — only scheme + netloc are used.
    cookies : dict, optional
        Cookies to attach to every request.

    Returns
    -------
    list[dict]
        Each dict has keys: vuln_type, payload, evidence, severity.
    """
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print(f"\n[*] Starting directory enumeration on {base_url}")
    print(f"[*] Wordlist size: {len(WORDLIST)} | Workers: {MAX_WORKERS}")

    findings: list[dict] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(_probe, base_url, path, cookies): path
            for path in WORDLIST
        }

        for i, future in enumerate(as_completed(futures), 1):
            path = futures[future]
            print(f"  [{i}/{len(WORDLIST)}] /{path}")
            try:
                result = future.result()
            except Exception:
                continue
            if result is not None:
                findings.append(result)
                print(f"  [!] FOUND — {result['evidence']}  [{result['severity']}]")

    # Sort: Critical first, then High, Medium, Low
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    if findings:
        print(f"\n[!] {len(findings)} path(s) discovered")
    else:
        print("\n[+] No interesting paths found")

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_url = input("Target URL: ")
    cookies_input = input("Session cookie (key=value or blank): ").strip()
    cookies = dict([cookies_input.split("=", 1)]) if cookies_input else None
    findings = scan_dirs(test_url, cookies)
    if findings:
        for f in findings:
            print(f)
    else:
        print("No directories found.")
