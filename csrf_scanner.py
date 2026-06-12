"""
csrf_scanner.py — VulnProbe CSRF Vulnerability Detection Module

Black-box CSRF scanner that:
  1. Fetches the target page and parses all HTML forms.
  2. Checks each form for the presence of a CSRF token field.
  3. Flags POST forms without a token as High, GET forms as Medium.
  4. Checks response headers for missing security headers (Low).

Dependencies: requests, beautifulsoup4
"""

from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEADERS = {
    "User-Agent": "Mozilla/5.0 (VulnProbe Scanner)",
}

TIMEOUT = 10

CSRF_TOKEN_NAMES = [
    "csrf",
    "token",
    "_token",
    "authenticity_token",
    "nonce",
    "__requestverificationtoken",
]

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_csrf_token(form) -> bool:
    """Return True if *form* contains an input whose name or id looks like a
    CSRF token."""
    for inp in form.find_all("input"):
        name = (inp.get("name") or "").lower()
        inp_id = (inp.get("id") or "").lower()
        for needle in CSRF_TOKEN_NAMES:
            if needle in name or needle in inp_id:
                return True
    return False


def _form_html_snippet(form, max_len: int = 300) -> str:
    """Return the first *max_len* chars of the form's raw HTML."""
    raw = str(form)
    return raw[:max_len]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_csrf(url: str, cookies: dict = None) -> list[dict]:
    """Run CSRF scan against *url*.

    Parameters
    ----------
    url : str
        Target URL to scan for CSRF issues.
    cookies : dict, optional
        Cookies to attach to the request.

    Returns
    -------
    list[dict]
        Each dict has keys: vuln_type, payload, evidence, severity.
    """
    print(f"\n[*] Starting CSRF scan on {url}")
    findings = []

    # --- Fetch the page ----------------------------------------------------
    try:
        resp = requests.get(
            url, headers=HEADERS, cookies=cookies,
            timeout=TIMEOUT, allow_redirects=True,
        )
    except requests.RequestException as e:
        print(f"[-] Failed to fetch target: {e}")
        return findings

    html = resp.text
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")

    print(f"[*] Found {len(forms)} form(s)")

    # --- Check each form ---------------------------------------------------
    for i, form in enumerate(forms, 1):
        action = form.get("action", "")
        action_url = urljoin(url, action) if action else url
        method = (form.get("method") or "get").upper()
        has_token = _has_csrf_token(form)
        snippet = _form_html_snippet(form)

        print(f"  [{i}/{len(forms)}] method={method}  action={action_url}  token={'YES' if has_token else 'NO'}")

        # GET form — state-changing via GET
        if method == "GET":
            findings.append({
                "vuln_type": "CSRF",
                "payload": f"GET form — action: {action_url}",
                "evidence": snippet,
                "severity": "Medium",
            })

        # POST form without CSRF token
        if method == "POST" and not has_token:
            findings.append({
                "vuln_type": "CSRF",
                "payload": f"POST form with no CSRF token — action: {action_url}",
                "evidence": snippet,
                "severity": "High",
            })

    # --- Check security headers --------------------------------------------
    for header in SECURITY_HEADERS:
        if header.lower() not in {k.lower() for k in resp.headers}:
            findings.append({
                "vuln_type": "Missing Header",
                "payload": f"Missing security header: {header}",
                "evidence": f"Response headers do not include {header}",
                "severity": "Low",
            })
            print(f"  [!] Missing header: {header}")

    # --- Summary -----------------------------------------------------------
    if findings:
        print(f"\n[!] {len(findings)} CSRF-related finding(s)")
    else:
        print("\n[+] No CSRF issues detected")

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_url = input("Target URL: ")
    cookies_input = input("Session cookie (key=value or blank): ").strip()
    cookies = dict([cookies_input.split("=", 1)]) if cookies_input else None
    findings = scan_csrf(test_url, cookies)
    if findings:
        for f in findings:
            print(f)
    else:
        print("No CSRF vulnerabilities detected.")
