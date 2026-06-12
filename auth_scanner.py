"""
auth_scanner.py — VulnProbe Default Credentials Scanner Module

Black-box auth scanner that:
  1. Fetches the target URL and searches for login forms (forms with password inputs).
  2. Submits a list of common default credentials to each discovered form.
  3. Analyzes response body and redirects to determine if login was successful.
  4. Checks for weak/predictable session tokens upon successful login.

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

CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "password123"),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("user", "user"),
    ("user", "password"),
    ("user", "123456"),
    ("test", "test"),
    ("test", "password"),
    ("guest", "guest"),
    ("guest", "password"),
    ("demo", "demo"),
    ("demo", "password"),
    ("operator", "operator"),
]

SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logout", "sign out", "my account",
    "profile", "logged in"
]

FAILURE_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "try again", "bad credentials"
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_login_form(form) -> bool:
    """Return True if the form contains an input of type 'password'."""
    for inp in form.find_all("input"):
        if (inp.get("type") or "").lower() == "password":
            return True
    return False


def _get_form_inputs(form) -> dict:
    """Return a template dict of form inputs to be submitted."""
    data = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        
        typ = (inp.get("type") or "").lower()
        if typ in ["text", "email", "username"]:
            data[name] = "{USERNAME}"
        elif typ == "password":
            data[name] = "{PASSWORD}"
        else:
            data[name] = inp.get("value", "")
            
    return data


def _is_weak_session_token(token: str) -> bool:
    """Return True if token is short (< 20 chars) or purely numeric."""
    if len(token) < 20:
        return True
    if token.isdigit():
        return True
    return False


def _check_success(resp: requests.Response, original_url: str) -> bool:
    """Analyze response to determine if login succeeded."""
    body = resp.text.lower()
    
    # Check for redirects to non-login pages
    if resp.history:
        first_resp = resp.history[0]
        if first_resp.status_code in [301, 302, 303, 307, 308]:
            # A redirect after POST might indicate success
            return True

    # Check body indicators
    has_success = any(ind in body for ind in SUCCESS_INDICATORS)
    has_failure = any(ind in body for ind in FAILURE_INDICATORS)
    
    if has_success and not has_failure:
        return True
        
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_auth(url: str, cookies: dict = None) -> list[dict]:
    """Run default credential scan against *url*.

    Parameters
    ----------
    url : str
        Target URL containing login forms.
    cookies : dict, optional
        Cookies to attach to the request.

    Returns
    -------
    list[dict]
        Each dict has keys: vuln_type, payload, evidence, severity.
    """
    print(f"\n[*] Starting Auth scan on {url}")
    findings = []

    # --- Fetch the page ----------------------------------------------------
    try:
        session = requests.Session()
        if cookies:
            session.cookies.update(cookies)
            
        resp = session.get(url, headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"[-] Failed to fetch target: {e}")
        return findings

    html = resp.text
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    
    login_forms = [f for f in forms if _is_login_form(f)]
    print(f"[*] Found {len(login_forms)} login form(s)")

    # --- Test each login form ----------------------------------------------
    for form_idx, form in enumerate(login_forms, 1):
        action = form.get("action", "")
        action_url = urljoin(url, action) if action else url
        method = (form.get("method") or "get").upper()
        
        # Only support POST forms for credential brute-forcing
        if method != "POST":
            print(f"  [{form_idx}] Skipping non-POST login form")
            continue
            
        inputs_template = _get_form_inputs(form)
        
        # Find which inputs are meant for username and password
        user_field = None
        pass_field = None
        for k, v in inputs_template.items():
            if v == "{USERNAME}":
                user_field = k
            elif v == "{PASSWORD}":
                pass_field = k
                
        # If we couldn't cleanly identify fields, fallback to first text and first password
        if not pass_field:
            print(f"  [{form_idx}] Could not identify password field, skipping")
            continue
            
        print(f"  [{form_idx}] Testing {len(CREDENTIALS)} credential pairs on {action_url}")
        
        for username, password in CREDENTIALS:
            # Prepare payload
            payload = inputs_template.copy()
            if user_field:
                payload[user_field] = username
            payload[pass_field] = password
            
            try:
                # Use a fresh session for each login attempt to keep cookies clean
                test_session = requests.Session()
                if cookies:
                    test_session.cookies.update(cookies)
                    
                post_resp = test_session.post(
                    action_url,
                    data=payload,
                    headers=HEADERS,
                    timeout=TIMEOUT,
                    allow_redirects=True
                )
            except requests.RequestException:
                continue
                
            if _check_success(post_resp, action_url):
                print(f"  [!] SUCCESS: {username}:{password}")
                
                # Default Credentials finding
                findings.append({
                    "vuln_type": "Default Credentials",
                    "payload": f"{username}:{password}",
                    "evidence": post_resp.text[:200],
                    "severity": "Critical"
                })
                
                # Check for weak session tokens
                for cookie in test_session.cookies:
                    if _is_weak_session_token(cookie.value):
                        print(f"  [!] Weak Session Token found: {cookie.name}={cookie.value}")
                        findings.append({
                            "vuln_type": "Weak Session Token",
                            "payload": cookie.value,
                            "evidence": "Session token appears weak or predictable",
                            "severity": "High"
                        })
                
                # Stop testing this form after a successful login
                break

    # --- Summary -----------------------------------------------------------
    if findings:
        print(f"\n[!] {len(findings)} Auth-related finding(s)")
    else:
        print("\n[+] No Default Credential vulnerabilities detected")

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_url = input("Target URL: ")
    cookies_input = input("Session cookie (key=value or blank): ").strip()
    cookies = dict([cookies_input.split("=", 1)]) if cookies_input else None
    findings = scan_auth(test_url, cookies)
    if findings:
        for f in findings:
            print(f)
    else:
        print("No Auth vulnerabilities detected.")
