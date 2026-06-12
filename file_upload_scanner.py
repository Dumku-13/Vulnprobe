"""
file_upload_scanner.py — VulnProbe File Upload Vulnerability Detection Module

Black-box scanner that:
  1. Crawls the target page for file-upload forms (<input type="file">).
  2. Attempts to upload malicious test files (PHP shells, double extensions,
     polyglots) through each discovered form.
  3. Analyses the server response for indicators of a successful upload.
  4. Returns a list of finding dicts for aggregation by the central runner.

Dependencies: requests, beautifulsoup4
"""

import io
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEADERS = {
    "User-Agent": "Mozilla/5.0 (VulnProbe Scanner)",
}

TIMEOUT = 15

MALICIOUS_FILES = [
    {
        "filename": "test.php",
        "content": b"<?php echo 'VULNPROBE_RCE'; ?>",
        "mime": "application/octet-stream",
    },
    {
        "filename": "test.php.jpg",
        "content": b"<?php echo 'VULNPROBE_RCE'; ?>",
        "mime": "image/jpeg",
    },
    {
        "filename": "test.phtml",
        "content": b"<?php echo 'VULNPROBE_RCE'; ?>",
        "mime": "application/octet-stream",
    },
    {
        "filename": "test.php5",
        "content": b"<?php echo 'VULNPROBE_RCE'; ?>",
        "mime": "application/octet-stream",
    },
    {
        "filename": "test.jpg",
        "content": b"GIF89a<?php echo 'VULNPROBE_RCE'; ?>",
        "mime": "image/gif",
    },
]

REJECTION_KEYWORDS = ["invalid", "not allowed", "error", "rejected"]
SUCCESS_INDICATORS = [".php", "/uploads/", "/files/"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_upload_forms(html: str, base_url: str) -> list:
    """Return a list of forms that contain at least one <input type='file'>.

    Each entry:
        {
            "action": <absolute URL>,
            "method": "post" | "get",
            "file_field": <name of the file input>,
            "extra_fields": {name: value, ...}
        }
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        file_inputs = form.find_all("input", attrs={"type": "file"})
        if not file_inputs:
            continue

        action = form.get("action", "")
        action = urljoin(base_url, action) if action else base_url
        method = (form.get("method") or "post").lower()

        # Collect non-file fields so we can submit them alongside the file
        extra = {}
        for inp in form.find_all("input"):
            inp_type = (inp.get("type") or "text").lower()
            if inp_type == "file":
                continue
            name = inp.get("name")
            if name:
                extra[name] = inp.get("value", "")
        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if name:
                extra[name] = ta.string or ""
        for sel in form.find_all("select"):
            name = sel.get("name")
            if name:
                opt = sel.find("option")
                extra[name] = opt.get("value", "") if opt else ""

        for fi in file_inputs:
            field_name = fi.get("name", "file")
            forms.append({
                "action": action,
                "method": method,
                "file_field": field_name,
                "extra_fields": extra,
            })

    return forms


def _looks_successful(response: requests.Response) -> bool:
    """Heuristic: upload appears to have been accepted."""
    if response.status_code != 200:
        return False

    body_lower = response.text.lower()

    # Rejection keywords → upload was blocked
    for kw in REJECTION_KEYWORDS:
        if kw in body_lower:
            return False

    # Look for signs of a stored file path / URL
    for indicator in SUCCESS_INDICATORS:
        if indicator in body_lower:
            return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_file_upload(url: str, cookies: dict = None) -> list:
    """Run file-upload vulnerability scan against *url*.

    Parameters
    ----------
    url : str
        Target URL that is expected to contain one or more upload forms.
    cookies : dict, optional
        Cookies to attach to every request (e.g. session tokens).

    Returns
    -------
    list[dict]
        Each dict has keys: vuln_type, payload, evidence, severity.
    """
    print(f"\n[*] Starting File Upload scan on {url}")
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

    upload_forms = _extract_upload_forms(resp.text, url)

    if not upload_forms:
        print("[-] No file upload forms found on this page.")
        return findings

    print(f"[*] Found {len(upload_forms)} upload form(s)")

    # --- Test each form with every malicious file --------------------------
    for fi, form in enumerate(upload_forms, 1):
        action = form["action"]
        method = form["method"]
        file_field = form["file_field"]
        extra = form["extra_fields"]

        print(f"\n[*] Form {fi}/{len(upload_forms)} — action={action}  field={file_field}")

        for mi, mal in enumerate(MALICIOUS_FILES, 1):
            filename = mal["filename"]
            content = mal["content"]
            mime = mal["mime"]

            print(f"  [{mi}/{len(MALICIOUS_FILES)}] Uploading {filename} ({mime})...")

            file_tuple = (filename, io.BytesIO(content), mime)
            files = {file_field: file_tuple}

            try:
                if method == "post":
                    upload_resp = requests.post(
                        action, data=extra, files=files,
                        headers=HEADERS, cookies=cookies,
                        timeout=TIMEOUT, allow_redirects=True,
                    )
                else:
                    upload_resp = requests.get(
                        action, params=extra, files=files,
                        headers=HEADERS, cookies=cookies,
                        timeout=TIMEOUT, allow_redirects=True,
                    )
            except requests.RequestException:
                continue

            if _looks_successful(upload_resp):
                print(f"  [!] UPLOAD ACCEPTED — {filename}")
                findings.append({
                    "vuln_type": "File Upload",
                    "payload": filename,
                    "evidence": upload_resp.text[:200],
                    "severity": "Critical",
                })

    # --- Summary -----------------------------------------------------------
    if findings:
        print(f"\n[!] {len(findings)} file upload finding(s) confirmed")
    else:
        print("\n[+] No file upload vulnerabilities detected with current payloads")

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_url = input("Target URL (upload form page): ")
    cookies_input = input("Session cookie (key=value or blank): ").strip()
    cookies = dict([cookies_input.split("=", 1)]) if cookies_input else None
    findings = scan_file_upload(test_url, cookies)
    if findings:
        for f in findings:
            print(f)
    else:
        print("No file upload vulnerabilities detected.")
