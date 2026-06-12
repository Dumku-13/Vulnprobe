"""
idor_scanner.py — VulnProbe Insecure Direct Object Reference Detection Module

Black-box IDOR scanner that:
  1. Identifies numeric parameters in the target URL and HTML forms.
  2. Tests adjacent IDs (e.g., id+1, id+2, id+3, id-1).
  3. Compares responses to baseline to detect unauthorized access to other objects.
  4. Returns a list of finding dicts for aggregation.

Dependencies: requests, beautifulsoup4
"""

import sys
import json
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

import requests
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (VulnProbe Scanner)",
}
TIMEOUT = 10

def _get_url_with_param(parsed_url, base_params, param_name, new_value):
    injected = {}
    for k, v in base_params.items():
        if k == param_name:
            injected[k] = [str(new_value)]
        else:
            injected[k] = v
    # parse_qs returns lists for values, doseq=True handles them
    return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(injected, doseq=True)}"

def _extract_numeric_params(url, html):
    """Extract numeric parameters from URL and form fields."""
    params = {}
    
    # URL parameters
    parsed = urlparse(url)
    url_qs = parse_qs(parsed.query, keep_blank_values=True)
    for k, v in url_qs.items():
        if v and v[0].isdigit():
            params[k] = {"type": "url", "value": int(v[0]), "base_params": url_qs, "parsed": parsed}

    # Form parameters
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            action = urljoin(url, action) if action else url
            method = (form.get("method") or "get").lower()
            
            form_params = {}
            numeric_fields = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                val = inp.get("value", "")
                if name:
                    form_params[name] = val
                    if val.isdigit():
                        numeric_fields[name] = int(val)
            
            for name, val in numeric_fields.items():
                params[f"form:{name}"] = {
                    "type": "form",
                    "value": val,
                    "action": action,
                    "method": method,
                    "all_params": form_params,
                    "field_name": name
                }
                
    return params



def scan(target_url: str, cookies: dict = None) -> list:
    print(f"\n[*] Starting IDOR scan on {target_url}")
    findings = []
    
    try:
        baseline_resp = requests.get(target_url, headers=HEADERS, cookies=cookies, timeout=TIMEOUT, allow_redirects=True)
        baseline_body = baseline_resp.text
    except Exception:
        # Handle all request exceptions silently
        return findings

    numeric_params = _extract_numeric_params(target_url, baseline_body)
    
    if not numeric_params:
        print("[-] No numeric parameters found to test for IDOR.")
        return findings

    seen_params = set()

    for param_id, info in numeric_params.items():
        param_name = param_id.replace("form:", "") if info["type"] == "form" else param_id
        
        if param_name in seen_params:
            continue
        seen_params.add(param_name)

        orig_val = info["value"]
        
        print(f"[*] Testing parameter '{param_name}' (original value: {orig_val})")
        
        # We test +1, +2, +3, -1
        test_offsets = [1, 2, 3, -1]
        
        for offset in test_offsets:
            test_val = orig_val + offset
            if test_val < 0:
                continue
                
            print(f"  Testing [{param_name}] original=[{orig_val}] modified=[{test_val}]...")
            
            test_url = target_url
            try:
                if info["type"] == "url":
                    test_url = _get_url_with_param(info["parsed"], info["base_params"], param_name, test_val)
                    test_resp = requests.get(test_url, headers=HEADERS, cookies=cookies, timeout=TIMEOUT, allow_redirects=True)
                else:
                    test_url = info["action"]
                    data = info["all_params"].copy()
                    data[info["field_name"]] = str(test_val)
                    if info["method"] == "post":
                        test_resp = requests.post(test_url, data=data, headers=HEADERS, cookies=cookies, timeout=TIMEOUT, allow_redirects=True)
                    else:
                        test_resp = requests.get(test_url, params=data, headers=HEADERS, cookies=cookies, timeout=TIMEOUT, allow_redirects=True)
                
                test_body = test_resp.text
                test_status = test_resp.status_code
            except Exception:
                continue
                
            # Detection logic
            if test_status == 200 and test_body != baseline_body:
                findings.append({
                    "type": "IDOR",
                    "subtype": "Parameter Tampering",
                    "severity": "High",
                    "location": target_url,
                    "field": param_name,
                    "original_value": str(orig_val),
                    "tested_value": str(test_val),
                    "evidence": test_body[:200],
                    "url": test_url
                })
                print(f"[!] IDOR found on parameter '{param_name}' with modified value '{test_val}'")

    if not findings:
        print("[+] No IDOR detected.")
        
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python idor_scanner.py <target_url> [session_cookie]")
        sys.exit(1)

    url = sys.argv[1]
    cookie_dict = None
    if len(sys.argv) >= 3:
        cookie_dict = {"session": sys.argv[2]}

    findings = scan(url, cookies=cookie_dict)
    print("\n" + json.dumps(findings, indent=2))
