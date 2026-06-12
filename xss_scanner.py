"""
xss_scanner.py — VulnProbe Reflected XSS Detection Module

Black-box reflected XSS scanner that:
  1. Crawls the target page for HTML forms and URL query parameters.
  2. Injects a curated payload list into every discovered input field.
  3. Checks the response body for unescaped reflection of the payload.
  4. Determines reflection context (script / attribute / html) and maps
     it to a severity level (Critical / High).
  5. Returns a deduplicated list of finding dicts for aggregation by the
     central VulnProbe runner.

Dependencies: requests, beautifulsoup4 (html.parser — no lxml needed).
"""

import sys
import json
import re
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    '"><svg onload=alert(1)>',
    "';alert(1)//",
    "</script><script>alert(1)</script>",
]

PARTIAL_INDICATORS = [
    "onerror=alert",
    "onload=alert",
    "<script>alert",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (VulnProbe Scanner)",
}

TIMEOUT = 10
EVIDENCE_WINDOW = 200  # chars around match to include as evidence

# ---------------------------------------------------------------------------
# Crawling helpers
# ---------------------------------------------------------------------------


def _extract_forms(html: str, base_url: str) -> list:
    """Return a list of form dicts from *html*.

    Each dict:
        {
            "action": <absolute URL>,
            "method": "get" | "post",
            "fields": [{"name": str, "type": str, "value": str}, ...]
        }
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        action = form.get("action", "")
        action = urljoin(base_url, action) if action else base_url
        method = (form.get("method") or "get").lower()

        fields = []
        # <input>
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            fields.append({
                "name": name,
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })
        # <textarea>
        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if not name:
                continue
            fields.append({
                "name": name,
                "type": "textarea",
                "value": ta.string or "",
            })
        # <select>
        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name:
                continue
            # grab first <option> value as default
            opt = sel.find("option")
            fields.append({
                "name": name,
                "type": "select",
                "value": opt.get("value", "") if opt else "",
            })

        forms.append({"action": action, "method": method, "fields": fields})

    return forms


def _extract_url_params(url: str) -> list:
    """Return a list of (param_name, value) tuples from the URL query string."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    # flatten: parse_qs returns lists; take first value
    return [(k, v[0]) for k, v in params.items()]


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _is_reflected(payload: str, body: str) -> bool:
    """Return True if *payload* or any partial indicator appears in *body*."""
    if payload in body:
        return True
    for indicator in PARTIAL_INDICATORS:
        if indicator in body:
            return True
    return False


def _detect_context(payload: str, body: str) -> str:
    """Determine reflection context: 'script', 'attribute', or 'html'."""
    idx = body.find(payload)
    if idx == -1:
        # try partial match for context detection
        for indicator in PARTIAL_INDICATORS:
            idx = body.find(indicator)
            if idx != -1:
                break
    if idx == -1:
        return "html"

    # Grab surrounding text for context analysis
    window_start = max(0, idx - 200)
    window_end = min(len(body), idx + len(payload) + 200)
    surrounding = body[window_start:window_end]

    # Check if inside a <script> block
    # Look for an opening <script that precedes the payload without a closing </script>
    before = body[window_start:idx].lower()
    after = body[idx:window_end].lower()

    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open != -1 and last_script_open > last_script_close:
        return "script"

    # Check if inside an HTML attribute (look for patterns like =" or =' before payload)
    attr_pattern = re.compile(r'''=\s*["'][^"']*$''')
    if attr_pattern.search(before[-80:]):
        return "attribute"

    return "html"


def _severity_for_context(context: str) -> str:
    """Map context to severity."""
    return "Critical" if context == "script" else "High"


def _extract_evidence(payload: str, body: str) -> str:
    """Return up to EVIDENCE_WINDOW chars centred on the first occurrence."""
    idx = body.find(payload)
    if idx == -1:
        for indicator in PARTIAL_INDICATORS:
            idx = body.find(indicator)
            if idx != -1:
                break
    if idx == -1:
        return ""
    start = max(0, idx - EVIDENCE_WINDOW // 2)
    end = min(len(body), idx + len(payload) + EVIDENCE_WINDOW // 2)
    return body[start:end]


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------


def _test_form(form: dict, cookies: Optional[dict], seen: set) -> list:
    """Inject payloads into every field of *form*. Return list of findings."""
    findings = []
    fields = form["fields"]
    action = form["action"]
    method = form["method"]
    total_payloads = len(PAYLOADS)

    for field in fields:
        fname = field["name"]

        for pi, payload in enumerate(PAYLOADS, 1):
            # Dedup: skip if this field+context already recorded
            # We check after detection, but also skip early if field already
            # has hits in ALL three contexts (unlikely but cheap guard).
            if all((fname, ctx) in seen for ctx in ("html", "attribute", "script")):
                break

            print(f"  Testing [{fname}] with payload [{pi}/{total_payloads}]...")

            # Build form data: payload in target field, benign in others
            data = {}
            for f in fields:
                if f["name"] == fname:
                    data[f["name"]] = payload
                else:
                    data[f["name"]] = f["value"] or "test"

            try:
                if method == "post":
                    resp = requests.post(
                        action, data=data, headers=HEADERS,
                        cookies=cookies, timeout=TIMEOUT,
                        allow_redirects=True,
                    )
                else:
                    resp = requests.get(
                        action, params=data, headers=HEADERS,
                        cookies=cookies, timeout=TIMEOUT,
                        allow_redirects=True,
                    )
            except Exception:
                continue

            body = resp.text

            if _is_reflected(payload, body):
                context = _detect_context(payload, body)
                dedup_key = (fname, context)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append({
                    "type": "XSS",
                    "subtype": "Reflected",
                    "severity": _severity_for_context(context),
                    "location": action,
                    "field": fname,
                    "payload": payload,
                    "context": context,
                    "evidence": _extract_evidence(payload, body)[:200],
                    "url": resp.url,
                })

    return findings


def _test_url_params(target_url: str, params: list, cookies: Optional[dict], seen: set) -> list:
    """Inject payloads into URL query parameters. Return list of findings."""
    findings = []
    parsed = urlparse(target_url)
    base_params = parse_qs(parsed.query, keep_blank_values=True)
    total_payloads = len(PAYLOADS)

    for param_name, _ in params:
        for pi, payload in enumerate(PAYLOADS, 1):
            if all((param_name, ctx) in seen for ctx in ("html", "attribute", "script")):
                break

            print(f"  Testing [{param_name}] with payload [{pi}/{total_payloads}]...")

            # Rebuild query string with payload replacing this param
            injected = {}
            for k, v in base_params.items():
                if k == param_name:
                    injected[k] = payload
                else:
                    injected[k] = v[0]

            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(injected)}"

            try:
                resp = requests.get(
                    url, headers=HEADERS, cookies=cookies,
                    timeout=TIMEOUT, allow_redirects=True,
                )
            except Exception:
                continue

            body = resp.text

            if _is_reflected(payload, body):
                context = _detect_context(payload, body)
                dedup_key = (param_name, context)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append({
                    "type": "XSS",
                    "subtype": "Reflected",
                    "severity": _severity_for_context(context),
                    "location": param_name,
                    "field": param_name,
                    "payload": payload,
                    "context": context,
                    "evidence": _extract_evidence(payload, body)[:200],
                    "url": resp.url,
                })

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan(target_url: str, cookies: dict = None) -> list:
    """Run reflected XSS scan against *target_url*.

    Parameters
    ----------
    target_url : str
        The URL to scan (may include query parameters).
    cookies : dict, optional
        Cookies to attach to every request (e.g. session tokens).

    Returns
    -------
    list[dict]
        Each dict describes one confirmed reflected XSS finding.
        Empty list if nothing found.
    """
    print(f"\n[*] Starting Reflected XSS scan on {target_url}")
    results = []
    seen: set = set()  # (field_name, context) pairs already reported

    # --- Fetch the page --------------------------------------------------
    try:
        resp = requests.get(
            target_url, headers=HEADERS, cookies=cookies,
            timeout=TIMEOUT, allow_redirects=True,
        )
    except Exception as e:
        print(f"[-] Failed to fetch target: {e}")
        return results

    html = resp.text

    # --- Extract injection points ----------------------------------------
    forms = _extract_forms(html, target_url)
    url_params = _extract_url_params(target_url)

    print(f"[*] Found {len(forms)} form(s) and {len(url_params)} URL parameter(s)")

    # --- Test forms -------------------------------------------------------
    for fi, form in enumerate(forms, 1):
        print(f"\n[*] Testing form {fi}/{len(forms)} — action={form['action']} method={form['method'].upper()}")
        results.extend(_test_form(form, cookies, seen))

    # --- Test URL params --------------------------------------------------
    if url_params:
        print(f"\n[*] Testing URL query parameters")
        results.extend(_test_url_params(target_url, url_params, cookies, seen))

    # --- Summary ----------------------------------------------------------
    if results:
        print(f"\n[!] {len(results)} reflected XSS finding(s) confirmed")
    else:
        print("\n[+] No reflected XSS detected with current payloads")

    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python xss_scanner.py <target_url> [session_cookie]")
        sys.exit(1)

    url = sys.argv[1]
    cookie_dict = None
    if len(sys.argv) >= 3:
        cookie_dict = {"session": sys.argv[2]}

    findings = scan(url, cookies=cookie_dict)
    print("\n" + json.dumps(findings, indent=2))
