"""
port_scanner.py — VulnProbe Port Scanner Module

Importable port scanner with banner grabbing.
Returns a list of dicts for aggregation by the central runner.

Dependencies: stdlib only (socket, threading)
"""

import socket
import threading


def scan_ports(target, start_port=1, end_port=1024, timeout=1):
    """Scan *target* for open ports in the given range.

    Parameters
    ----------
    target : str
        IP address or hostname.
    start_port : int
        First port to scan (inclusive).
    end_port : int
        Last port to scan (inclusive).
    timeout : float
        Socket timeout in seconds.

    Returns
    -------
    list[dict]
        Each dict: vuln_type, port, banner, severity.
    """
    open_ports = []
    lock = threading.Lock()

    def _scan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((target, port))
            if result == 0:
                banner = ""
                try:
                    banner = s.recv(1024).decode().strip()
                except Exception:
                    pass
                if not banner:
                    try:
                        s.send(
                            b"GET / HTTP/1.1\r\nHost: "
                            + target.encode()
                            + b"\r\n\r\n"
                        )
                        banner = s.recv(1024).decode().strip()
                    except Exception:
                        pass
                with lock:
                    open_ports.append({
                        "vuln_type": "Open Port",
                        "port": port,
                        "banner": banner or "No banner",
                        "severity": "Info",
                    })
        except Exception:
            pass
        finally:
            s.close()

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=_scan, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return sorted(open_ports, key=lambda x: x["port"])


if __name__ == "__main__":
    host = input("Target IP/domain: ").strip()
    sp = int(input("Start port: "))
    ep = int(input("End port: "))
    results = scan_ports(host, sp, ep)
    for r in results:
        print(r)
