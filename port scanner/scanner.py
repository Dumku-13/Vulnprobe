import socket
import threading
import time

target = input ("Enter the target IP address or domain:")
start_port = int(input("Enter the starting port:"))
end_port = int(input("Enter the ending port:"))

print(f"\nScanning {target} from port {start_port} to {end_port}...\n")
open_ports = []
lock = threading.Lock()

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    try:
        result = s.connect_ex((target, port))

        if result == 0:
            banner = ""

        try:
            banner = s.recv(1024).decode().strip()
        except:
            pass

        if not banner:
            try:
                    s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                    banner = s.recv(1024).decode().strip()
            except:
                    pass
            with lock:
                open_ports.append((port, banner))

    except:
        pass

    s.close()

start_time = time.time()

threads = []

for port in range(start_port, end_port + 1):
    t = threading.Thread(target=scan_port, args=(port,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

end_time = time.time()
print("open ports:")
for port, banner in sorted(open_ports):
     if banner:
          lines = banner.split("\n")

          server_info = ""
     for line in lines:
            if "Server:" in line:
                server_info = line.strip()
                break

     if server_info:
            print(f"Port {port} -> {server_info}")
     else:
            print(f"Port {port} -> Banner received")
else:
        print(f"Port {port} -> No banner")
print(f"\nscan completed in {end_time - start_time:.2f} seconds ")