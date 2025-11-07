#!/usr/bin/env python3

"""
Simple Port Scanner
WARNING: For educational purposes only. Use only in authorized testing environments.
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(host, port, timeout=1):
    """Scan a single port on the target host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return port, True
        return port, False
    except socket.error:
        return port, False

def main():
    if len(sys.argv) != 4:
        print("Usage: python port_scanner.py <host> <start_port> <end_port>")
        sys.exit(1)
    
    host = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    
    print(f"[+] Scanning {host} from port {start_port} to {end_port}")
    print(f"[+] This may take a while...")
    
    open_ports = []
    
    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port): port 
            for port in range(start_port, end_port + 1)
        }
        
        for future in as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                print(f"[+] Port {port} is OPEN")
                open_ports.append(port)
    
    print(f"\n[+] Scan complete!")
    print(f"[+] Found {len(open_ports)} open ports")
    if open_ports:
        print(f"[+] Open ports: {', '.join(map(str, open_ports))}")

if __name__ == "__main__":
    main()
