# Python Pen Testing Cheat Sheet

## Basic Execution

```bash
python3 script.py                    # Execute script
chmod +x script.py                   # Make executable
./script.py                          # Run standalone
```

**Shebang:** `#!/bin/python3`

---

## ctypes - Windows API Access

### Loading DLLs
```python
from ctypes import *
kernel32 = windll.kernel32
user32 = windll.user32
```

### Common C Datatypes
| C Type | ctypes Type |
|--------|-------------|
| char | c_char |
| int | c_int |
| long | c_long |
| void * | c_void_p |
| char * | c_char_p |

### Example API Call
```python
MessageBox = user32.MessageBoxW
MessageBox.argtypes = [c_int, c_wchar_p, c_wchar_p, c_int]
MessageBox.restype = c_int
result = MessageBox(None, "Hello", "Title", 0)
```

---

## Debugging - Manual Debugger

### Create Debug Process
```python
from ctypes import *

startupinfo = STARTUPINFO()
processinfo = PROCESS_INFORMATION()

kernel32.CreateProcessA(
    None, "C:\\Windows\\System32\\calc.exe",
    None, None, False, DEBUG_PROCESS,
    None, None, byref(startupinfo), byref(processinfo)
)
```

### Wait for Debug Events
```python
debug_event = DEBUG_EVENT()
kernel32.WaitForDebugEvent(byref(debug_event), INFINITE)

if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
    exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
```

### Get/Set Thread Context
```python
context = CONTEXT()
context.ContextFlags = CONTEXT_FULL
kernel32.GetThreadContext(h_thread, byref(context))
print("EIP: 0x%08x" % context.Eip)
```

### Continue Debug Event
```python
kernel32.ContinueDebugEvent(pid, tid, DBG_CONTINUE)
```

### Software Breakpoint
```python
# Read original byte
original_byte = c_char()
kernel32.ReadProcessMemory(h_process, address, byref(original_byte), 1, byref(c_ulong()))

# Write INT3 (0xCC)
kernel32.WriteProcessMemory(h_process, address, b"\xCC", 1, byref(c_ulong()))

# Restore
kernel32.WriteProcessMemory(h_process, address, original_byte, 1, byref(c_ulong()))
```

---

## PyDbg - Advanced Debugging

### Basic Setup
```python
from pydbg import *
from pydbg.defines import *

dbg = pydbg()
dbg.load("C:\\Windows\\system32\\calc.exe")
```

### Access Violation Handler
```python
def av_handler(dbg):
    print("[*] Access violation at: 0x%08x" % dbg.exception_address)
    return DBG_CONTINUE

dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, av_handler)
dbg.run()
```

### Breakpoints
```python
dbg.bp_set(0x401000)                     # Set breakpoint
dbg.bp_set(0x401000, handler=my_func)    # With handler
```

### Memory Operations
```python
data = dbg.read_process_memory(address, length)
dbg.write_process_memory(address, data, length)
```

---

## Immunity Debugger (PyCommands)

### Basic PyCommand
```python
from immlib import *

def main(args):
    imm = Debugger()
    pid = imm.getDebuggedPid()
    imm.log("[*] PID: %d" % pid)
    return "[+] Done"
```

### Memory Operations
```python
data = imm.readMemory(0x401000, 16)
imm.search("A1B2C3D4")                   # Search bytes
```

### PyHook
```python
class MyHook(LogBpHook):
    def run(self, regs):
        imm = Debugger()
        imm.log("[HOOK] EAX: 0x%08x" % regs['EAX'])

def main(args):
    imm = Debugger()
    hook = MyHook()
    hook.add("HOOK1", 0x401000)
    imm.addHook(hook)
```

---

## DLL & Code Injection

### DLL Injection
```python
from ctypes import *

pid = 1234
dll_path = "C:\\path\\to\\evil.dll"

# Open process
h_process = kernel32.OpenProcess(0x1F0FFF, False, pid)

# Allocate memory for DLL path
arg_address = kernel32.VirtualAllocEx(h_process, 0, len(dll_path), 0x3000, 0x40)

# Write DLL path
kernel32.WriteProcessMemory(h_process, arg_address, dll_path, len(dll_path), byref(c_int(0)))

# Get LoadLibraryA address
h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
load_library = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

# Create remote thread
kernel32.CreateRemoteThread(h_process, None, 0, load_library, arg_address, 0, None)
```

### Shellcode Injection
```python
shellcode = b"\x90" * 100

h_process = kernel32.OpenProcess(0x1F0FFF, False, pid)
mem_address = kernel32.VirtualAllocEx(h_process, 0, len(shellcode), 0x3000, 0x40)
kernel32.WriteProcessMemory(h_process, mem_address, shellcode, len(shellcode), byref(c_int(0)))
kernel32.CreateRemoteThread(h_process, None, 0, mem_address, None, 0, None)
```

---

## Fuzzing

### Simple File Fuzzer
```python
import random

def fuzz(data):
    fuzzed = bytearray(data)
    for _ in range(random.randint(1, 10)):
        offset = random.randint(0, len(fuzzed) - 1)
        fuzzed[offset] = random.randint(0, 255)
    return bytes(fuzzed)

# Generate fuzzed files
with open("template.jpg", "rb") as f:
    original = f.read()

for i in range(100):
    with open(f"fuzzed_{i}.jpg", "wb") as out:
        out.write(fuzz(original))
```

### Driver Fuzzing (IOCTL)
```python
device = "\\\\.\\HackSysExtremeVulnerableDriver"
ioctl = 0x222003

handle = kernel32.CreateFileA(device.encode(), 0xC0000000, 0, None, 3, 0, None)

for size in range(1, 256):
    buf = create_string_buffer(b"A" * size)
    out_buf = create_string_buffer(64)
    kernel32.DeviceIoControl(handle, ioctl, buf, len(buf), out_buf, 64, byref(c_ulong()), None)
```

---

## Sulley Framework

### Basic Request
```python
from sulley import *

s_initialize("ftp_user")
if s_block_start("user_cmd"):
    s_string("USER", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("anonymous")
    s_static("\r\n")
s_block_end()
```

### Session Setup
```python
sess = sessions.session(session_filename="ftp_session")
target = sessions.target("127.0.0.1", 21)
sess.add_target(target)
sess.connect(s_get("ftp_user"))
sess.fuzz()
```

---

## IDAPython

### List Functions
```python
for function_ea in Functions():
    name = GetFunctionName(function_ea)
    print("[*] %s at 0x%x" % (name, function_ea))
```

### Find Dangerous Functions
```python
bad_funcs = ["strcpy", "sprintf", "gets", "strcat"]

for func in bad_funcs:
    addr = LocByName(func)
    if addr != BADADDR:
        for ref in XrefsTo(addr):
            print("[>] %s called at: 0x%x" % (func, ref.frm))
```

### Rename Functions
```python
for function_ea in Functions():
    name = GetFunctionName(function_ea)
    if "sub_" in name:
        MakeName(function_ea, "func_%x" % function_ea)
```

### Extract Strings
```python
for i in range(StringQty()):
    s = GetString(StringIndex(i))
    print("[+] String: %s" % s)
```

---

## PyEMU - x86 Emulation

### Setup & Execute
```python
from pyemu import *

emu = Pemu()
emu.set_memory_area(0x1000, 0x1000, PAGE_READWRITE)

shellcode = b"\x90" * 10 + b"\xcc"
emu.set_memory(0x1000, shellcode)
emu.set_register("EIP", 0x1000)

for i in range(10):
    emu.execute()
    print("[*] EIP: 0x%x" % emu.get_register("EIP"))
```

### Instruction Hook
```python
def log_inst(emu):
    eip = emu.get_register("EIP")
    opcode = emu.disasm(eip)
    print("[*] 0x%x: %s" % (eip, opcode))

emu.add_instruction_hook(log_inst)
```

---

## Common Patterns

### Network Socket
```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("192.168.1.100", 80))
sock.send(b"GET / HTTP/1.1\r\n\r\n")
data = sock.recv(1024)
```

### HTTP Request
```python
import requests

r = requests.get("http://target.com/api")
print(r.status_code, r.text)
```

### Subprocess Execution
```python
import subprocess

subprocess.run(["cmd.exe", "/c", "dir"])
subprocess.Popen(["notepad.exe", "file.txt"])
```

---

## Key Windows API Functions

| Function | Purpose |
|----------|---------|
| `CreateProcessA` | Start new process |
| `OpenProcess` | Get process handle |
| `VirtualAllocEx` | Allocate memory in remote process |
| `WriteProcessMemory` | Write to remote process |
| `CreateRemoteThread` | Execute code in remote process |
| `WaitForDebugEvent` | Monitor debug events |
| `GetThreadContext` | Read thread registers |
| `SetThreadContext` | Modify thread registers |
| `DeviceIoControl` | Communicate with drivers |

---

## Development Tools

- **IDE:** Sublime, Eclipse + PyDev, VS Code
- **Debuggers:** PyDbg, Immunity Debugger
- **Disassemblers:** IDA Pro (IDAPython)
- **Emulators:** PyEMU
- **Fuzzing:** Sulley, custom fuzzers

---

## Quick Tips

- Use `byref()` to pass pointers to ctypes
- Always check return values from WinAPI calls
- Use VMs for fuzzing and malware analysis
- Log everything for post-analysis
- Restore original bytes after breakpoints
- Handle exceptions gracefully in hooks
