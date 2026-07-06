# AV/EDR Evasion - Detection & Defense Deep Dive

> **Scope:** How attackers evade antivirus and endpoint detection/response solutions - technique concepts, how each works, what artifacts it leaves, and how defenders detect, hunt, and harden against it. Structured for blue team and purple team practitioners.

✅ **Quick-reference checklists:** [Defense Evasion](../Checklists/Defense-Evasion.md) · [AppLocker Bypass](../Checklists/AppLocker.md)

---

## Table of Contents

1. [EDR Architecture & Detection Layers](#edr-architecture--detection-layers)
2. [Static Evasion Techniques](#static-evasion-techniques)
3. [AMSI Bypass Techniques](#amsi-bypass-techniques)
4. [ETW Tampering](#etw-tampering)
5. [API Hook Evasion](#api-hook-evasion)
6. [Syscall Abuse](#syscall-abuse)
7. [Process Injection Overview](#process-injection-overview)
8. [In-Memory Execution](#in-memory-execution)
9. [Sleep Obfuscation & Memory Evasion](#sleep-obfuscation--memory-evasion)
10. [Behavioral Evasion Techniques](#behavioral-evasion-techniques)
11. [Detection Engineering Priorities](#detection-engineering-priorities)
12. [Defensive Hardening](#defensive-hardening)
13. [Purple Team Validation](#purple-team-validation)

---

## EDR Architecture & Detection Layers

Understanding where EDR detects is essential to understanding what attackers try to bypass - and therefore what defenders must protect.

```
┌──────────────────────────────────────────────────────────────────┐
│  Layer 1: Static File Scanning          (AV signatures, YARA)    │
│  Layer 2: AMSI                          (Script content scanning) │
│  Layer 3: ETW Providers                 (Kernel + user telemetry) │
│  Layer 4: Kernel Callbacks              (Process/thread/image)    │
│  Layer 5: User-Mode API Hooks           (ntdll inline hooks)      │
│  Layer 6: Behavioral Analytics          (ML, rule engines)        │
│  Layer 7: Network Inspection            (DNS, TLS metadata)       │
└──────────────────────────────────────────────────────────────────┘
```

**Key insight for defenders:** Attackers who are "EDR-aware" target specific layers. Detection gaps appear when one layer is bypassed but others aren't compensating. Defense-in-depth across all layers is the goal - no single layer is sufficient.

### How EDR Instruments the Endpoint

**User-mode hooks (most common):** The EDR injects a DLL into every process. That DLL overwrites the first few bytes of sensitive Windows API functions in `ntdll.dll` with a jump to the EDR's inspection code. When a process calls `NtCreateThread`, for example, execution is redirected to the EDR before the syscall happens.

**Kernel callbacks:** EDRs register callback routines in the Windows kernel for events like process creation (`PsSetCreateProcessNotifyRoutine`), image load, and thread creation. These fire regardless of user-mode tampering.

**ETW providers:** Windows Event Tracing provides a high-throughput telemetry channel. EDRs subscribe to ETW providers for PowerShell, .NET CLR activity, DNS, network connections, and more.

**Minifilter drivers:** EDR kernel drivers intercept file system operations to scan files on read/write/execute.

---

## Static Evasion Techniques

### How It Works

Static analysis examines a file's content without executing it - AV signatures, hash matching, YARA rules, and string scanning. Attackers modify payloads so the static signature no longer matches.

**Common techniques:**

| Technique | How | What Changes |
|---|---|---|
| Encryption | XOR, AES encrypt shellcode | Raw bytes no longer match signature |
| Encoding | Base64, hex, custom encoding | Transforms byte patterns |
| Compression | LZMA, zlib compress payload | Alters byte distribution |
| Polymorphism | Mutate code on each generation | New hash/signature per sample |
| PE modification | Change section names, imports, headers | Header-based signatures fail |
| Packing | Runtime unpack/decrypt to memory | No static payload on disk |

### Defender Perspective

**What attackers try to avoid:**
- Known byte sequences (shellcode stubs, string literals)
- Known PE structure characteristics (section names, import tables)
- Known file hashes

**Detection opportunities:**

**Entropy analysis** - Encrypted/compressed payloads have high entropy (close to 8.0 bits/byte). High-entropy sections in PE files are anomalous.

```python
# Detect high-entropy sections in PE files
import math
from collections import Counter

def section_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

# Thresholds:
# Legitimate code:     ~6.0–6.5 entropy
# Compressed data:     ~7.5–8.0 entropy  
# Encrypted shellcode: ~7.8–8.0 entropy
# Flag sections above ~7.2 for investigation
```

**Behavioral detonation** - Even if static evasion succeeds, the payload must execute. Sandbox detonation catches behavior that static misses.

**Memory scanning** - Payloads decrypt at runtime. The decrypted shellcode in memory can then match signatures. EDRs with memory scanning (PE-sieve, Moneta, Elastic memory scanning) catch this post-decrypt.

**YARA - hunt for high-entropy PE sections:**

```yara
import "math"

rule HighEntropyPESection {
    meta:
        description = "PE with high-entropy section - possible packing or encryption"
    condition:
        uint16(0) == 0x5A4D and
        math.entropy(0, filesize) > 7.2
}
```

---

## AMSI Bypass Techniques

### How AMSI Works

AMSI (Antimalware Scan Interface) is a Windows API that allows script hosts to submit content to AV engines before execution. PowerShell, VBScript, JScript, and the .NET CLR all call AMSI before running any script content - so even fully in-memory scripts get scanned.

The core function is `AmsiScanBuffer` in `amsi.dll`. If it returns `AMSI_RESULT_DETECTED`, execution is blocked.

### Evasion Approach: Memory Patching

The most direct bypass patches `AmsiScanBuffer` in memory to always return a "clean" result. Since `amsi.dll` is a user-mode DLL loaded into the PowerShell process, a sufficiently privileged process can modify its own memory.

**What defenders see:**
- A process writes to its own executable memory in `amsi.dll`'s address range
- `VirtualProtect` called on `amsi.dll`'s memory region to make it writable
- Immediately followed by a memory write to that region

### Evasion Approach: Reflection

AMSI's internal state can be manipulated via .NET reflection - accessing private fields in `System.Management.Automation` that control whether AMSI scanning is active.

**What defenders see:**
- Reflection calls targeting `System.Management.Automation` internals
- PowerShell Script Block Logging captures the reflection attempt itself (since AMSI logs before it's bypassed)

### Evasion Approach: PowerShell Downgrade

PowerShell v2 predates AMSI and does not support it. Launching `powershell -version 2` bypasses AMSI entirely - if the v2 engine is installed.

**What defenders see:**
- `powershell.exe` launched with `-version 2` or `-ver 2` in the command line

### Detection

**Event ID 4104 (Script Block Logging)** - Captures PowerShell script content before execution. Even obfuscated bypass attempts are often partially captured. This is the primary AMSI bypass detection mechanism.

```powershell
# Enable Script Block Logging
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $path -Force
Set-ItemProperty $path -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty $path -Name "EnableScriptBlockInvocationLogging" -Value 1
```

**Sigma - AMSI bypass strings in Script Block Log:**

```yaml
title: PowerShell AMSI Bypass Attempt
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'AmsiScanBuffer'
            - 'AmsiInitialize'
            - 'amsiContext'
            - 'amsiSession'
            - 'amsiInitFailed'
            - '[Ref].Assembly.GetType'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001
```

**Sigma - PowerShell v2 downgrade:**

```yaml
title: PowerShell Version 2 Downgrade
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-version 2'
            - '-ver 2'
    condition: selection
level: high
```

**Defensive control - disable PowerShell v2:**

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart
```

---

## ETW Tampering

### How ETW Works

Event Tracing for Windows is a kernel-level logging infrastructure. ETW providers exist for PowerShell, .NET CLR activity, process creation, network connections, DNS, WMI, and more. EDRs subscribe to these channels for telemetry.

### Evasion Approach: Patching EtwEventWrite

`EtwEventWrite` in `ntdll.dll` is the user-mode function that submits events to ETW. Patching it with a `RET` instruction causes all ETW events from that process to silently disappear - the function returns immediately without writing anything.

**What defenders see:**
- `VirtualProtect` + memory write to `ntdll.dll`'s `EtwEventWrite` address in the process
- Sudden absence of expected ETW telemetry from a process that was previously generating it
- EDRs with kernel-mode sensors observe the memory modification even if user-mode telemetry stops

### Evasion Approach: .NET ETW Disable via Reflection

.NET's ETW integration goes through a managed provider. Reflection can access and disable the provider's internal enabled flag, stopping .NET and PowerShell ETW events.

**What defenders see:**
- Reflection targeting ETW-related fields in `System.Management.Automation.Tracing`
- Captured in Script Block Logging if AMSI is still active at time of execution

### Detection

**Kernel callbacks are ETW-tamper-resistant.** EDRs that use kernel driver callbacks for core telemetry are unaffected by user-mode ETW patching. Modern EDRs prioritize kernel-mode collection over ETW for critical events.

**Detect via telemetry gap analysis:** A process that is active but generating zero ETW events (especially PowerShell with no Script Block logs) is itself anomalous.

**Sigma - memory write to ntdll.dll ETW function:**

```yaml
title: Possible EtwEventWrite Patch - ETW Tampering
logsource:
    category: process_access
    product: windows
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\ntdll.dll'
        GrantedAccess|contains: 'WRITE'
    filter:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter
level: high
```

---

## API Hook Evasion

### How EDR Hooks Work

When an EDR's agent DLL is injected into a process, it hooks sensitive API functions in `ntdll.dll` by overwriting the first bytes with a jump to the EDR's inspection code:

```
Normal: Process → ntdll!NtAllocateVirtualMemory → syscall → kernel
Hooked: Process → ntdll!NtAllocateVirtualMemory → [JMP to EDR] → EDR inspects → syscall → kernel
```

The EDR examines parameters and context, then allows or blocks the call.

### Evasion Approach: Unhooking

Attackers restore the original bytes in `ntdll.dll` by reading a fresh unmodified copy from disk and overwriting the hooked in-memory `.text` section. After unhooking, API calls bypass EDR inspection.

**Why it's detectable:**
- Loading `ntdll.dll` from disk and mapping it is unusual for a non-loader process
- Writing to `ntdll.dll`'s executable sections triggers EDRs with kernel-mode sensors
- Some EDRs actively monitor hook integrity and re-hook on modification attempts

### Evasion Approach: Per-Function Unhooking

Restoring only specific functions rather than the entire `.text` section - less noisy, but same detection surface.

### Detection

**Kernel-mode sensors are unaffected by user-mode unhooking.** Kernel callbacks (`PsSetCreateProcessNotifyRoutine`, minifilter driver) don't go through `ntdll.dll` and cannot be removed by user-mode unhooking.

**Sigma - unusual ntdll.dll file reads:**

```yaml
title: Suspicious ntdll.dll Read - Possible Unhooking
logsource:
    category: file_access
    product: windows
detection:
    selection:
        FileName|endswith: '\ntdll.dll'
        AccessMask|contains: 'READ_DATA'
    filter:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter
level: medium
```

**Sysmon Event 7 (ImageLoad):** Detect `ntdll.dll` being mapped in unusual contexts outside normal load paths.

---

## Syscall Abuse

### How It Works

Windows API calls ultimately translate to syscalls - numbered kernel services invoked via the `syscall` CPU instruction. Normally, code calls a wrapper in `ntdll.dll` which sets the syscall number and executes `syscall`. EDR hooks intercept at the `ntdll.dll` layer.

**Direct syscalls:** Custom assembly stubs that set the syscall number and execute `syscall` directly - bypassing `ntdll.dll` entirely and therefore bypassing all EDR hooks on that DLL. Tools like SysWhispers generate these stubs at compile time or resolve syscall numbers at runtime.

**Indirect syscalls:** Rather than placing the `syscall` instruction in attacker code (which has an anomalous call stack origin), the attacker locates a legitimate `syscall` gadget inside `ntdll.dll` and jumps to it after setting up the syscall number. The call stack then appears to originate from `ntdll.dll` - harder to detect than direct syscalls.

### What Makes This Detectable

**Call stack analysis:** For legitimate code, a call to `NtAllocateVirtualMemory` should have a stack tracing back through `ntdll.dll` → calling DLL → application. Direct syscalls produce a call stack originating in unusual memory (heap allocation, anonymous MEM_PRIVATE) - anomalous and detectable by EDRs with call stack inspection.

**Kernel ETW:** Kernel-level syscall auditing can detect anomalous patterns without relying on user-mode telemetry.

**Syscall number portability issues:** Tools hardcoding syscall numbers may behave incorrectly on different OS versions, producing detectable errors or crashes.

### Detection

EDRs with **kernel-mode telemetry and call stack analysis** are required to reliably detect syscall abuse. User-mode-only EDRs are blind to direct syscalls by design.

**Defensive implication:** When evaluating EDR products, test specifically for direct/indirect syscall detection - ask vendors for documentation on how they handle this. It's a known gap in many user-mode-first products.

---

## Process Injection Overview

### What It Is

Process injection places and executes attacker code within another (often legitimate) process's memory space. The goal: run malicious code under a trusted process identity, evading process-based detections and inheriting the target process's permissions.

### Common Injection Variants and Their Artifacts

**Classic VirtualAlloc + WriteProcessMemory + CreateRemoteThread**
The foundational injection method. Allocates memory in target, writes shellcode, spawns a thread to execute it. Generates the most telemetry and is the most heavily signatured - `CreateRemoteThread` on a foreign process is a loud signal.

**APC Injection**
Queues code execution via Asynchronous Procedure Calls on an existing thread. Executes when the thread enters an alertable wait state. *Early Bird* variant queues the APC into a freshly-created suspended process before it starts - stealthier because the thread never "normally" runs and the APC fires at startup.

**Thread Hijacking**
Opens an existing thread, suspends it, overwrites its instruction pointer to point at shellcode, then resumes. Avoids `CreateRemoteThread` but generates `NtGetContextThread`/`NtSetContextThread` calls on a foreign thread - detectable via process access monitoring.

**Process Hollowing**
Creates a legitimate process in suspended state, unmaps its memory, replaces it with a malicious PE, resumes. Externally looks like a legitimate process; internally executes malicious code. Sysmon Event 25 (ProcessTampering) is specifically designed to catch this.

**Module Stomping / DLL Stomping**
Loads a legitimate DLL into a process then overwrites its memory with shellcode. The shellcode appears to reside within a legitimate module - evades memory scanners that trust image-backed memory regions. Detectable via integrity checking of loaded module content vs. on-disk copy.

**Process Doppelgänging**
Uses NTFS transactions to write a payload, create a process from the transacted file, then roll back the transaction. The file technically never existed on disk. Complex and fragile; detectable via transaction handle anomalies.

**Reflective DLL Injection**
A DLL containing its own loader function (`ReflectiveLoader`). When called, it maps itself into memory, resolves imports, and executes - without any `LoadLibrary` call. Widely used by C2 frameworks. Leaves no entry in the process's module list, but PE headers exist in `MEM_PRIVATE` memory and are found by memory scanners.

### Detection

**API call sequences** - Most injection techniques involve recognizable sequences:
- `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` (classic)
- `CreateProcess` (suspended) → `NtUnmapViewOfSection` → `VirtualAllocEx` → `ResumeThread` (hollowing)
- `QueueUserAPC` on a foreign process thread (APC injection)

**Memory region characteristics:**
- RWX memory (read-write-execute simultaneously) - almost never legitimate
- `MEM_PRIVATE` executable memory not backed by a file on disk
- PE headers appearing in heap-allocated regions

**Sysmon Event IDs:**
- **Event 8:** `CreateRemoteThread` - injecting a thread into another process
- **Event 10:** `ProcessAccess` - one process reading/writing another's memory
- **Event 25:** `ProcessTampering` - process hollowing indicator

```yaml
title: CreateRemoteThread into Non-Child Process
logsource:
    category: create_remote_thread
    product: windows
detection:
    selection:
        EventID: 8
    filter:
        SourceImage|contains:
            - '\svchost.exe'
            - '\werfault.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter
level: high
tags:
    - attack.defense_evasion
    - attack.t1055

---

title: Suspicious Cross-Process Memory Write
logsource:
    category: process_access
    product: windows
detection:
    selection:
        EventID: 10
        GrantedAccess|contains: '0x1F0FFF'
    filter:
        SourceImage|contains:
            - '\MsMpEng.exe'
            - '\csrss.exe'
            - '\lsass.exe'
    condition: selection and not filter
level: medium
```

---

## In-Memory Execution

### What It Is

Executing code without writing a recognizable payload to disk - evades file-based AV and reduces forensic artifacts.

### Reflective DLL Loading

A DLL with its own `ReflectiveLoader` export that maps itself into memory without calling `LoadLibrary`. No file on disk, no module list entry. Commonly used by Cobalt Strike, Metasploit, and most commercial C2 frameworks.

**Detection:** Memory scanners (PE-sieve, Moneta) find PE headers in `MEM_PRIVATE` regions. Sysmon Event 7 won't fire (no `LoadLibrary` call), but module list integrity checking reveals the gap between what's listed and what's in memory.

### .NET Assembly Execution in Memory (execute-assembly)

.NET assemblies can be loaded and executed entirely from memory by hosting the CLR in a native process. C2 frameworks use this to run post-exploitation tools (Rubeus, Seatbelt, SharpHound) without writing them to disk.

**Detection:**
- ETW .NET CLR provider records assembly loads - visible if ETW is intact
- `clr.dll` or `clrjit.dll` loaded into processes that have no business hosting .NET (Sysmon Event 7)
- Behavioral anomaly: process hosting CLR for the first time with no prior .NET activity

### PowerShell Without powershell.exe

Hosting `System.Management.Automation.dll` in a custom process allows PowerShell command execution without launching `powershell.exe` - evades PowerShell-specific process monitoring.

**Detection:**
- `System.Management.Automation.dll` loaded into non-PowerShell processes (Sysmon Event 7)
- AMSI still fires if intact (the DLL still calls AMSI), so Script Block Logging still captures content
- Behavioral: process making PowerShell-typical API calls with an unexpected image path

---

## Sleep Obfuscation & Memory Evasion

### The Problem (from Attacker's View)

When a C2 implant is sleeping between beacons, it sits in memory doing nothing. Memory scanners can scan all executable memory regions, find the shellcode, and match signatures. Sleep obfuscation makes the implant's memory unreadable during sleep.

### How It Works (Ekko / Foliage Pattern)

These techniques encrypt the implant's own memory region before sleeping:

1. Change memory protection from RX (execute) to RW (read-write, non-executable)
2. Encrypt the shellcode in place (XOR or AES)
3. Sleep
4. Decrypt the shellcode
5. Restore RX protection
6. Resume execution

During the sleep window: the shellcode region is RW with encrypted content - no signature can match, and the region is non-executable so behavior-based scanners ignore it.

### Stack Spoofing

A sleeping thread's call stack can be inspected by EDRs. If the top frame traces back to shellcode or anonymous memory, it's suspicious. Stack spoofing overwrites saved return addresses during sleep so the stack appears to originate from a normal Windows API call path.

### What Defenders Look For

**Memory permission transitions:** RX → RW → RX on `MEM_PRIVATE` memory in a short time window. Legitimate code almost never changes its own protections in this pattern.

**Timing correlation:** Permission changes that occur at predictable beacon-interval timing correlate with sleep obfuscation cycles.

**Snapshot-based scanning:** Scanners that run at random intervals (not predictable schedules) have a higher chance of catching the decrypted execution window.

**Thread call stack analysis at random intervals:** Catching the implant's thread in its active (decrypted) state rather than only during the protected sleep.

```yaml
title: Suspicious RX to RW Memory Protection Change
logsource:
    product: windows
    category: process_access
detection:
    selection:
        EventID: 10
        CallTrace|contains: 'VirtualProtect'
    filter:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter
level: medium
```

---

## Behavioral Evasion Techniques

### Parent Process Spoofing

Windows process creation allows specifying a parent process handle via extended attributes. This lets malware make `cmd.exe` appear to have been spawned by `explorer.exe` (normal) rather than by the actual malicious parent.

**Detection:** Sysmon logs both the actual spawning process and the reported parent. Correlating Sysmon Event 1 with Event 4688 `ParentProcessId` reveals the discrepancy. EDRs with kernel-level process tracking see through this.

```yaml
title: Mismatched Parent-Child Process Relationship
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Suspicious: cmd/powershell reporting Office app as parent
        ParentImage|contains:
            - '\winword.exe'
            - '\excel.exe'
            - '\outlook.exe'
        Image|contains:
            - '\powershell.exe'
            - '\cmd.exe'
            - '\wscript.exe'
            - '\mshta.exe'
    condition: selection
level: high
```

### Fork-and-Run / Spawnto Evasion

C2 frameworks (especially Cobalt Strike) traditionally spawn a new process to execute post-exploitation tasks, then kill it. The spawned process binary (`spawnto`) is configurable. Default values (`WerFault.exe`, `rundll32.exe`) are heavily signatured.

**Detection:** Alert on short-lived processes spawned by unusual parents. `WerFault.exe` appearing outside actual crash contexts, or `rundll32.exe` with no arguments, are classic tells. Behavioral analytics on process lifetime (processes that live < 5 seconds) are useful here.

### Token Impersonation & Manipulation

Windows security tokens determine a process's identity and privileges. Attackers steal tokens from other processes or create new ones to impersonate privileged accounts (SYSTEM, Domain Admin) or blend with expected process identity.

**Detection:**
- Event 4624 Logon Type 9 (NewCredentials) - token created from supplied credentials
- Sysmon Event 10 with `PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE` - token duplication pattern
- Process running under an identity inconsistent with its image path (e.g., `notepad.exe` running as SYSTEM)

### Command Line Obfuscation

Attackers obfuscate PowerShell and cmd.exe command lines to evade string-matching detection rules:
- Environment variable insertion: `%COMSPEC%` instead of `cmd.exe`
- String concatenation: `po`+`wer`+`shell`
- `^` character insertion in cmd.exe: `po^wer^shell`
- Encoded commands: `-EncodedCommand <base64>`
- Whitespace manipulation

**Detection:** Script Block Logging decodes obfuscated PowerShell before logging - so command-line obfuscation is often irrelevant if Script Block Logging is enabled. AMSI also sees the decoded content before execution. For cmd.exe obfuscation, process command line logging (Event 4688 with command line enabled) combined with regex detection:

```yaml
title: Suspicious PowerShell Encoded Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand '
            - ' -ec '
    condition: selection
level: medium

---

title: PowerShell with Excessive String Concatenation
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|re: '(\+\s*["\']){4,}'
    condition: selection
level: low
```

---

## Detection Engineering Priorities

### Coverage Matrix

| Evasion Technique | Primary Detection | Backup Detection | EDR Dependency |
|---|---|---|---|
| Static obfuscation | Entropy analysis, sandbox detonation | Memory scanning post-execution | Low |
| AMSI bypass | Script Block Log (Event 4104) | ETW .NET provider | Medium |
| ETW patching | Kernel callback telemetry | Memory write to ntdll | High |
| API unhooking | Kernel callbacks (unaffected) | File read of ntdll.dll | High |
| Direct syscalls | Call stack analysis | Kernel ETW | High |
| Process injection | Sysmon 8/10, memory scanning | Behavioral analytics | Medium |
| Reflective DLL load | Memory scanner (PE in MEM_PRIVATE) | Module list gap | Medium |
| Sleep obfuscation | RX→RW→RX transitions, snapshot scan | Timing correlation | Medium |
| Parent spoofing | Event 4688 parent correlation | Sysmon Event 1 | Low |
| Token manipulation | Event 4624/4648, Sysmon 10 | Identity delta monitoring | Low |

### Tiered Alert Model

**Tier 1 - High confidence, alert immediately:**
- AMSI bypass strings in Script Block Log
- `CreateRemoteThread` into non-child processes from non-system binaries
- LSASS process access from non-security tools
- Sysmon Event 25 (ProcessTampering)
- `ntdll.dll` memory write from non-OS process

**Tier 2 - Medium confidence, investigate:**
- High-entropy PE from temp/user/AppData directories
- PowerShell encoded commands with outbound network connections
- `clr.dll` loaded into processes with no prior .NET history
- Short-lived processes (< 5 seconds) spawned from Office applications
- `MEM_PRIVATE` RX allocations exceeding 1MB in non-dev processes

**Tier 3 - Low confidence, trend and baseline:**
- Command line obfuscation patterns
- Unusual parent-child relationships without other indicators
- Processes with very few loaded modules making network connections

---

## Defensive Hardening

### EDR Selection Criteria

When evaluating EDR products, prioritize:
- **Kernel-mode driver** - resists user-mode unhooking
- **Call stack analysis** - detects direct/indirect syscalls
- **Memory scanning** - catches reflective loads and sleep-obfuscated implants
- **ETW-independent telemetry** - not solely reliant on patchable ETW providers
- **Behavioral ML** - catches novel evasions that signature rules miss

Ask vendors specifically: *How does your product detect direct syscalls? How does it handle ntdll unhooking?* Vague answers indicate user-mode-only architecture.

### Windows Security Feature Checklist

```powershell
# 1. Credential Guard - VBS-protected LSA, prevents most LSASS dumping
# Enable via GPO: Computer Config → Admin Templates → System → Device Guard

# 2. LSASS Protected Process Light (PPL) - requires Secure Boot
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1

# 3. Disable WDigest - prevents cleartext credentials in LSASS
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 0

# 4. Disable PowerShell v2 - removes AMSI downgrade path
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart

# 5. Enable PowerShell Script Block Logging
$psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $psPath -Force
Set-ItemProperty $psPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty $psPath -Name "EnableScriptBlockInvocationLogging" -Value 1

# 6. Enable process creation command line logging
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# 7. Attack Surface Reduction rules
$asr = @(
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",  # Block Office child processes
    "3b576869-a4ec-4529-8536-b80a7769e899",  # Block JS/VBS from downloaded content
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",  # Block Office macro injections
    "d1e49aac-8f56-4280-b9ba-993a6d77406c"   # Block PSExec/WMI process creation
)
foreach ($id in $asr) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $id `
        -AttackSurfaceReductionRules_Actions Enabled
}
```

### Audit Policy

```powershell
# Process creation + command line
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Process Termination" /success:enable

# Privilege use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Kernel object access (LSASS)
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable

# DPAPI (credential decryption activity)
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
```

### Sysmon Deployment

```xml
<!-- Key Sysmon config elements for evasion detection -->
<EventFiltering>
    <!-- Event 8: CreateRemoteThread -->
    <CreateRemoteThread onmatch="include">
        <TargetImage condition="is not">C:\Windows\system32\svchost.exe</TargetImage>
    </CreateRemoteThread>

    <!-- Event 10: ProcessAccess - LSASS and cross-process -->
    <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
    </ProcessAccess>

    <!-- Event 7: ImageLoad - unsigned DLLs -->
    <ImageLoad onmatch="include">
        <Signed condition="is">false</Signed>
    </ImageLoad>

    <!-- Event 25: ProcessTampering - hollowing indicator -->
    <ProcessTampering onmatch="include" />
</EventFiltering>
```

Recommended configs:
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)

---

## Purple Team Validation

Use purple team exercises to verify that detections actually fire against real evasion techniques before attackers test them for you.

### Atomic Red Team

```powershell
# Install
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser

# Test AMSI bypass
Invoke-AtomicTest T1562.001 -TestNumbers 1,2,3

# Test process injection
Invoke-AtomicTest T1055 -TestNumbers 1,2,3

# Test PowerShell obfuscation and execution
Invoke-AtomicTest T1059.001

# Test credential dumping
Invoke-AtomicTest T1003.001
```

### VECTR for Gap Tracking

VECTR (vectr.io) tracks purple team exercises against MITRE ATT&CK and maintains a living record of which techniques are detected vs. which are blind spots. Essential for communicating coverage to stakeholders and tracking improvement over time.

### After Each Test - Ask These Questions

- Did the alert fire? At what layer?
- What's the false positive rate of this detection in production?
- If the attacker slightly modified the technique, would detection still work?
- What's the mean time to detect (MTTD)?
- Which layer would have caught this if the primary layer was bypassed?

The goal is not just "does the alert fire" but **resilience across layers** - if one layer is bypassed, the next one should still catch it.

---

## Analysis Environments & Tooling Reference

A complete analyst toolkit spans both platforms. The right tool depends on what you're analyzing and where.

### Windows Analysis Environment

**FLARE VM** - Mandiant's Windows-based malware analysis distribution. Installs on top of a standard Windows VM and deploys 100+ analysis tools automatically. The Windows equivalent of REMnux.

```powershell
# Install FLARE VM on a clean Windows 10/11 VM
# https://github.com/mandiant/flare-vm
(New-Object net.webclient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1', "$env:USERPROFILE\Downloads\install.ps1")
Unblock-File "$env:USERPROFILE\Downloads\install.ps1"
Set-ExecutionPolicy Unrestricted -Force
.\install.ps1
```

Key tools installed by FLARE VM:

| Tool | Purpose |
|---|---|
| x64dbg / x32dbg | Windows debugger - step through malware execution |
| IDA Free / Ghidra | Disassembly and decompilation |
| PE-bear | PE file editor and viewer |
| CFF Explorer | PE structure inspection |
| PEiD / Detect-It-Easy | Packer/compiler detection |
| Procmon | Real-time process/file/registry monitoring |
| Process Hacker | Advanced process and memory viewer |
| Regshot | Registry snapshot diff - before/after malware run |
| Wireshark | Packet capture and analysis |
| FakeNet-NG | Simulated network for malware C2 interception |
| CyberChef | Data decoding - base64, XOR, gzip, hex, any combination |
| dnSpy | .NET assembly decompiler and debugger |
| de4dot | .NET deobfuscator |

**Sysinternals Suite** - Microsoft's essential Windows analysis toolkit. Available at `https://live.sysinternals.com` or installable via winget.

```powershell
winget install Microsoft.Sysinternals.ProcessMonitor
winget install Microsoft.Sysinternals.ProcessExplorer
winget install Microsoft.Sysinternals.Autoruns
winget install Microsoft.Sysinternals.TCPView
winget install Microsoft.Sysinternals.Sysmon

# Or download the full suite
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile SysinternalsSuite.zip
Expand-Archive SysinternalsSuite.zip -DestinationPath C:\Tools\Sysinternals\
```

| Sysinternals Tool | What It Shows | Evasion Relevance |
|---|---|---|
| **Process Explorer** | Full process tree, DLLs loaded, handles, strings | Spot injected DLLs, hollow processes, unsigned modules |
| **Process Monitor** | Real-time file, registry, network, process events | Catch payload drops, registry persistence, C2 callbacks |
| **Autoruns** | Everything that runs at startup, all persistence locations | Find persistence mechanisms across 20+ autostart locations |
| **TCPView** | Live network connections per process | Identify C2 beacons, unusual outbound connections |
| **VMMap** | Detailed virtual memory map of a process | Spot MEM_PRIVATE executable regions, injected code |
| **Handle** | Open handles per process | Find suspicious cross-process handle ownership |
| **Strings** | Extract printable strings from binaries | Quick triage - find C2 domains, function names, paths |
| **Sigcheck** | Verify code signing on executables | Find unsigned or fake-signed binaries |

**PE-sieve** (Windows) - Scan running processes for injected code, hollowing, and reflective loads:

```powershell
# Download PE-sieve
Invoke-WebRequest -Uri "https://github.com/hasherezade/pe-sieve/releases/latest/download/pe-sieve64.exe" -OutFile pe-sieve64.exe

# Scan a specific process
.\pe-sieve64.exe /pid 4892

# Scan all processes
Get-Process | ForEach-Object {
    .\pe-sieve64.exe /pid $_.Id /quiet
}

# Scan with dump (saves detected artifacts to disk for further analysis)
.\pe-sieve64.exe /pid 4892 /dump 3

# Output interpretation:
# [*] Found: 1 modified module(s)
# INJECTED: virtual address 0x1F4000000 - shellcode or reflective DLL
# PE file (reflective) - PE header in private memory, not in module list
# Image replaced  - process hollowing detected
```

**Moneta** (Windows) - In-memory IOC scanner, finds anomalous memory regions:

```powershell
# Download from https://github.com/forrest-orr/moneta
.\Moneta64.exe -m ioc -p 4892     # Scan specific PID
.\Moneta64.exe -m ioc             # Scan all processes
.\Moneta64.exe -m ioc -e          # Extended scan with entropy analysis

# What it flags:
# MEM_PRIVATE executable regions not backed by a file
# PE headers in unexpected locations
# Regions with abnormally high entropy (encrypted payloads)
# Threads with start addresses in anomalous memory
```

**CyberChef** (Windows/Linux/Web) - The Swiss army knife for decoding obfuscated content. Runs in browser at `https://gchq.github.io/CyberChef/` or as a local install.

```
# Common recipes for malware analysis:

# Decode PowerShell encoded command
From Base64 → Decode text (UTF-16LE)

# Decode a base64+gzip payload (common PowerShell cradle)
From Base64 → Gunzip → Extract strings

# XOR decode with known key
XOR (key: 0x41, scheme: Standard)

# Decode obfuscated JavaScript
JavaScript Beautify → Extract URLs

# Detect and decode multiple layers automatically
"Magic" operation - detects encoding and applies appropriate decoding

# Decode a hex-encoded shellcode blob
From Hex → Disassemble x86 (32-bit or 64-bit)
```

**Windows Sandbox** - Built-in lightweight VM for quick behavioral detonation, no setup required:

```powershell
# Enable Windows Sandbox (requires Windows 10/11 Pro or Enterprise)
Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online -NoRestart

# Launch: Start Menu → Windows Sandbox
# Drop suspicious file in, run it, observe behavior
# Sandbox is fully disposable - wiped on close
# Limitation: no persistence across sessions, limited network visibility
```

**Regshot** (Windows) - Take a registry/filesystem snapshot before and after running a suspicious binary to see exactly what changed:

```
1. Open Regshot, click "1st shot" → scans registry + optional filesystem
2. Run the suspicious binary
3. Click "2nd shot"
4. Click "Compare" → generates a report of all additions, deletions, modifications
# Reveals: persistence keys, dropped files, service creation, scheduled tasks
```

---

### Linux Analysis Environment

**REMnux** - The Linux counterpart to FLARE VM. A Ubuntu-based distro packed with malware analysis tools. Use alongside FLARE VM for cross-platform analysis pipelines.

```bash
# Install REMnux on Ubuntu (converts existing install)
wget https://REMnux.org/remnux-cli
mv remnux-cli /usr/local/bin/remnux
chmod +x /usr/local/bin/remnux
remnux install

# Or download the pre-built OVA:
# https://remnux.org/get-remnux/
```

Key REMnux tools:

| Tool | Purpose |
|---|---|
| Volatility 3 | Memory forensics - analyze RAM dumps |
| YARA | Pattern matching across files and memory |
| radare2 / Cutter | Disassembly and reverse engineering |
| Ghidra | NSA decompiler (also on Windows) |
| pestudio | PE file static analysis |
| ssdeep | Fuzzy hashing - find similar malware samples |
| exiftool | Metadata extraction from files |
| binwalk | Firmware and binary analysis, extract embedded files |
| oledump | Analyze malicious Office documents |
| pdfid / pdf-parser | Analyze malicious PDFs |
| vmonkey | VBA macro emulator for Office documents |
| NetworkMiner | PCAP analysis, extracts files transferred over network |
| Wireshark / tshark | Packet capture and analysis |
| FakeNet-NG | Linux version - intercept malware C2 traffic |
| inetsim | Simulate internet services for malware analysis |

**Volatility 3** (Linux/Windows/macOS) - Memory forensics framework. Analyze RAM dumps to find injected code, hidden processes, network connections, and credentials:

```bash
# Install
pip3 install volatility3

# Or clone
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3 && pip3 install -r requirements.txt

# Identify OS profile from dump
python3 vol.py -f memory.dmp windows.info

# List processes (catches hidden processes via different methods)
python3 vol.py -f memory.dmp windows.pslist      # Standard process list
python3 vol.py -f memory.dmp windows.pstree      # Process tree with parent-child
python3 vol.py -f memory.dmp windows.psscan      # Scan memory for EPROCESS blocks (finds hidden)

# Find injected code - the core evasion detection use case
python3 vol.py -f memory.dmp windows.malfind     # Find MEM_PRIVATE executable regions with PE headers
                                                  # This is the primary injection/hollowing detector

# Network connections
python3 vol.py -f memory.dmp windows.netstat     # Active connections at time of capture
python3 vol.py -f memory.dmp windows.netscan     # Scan for connection structures (finds closed connections too)

# DLLs loaded per process
python3 vol.py -f memory.dmp windows.dlllist --pid 4892

# Dump a suspicious process's memory for further analysis
python3 vol.py -f memory.dmp windows.memmap --pid 4892 --dump

# Extract all executables from memory (catches reflective loads)
python3 vol.py -f memory.dmp windows.dumpfiles --pid 4892

# Detect process hollowing
python3 vol.py -f memory.dmp windows.hollowprocesses

# Dump LSASS for credential analysis (defender use: verify what's accessible)
python3 vol.py -f memory.dmp windows.lsadump

# Volatility malfind output interpretation:
# Process: svchost.exe  PID: 4892  Address: 0x1F4000000
# Vad Tag: VadS  Protection: PAGE_EXECUTE_READWRITE   ← RWX = suspicious
# 4d 5a 90 00 ...                                     ← MZ header = PE in memory
```

**AVML** - Linux memory acquisition tool (Microsoft):

```bash
# Acquire memory from a live Linux system
wget https://github.com/microsoft/avml/releases/latest/download/avml
chmod +x avml
sudo ./avml /tmp/memory.lime

# Then analyze with Volatility
python3 vol.py -f /tmp/memory.lime linux.pslist
```

**Cutter / rizin** (Linux/Windows/macOS) - Open-source GUI reverse engineering platform, Rizin-based:

```bash
# Install on Linux
sudo snap install cutter

# Install rizin CLI
git clone https://github.com/rizinorg/rizin
cd rizin && meson build && ninja -C build && sudo ninja -C build install

# Quick static analysis of suspicious binary
rizin -A suspicious.exe   # Analyze and auto-identify functions
[0x00401000]> afl          # List all functions
[0x00401000]> pdf @ main   # Disassemble main function
[0x00401000]> iz           # List strings
[0x00401000]> ii           # List imports
```

**pwndbg / peda** (Linux) - GDB extensions that add malware/exploit analysis capabilities:

```bash
# Install pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Useful for stepping through Linux malware or shellcode
gdb ./suspicious_binary
# pwndbg adds: heap visualization, ROP chain search, memory search,
# register highlighting, backtrace enhancement
```

**CAPE Sandbox** (Linux-hosted) - Open-source automated malware analysis platform, self-hosted:

```bash
# CAPE runs on Ubuntu and provides behavioral analysis, memory dumps,
# config extraction for known malware families (Cobalt Strike, Emotet, etc.)
# https://github.com/kevoreilly/CAPEv2

# Key capability: automatically extracts C2 configs from unpacked malware
# Recognizes 500+ malware families and extracts IOCs automatically
```

---

### Cross-Platform Tools

These run natively on both Windows and Linux:

| Tool | Windows | Linux | Purpose |
|---|---|---|---|
| **Ghidra** | `ghidraRun.bat` | `./ghidraRun` | NSA decompiler, full RE suite |
| **Wireshark** | GUI installer | `apt install wireshark` | PCAP analysis |
| **CyberChef** | Browser / Electron | Browser / Node | Encoding/decoding Swiss army knife |
| **YARA** | `yara64.exe` | `apt install yara` | Pattern matching |
| **Volatility 3** | `python vol.py` | `python3 vol.py` | Memory forensics |
| **Sigma** | `sigmac` (Python) | `sigmac` (Python) | Detection rule format |
| **Atomic Red Team** | PowerShell module | Bash executor | Purple team testing |
| **CrackMapExec** | `pip install cme` | `apt install crackmapexec` | SMB/AD lateral movement testing |
| **Impacket** | `pip install impacket` | `pip3 install impacket` | Windows protocol toolkit |
| **Hashcat** | `hashcat.exe` | `hashcat` | Password/hash cracking |
| **VECTR** | Docker (Windows) | Docker Compose | Purple team tracking |

---

### Choosing the Right Environment

```
Analyzing a Windows binary?
  → Start on Windows: FLARE VM + x64dbg + Process Monitor + PE-sieve
  → Static analysis: Ghidra or IDA (both platforms)
  → Memory forensics: Volatility 3 (either platform, Windows symbols needed)

Analyzing a Linux ELF binary?
  → REMnux + pwndbg + rizin/Cutter
  → Dynamic: ltrace/strace + gdb + pwndbg

Decoding obfuscated scripts/payloads?
  → CyberChef (any platform, browser-based)
  → PowerShell payloads: Windows with Script Block Logging enabled + CyberChef

Full behavioral sandbox?
  → Windows malware: Windows Sandbox (quick) or CAPE (thorough)
  → Linux malware: CAPE on Ubuntu or manual REMnux + inetsim

Memory forensics on acquired dump?
  → Volatility 3 on Linux (faster) or Windows (same result)
  → pe-sieve for targeted process scan (Windows only)
  → Moneta for full process memory sweep (Windows only)
```

---

## References

- [MITRE ATT&CK: Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005/)
- [PE-sieve - memory scanner](https://github.com/hasherezade/pe-sieve)
- [Moneta - in-memory IOC scanner](https://github.com/forrest-orr/moneta)
- [FLARE VM - Windows malware analysis distro](https://github.com/mandiant/flare-vm)
- [REMnux - Linux malware analysis distro](https://remnux.org/)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/)
- [Ghidra](https://ghidra-sre.org/)
- [Cutter / rizin](https://cutter.re/)
- [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2)
- [Elastic: Detecting Evasion with Memory Signatures](https://www.elastic.co/security-labs/detecting-cobalt-strike-with-memory-signatures)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [VECTR Purple Team Platform](https://vectr.io/)
- [Sysmon Config (SwiftOnSecurity)](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sysmon-Modular (olafhartong)](https://github.com/olafhartong/sysmon-modular)
- [hasherezade malware analysis blog](https://hshrzd.wordpress.com/)
- [Windows Security Baselines (Microsoft)](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
- [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
