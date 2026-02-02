# 🧠 Volatility 3 Memory Forensics Guide

**Volatility** is the industry-standard open-source framework for memory forensics. It enables analysts to extract digital artifacts from volatile memory (RAM) dumps, revealing evidence that may not exist on disk—running processes, network connections, injected code, encryption keys, and more.

This guide covers Volatility 3 installation, memory acquisition, and comprehensive analysis techniques for Windows memory forensics.

---

## 🎯 Why Memory Forensics?

Memory analysis reveals artifacts that disk forensics cannot:

| Artifact | Disk Forensics | Memory Forensics |
|----------|----------------|------------------|
| Running processes | ❌ | ✅ Full details including hidden |
| Network connections | Limited (logs) | ✅ Active at capture time |
| Encryption keys | ❌ | ✅ In cleartext |
| Injected code/shellcode | ❌ | ✅ Detectable |
| Malware in memory-only | ❌ | ✅ Capturable |
| Command history | Limited | ✅ Console buffers |
| Clipboard contents | ❌ | ✅ Recoverable |
| Decrypted data | ❌ | ✅ Before encryption |
| Deleted/hidden processes | ❌ | ✅ Via pool scanning |

---

## 📋 Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows/Linux/macOS | Linux (Ubuntu 22.04) |
| Python | 3.7+ | 3.10+ |
| RAM | 8 GB | 16 GB+ |
| Storage | 2x size of memory dump | SSD recommended |

### Required Software

- Python 3.7 or higher
- pip (Python package manager)
- Git (for installation from source)

---

## 📥 Part 1: Installation

### Method 1: pip Installation (Recommended)

```bash
# Install Volatility 3
pip3 install volatility3

# Verify installation
vol --help
```

### Method 2: Installation from Source

```bash
# Clone the repository
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3

# Install dependencies
pip3 install -r requirements.txt

# Run directly
python3 vol.py --help
```

### Method 3: Docker Installation

```bash
# Pull the official image
docker pull sk4la/volatility3

# Run with a memory dump
docker run -v /path/to/dumps:/dumps sk4la/volatility3 -f /dumps/memory.dmp windows.pslist
```

### Installing Symbol Tables

Volatility 3 requires symbol tables (ISF files) to analyze memory dumps. These are downloaded automatically but can be pre-installed:

```bash
# Create symbols directory
mkdir -p ~/.local/lib/volatility3/symbols

# Download Windows symbols (automatic on first run)
# Or manually from: https://downloads.volatilityfoundation.org/volatility3/symbols/

# For offline environments, download and extract:
cd ~/.local/lib/volatility3/symbols
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip
```

### Verify Installation

```bash
# List available plugins
vol --help | grep windows

# Or from source
python3 vol.py --help | grep windows
```

---

## 💾 Part 2: Memory Acquisition

Before analysis, you need a memory dump. Several tools can capture RAM from live systems.

### Windows Memory Acquisition

#### DumpIt (Recommended for Simplicity)

Free, portable, and simple:

```cmd
:: Run as Administrator
DumpIt.exe
```

Output: Creates a raw memory dump in the current directory.

#### WinPMEM (Rekall Project)

```cmd
:: Capture to raw format
winpmem_mini_x64.exe output.raw

:: Capture to AFF4 format (compressed)
winpmem_mini_x64.exe -o output.aff4
```

#### FTK Imager

1. Download from AccessData (free)
2. File → Capture Memory
3. Select destination path
4. Include pagefile (optional)

#### Magnet RAM Capture

Free GUI tool from Magnet Forensics:

1. Run as Administrator
2. Select output location
3. Click "Capture Memory"

### Linux Memory Acquisition

#### LiME (Linux Memory Extractor)

```bash
# Install dependencies
sudo apt install -y build-essential linux-headers-$(uname -r)

# Clone and build LiME
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make

# Capture memory (as root)
sudo insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"
```

#### AVML (Microsoft)

```bash
# Download AVML
wget https://github.com/microsoft/avml/releases/latest/download/avml

# Capture memory
sudo ./avml memory.lime
```

### Virtual Machine Memory

| Hypervisor | Method |
|------------|--------|
| VMware | Suspend VM → `.vmem` file in VM directory |
| VirtualBox | `VBoxManage debugvm <VM> dumpguestcore --filename dump.elf` |
| Hyper-V | Checkpoint → Export → `.bin` file |
| KVM/QEMU | `virsh dump <domain> memory.dump --memory-only` |

### Memory Dump Formats

| Format | Extension | Tools | Notes |
|--------|-----------|-------|-------|
| Raw | `.raw`, `.mem`, `.bin` | Most tools | Uncompressed, largest |
| LiME | `.lime` | LiME | Linux format with metadata |
| AFF4 | `.aff4` | WinPMEM | Compressed, with metadata |
| Crash Dump | `.dmp` | Windows | Kernel/complete dumps |
| VMware | `.vmem` | VMware | Suspended VM state |
| ELF Core | `.elf`, `.core` | VirtualBox, QEMU | Standard format |
| Hibernation | `hiberfil.sys` | Windows | Compressed RAM snapshot |

---

## 🛠️ Part 3: Basic Usage

### Command Syntax

```bash
# Standard syntax
python3 vol.py -f <MEMORY_DUMP> <PLUGIN> [OPTIONS]

# With output file
python3 vol.py -f memory.dmp windows.pslist > processes.txt

# JSON output for scripting
python3 vol.py -f memory.dmp -r json windows.pslist > processes.json

# Specify symbol path
python3 vol.py -s /path/to/symbols -f memory.dmp windows.pslist
```

### Common Global Options

| Option | Description |
|--------|-------------|
| `-f <file>` | Path to memory dump file |
| `-r <format>` | Output format: pretty, json, csv |
| `-o <dir>` | Output directory for dumped files |
| `-s <path>` | Additional symbol path |
| `-v` | Verbose output |
| `-p` | Parallelism (number of threads) |
| `--help` | Show help for plugin |

### Getting Plugin Help

```bash
# General help
python3 vol.py --help

# Plugin-specific help
python3 vol.py windows.pslist --help
```

---

## 🕵️ Part 4: Process Analysis

Process analysis is typically the starting point for any memory investigation.

### windows.pslist

Lists processes from the EPROCESS doubly-linked list (what the OS sees):

```bash
python3 vol.py -f memory.dmp windows.pslist
```

**Output columns:**
| Column | Description |
|--------|-------------|
| PID | Process ID |
| PPID | Parent Process ID |
| ImageFileName | Process name |
| Offset | Memory offset of EPROCESS |
| Threads | Number of threads |
| Handles | Number of handles |
| SessionId | User session (0 = system) |
| Wow64 | 32-bit process on 64-bit OS |
| CreateTime | Process start time |
| ExitTime | Process end time (if exited) |

**What to look for:**
- Processes with `ExitTime` set (terminated but still in memory)
- Unusual parent/child relationships
- Processes with very few threads or handles
- Misspelled system process names (`scvhost.exe` vs `svchost.exe`)

### windows.pstree

Displays processes in a tree structure showing parent/child relationships:

```bash
python3 vol.py -f memory.dmp windows.pstree
```

**Suspicious patterns:**
- `WINWORD.EXE` → `cmd.exe` or `powershell.exe` (macro execution)
- `explorer.exe` → suspicious child processes
- System processes with wrong parents
- `services.exe` should be a child of `wininit.exe`
- `svchost.exe` should be a child of `services.exe`

**Normal Windows process tree:**
```
System (4)
└── smss.exe
    ├── csrss.exe (Session 0)
    ├── wininit.exe
    │   ├── services.exe
    │   │   └── svchost.exe (multiple)
    │   └── lsass.exe
    └── csrss.exe (Session 1)
        └── winlogon.exe
            └── explorer.exe
```

### windows.psscan

Scans for EPROCESS structures using pool tag scanning. Finds hidden/unlinked processes:

```bash
python3 vol.py -f memory.dmp windows.psscan
```

**Why this matters:**
- Rootkits unlink processes from the active process list
- `psscan` finds these by scanning raw memory for process structures
- Compare output with `pslist`—differences indicate hidden processes

**Find hidden processes:**
```bash
# Compare pslist vs psscan
python3 vol.py -f memory.dmp windows.pslist > pslist.txt
python3 vol.py -f memory.dmp windows.psscan > psscan.txt
diff pslist.txt psscan.txt
```

### windows.cmdline

Shows command-line arguments for each process:

```bash
python3 vol.py -f memory.dmp windows.cmdline
```

**Suspicious indicators:**
- Encoded PowerShell (`-enc`, `-e`, `-encodedcommand`)
- Commands with Base64 strings
- Processes running from `\Temp\`, `\AppData\`, `\Downloads\`
- Unusual arguments for system processes

### windows.envars

Displays environment variables for processes:

```bash
# All processes
python3 vol.py -f memory.dmp windows.envars

# Specific process
python3 vol.py -f memory.dmp windows.envars --pid 1234
```

**Look for:**
- Unusual `PATH` modifications
- Suspicious environment variables set by malware
- User context (`USERNAME`, `USERPROFILE`)

---

## 🌐 Part 5: Network Analysis

Network artifacts reveal active connections, listening ports, and potential C2 communication.

### windows.netscan

Scans for network connection structures (TCP/UDP endpoints):

```bash
python3 vol.py -f memory.dmp windows.netscan
```

**Output columns:**
| Column | Description |
|--------|-------------|
| Offset | Memory offset |
| Proto | Protocol (TCPv4, TCPv6, UDPv4, UDPv6) |
| LocalAddr | Local IP and port |
| ForeignAddr | Remote IP and port |
| State | Connection state |
| PID | Associated process ID |
| Owner | Process name |
| Created | Connection creation time |

**Connection states:**
| State | Meaning |
|-------|---------|
| LISTENING | Waiting for incoming connections |
| ESTABLISHED | Active connection |
| CLOSE_WAIT | Remote side closed |
| TIME_WAIT | Connection closing |
| SYN_SENT | Initiating connection |

**Suspicious patterns:**
- Connections from non-browser processes to port 80/443
- Connections to known-bad IPs
- Unusual listening ports
- System processes with external connections

### windows.netstat

Similar to the `netstat` command output:

```bash
python3 vol.py -f memory.dmp windows.netstat
```

### Correlating Network with Processes

```bash
# Find process with suspicious connection
python3 vol.py -f memory.dmp windows.netscan | grep "192.168.1.100"

# Get full details on that process
python3 vol.py -f memory.dmp windows.pslist --pid <PID>
python3 vol.py -f memory.dmp windows.cmdline --pid <PID>
```

---

## 💉 Part 6: Malware & Injection Detection

These plugins help identify malicious code injection and suspicious memory regions.

### windows.malfind

Scans process memory for signs of code injection:

```bash
python3 vol.py -f memory.dmp windows.malfind
```

**Detection criteria:**
- Memory regions with `PAGE_EXECUTE_READWRITE` protection
- Executable code in regions not backed by files
- Common shellcode patterns (e.g., `MZ` headers)

**Output includes:**
- Process name and PID
- Memory region address and protection
- Hexdump of suspicious region
- Disassembly of code

**Dump injected regions:**
```bash
python3 vol.py -f memory.dmp -o /output/dir windows.malfind --dump
```

**Common false positives:**
- .NET JIT compiled code
- Some security products
- Legitimate packers

### windows.vadinfo

Lists Virtual Address Descriptor (VAD) information for memory regions:

```bash
python3 vol.py -f memory.dmp windows.vadinfo --pid 1234
```

**Memory protection flags:**
| Flag | Description | Suspicious? |
|------|-------------|-------------|
| PAGE_EXECUTE_READWRITE | RWX | Yes - common for injection |
| PAGE_EXECUTE_WRITECOPY | Execute + Copy-on-write | Potentially |
| PAGE_EXECUTE_READ | Normal executable | Usually OK |
| PAGE_READWRITE | Data section | Normal |

### windows.ldrmodules

Compares loaded modules across three different lists:

```bash
python3 vol.py -f memory.dmp windows.ldrmodules --pid 1234
```

**The three lists:**
- InLoadOrderList
- InInitOrderList
- InMemOrderList

**Interpretation:**
- Legitimate DLLs appear in all three lists
- `False` entries may indicate:
  - Unlinked/hidden modules
  - Manually loaded DLLs
  - Injection artifacts

### windows.hollowprocesses

Detects process hollowing (a technique where legitimate process memory is replaced):

```bash
python3 vol.py -f memory.dmp windows.hollowprocesses
```

### windows.callbacks

Lists kernel callbacks that malware might use for persistence:

```bash
python3 vol.py -f memory.dmp windows.callbacks
```

---

## 📚 Part 7: DLL Analysis

### windows.dlllist

Lists DLLs loaded by a process:

```bash
# All processes
python3 vol.py -f memory.dmp windows.dlllist

# Specific process
python3 vol.py -f memory.dmp windows.dlllist --pid 1234
```

**Suspicious indicators:**
- DLLs loaded from unusual paths (`\Temp\`, `\Users\`)
- Misspelled DLL names
- DLLs with no file path (memory-only)

### windows.modules

Lists kernel modules (drivers):

```bash
python3 vol.py -f memory.dmp windows.modules
```

**Look for:**
- Unsigned drivers
- Drivers loaded from unusual locations
- Known malicious driver names

### windows.modscan

Pool scanner for kernel modules (finds hidden drivers):

```bash
python3 vol.py -f memory.dmp windows.modscan
```

### Dumping DLLs

```bash
# Dump all DLLs for a process
python3 vol.py -f memory.dmp -o /output/dir windows.dlllist --pid 1234 --dump
```

---

## 🔑 Part 8: Credential Extraction

### windows.hashdump

Extracts password hashes from the SAM database:

```bash
python3 vol.py -f memory.dmp windows.hashdump
```

**Output format:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**Hash positions:**
- LM hash (first 32 chars, often empty)
- NTLM hash (second 32 chars)

### windows.lsadump

Extracts LSA secrets:

```bash
python3 vol.py -f memory.dmp windows.lsadump
```

**Contains:**
- Service account passwords
- Cached domain credentials
- VPN/dial-up passwords

### windows.cachedump

Extracts cached domain credentials:

```bash
python3 vol.py -f memory.dmp windows.cachedump
```

### Mimikatz Integration

For more comprehensive credential extraction, dump LSASS and analyze with Mimikatz:

```bash
# Find LSASS PID
python3 vol.py -f memory.dmp windows.pslist | grep lsass

# Dump LSASS memory
python3 vol.py -f memory.dmp -o /output/dir windows.memmap --pid <LSASS_PID> --dump
```

---

## 📁 Part 9: File System Artifacts

### windows.filescan

Scans for FILE_OBJECT structures:

```bash
python3 vol.py -f memory.dmp windows.filescan
```

**Filter for specific files:**
```bash
python3 vol.py -f memory.dmp windows.filescan | grep -i "malware"
python3 vol.py -f memory.dmp windows.filescan | grep -i "\.exe"
```

### windows.dumpfiles

Dumps files from memory:

```bash
# Dump by physical offset
python3 vol.py -f memory.dmp -o /output/dir windows.dumpfiles --physaddr 0x12345678

# Dump by virtual address
python3 vol.py -f memory.dmp -o /output/dir windows.dumpfiles --virtaddr 0x12345678
```

### windows.handles

Lists handles opened by processes:

```bash
# All handles for a process
python3 vol.py -f memory.dmp windows.handles --pid 1234

# Filter by handle type
python3 vol.py -f memory.dmp windows.handles --pid 1234 | grep "File"
```

**Handle types of interest:**
- File handles (accessed files)
- Key handles (registry access)
- Process/Thread handles (injection indicators)
- Mutant handles (malware mutexes)

---

## 📝 Part 10: Registry Analysis

### windows.registry.hivelist

Lists registry hives loaded in memory:

```bash
python3 vol.py -f memory.dmp windows.registry.hivelist
```

### windows.registry.printkey

Prints registry keys and values:

```bash
# Print specific key
python3 vol.py -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# With specific hive offset
python3 vol.py -f memory.dmp windows.registry.printkey --offset 0x12345678 --key "Software"
```

**Important keys for investigation:**
| Key | Purpose |
|-----|---------|
| `...\CurrentVersion\Run` | Startup programs |
| `...\CurrentVersion\RunOnce` | One-time startup |
| `...\Services` | Service configurations |
| `...\Explorer\RecentDocs` | Recent documents |
| `...\TypedPaths` | Explorer address bar history |

### windows.registry.userassist

Extracts UserAssist data (program execution history):

```bash
python3 vol.py -f memory.dmp windows.registry.userassist
```

---

## ⏰ Part 11: Timeline Analysis

### timeliner

Creates a timeline of system events:

```bash
python3 vol.py -f memory.dmp timeliner.Timeliner
```

**Output includes:**
- Process creation/exit times
- Network connection times
- File access times
- Registry modification times

### Creating Investigation Timeline

```bash
# Generate timeline in CSV format
python3 vol.py -f memory.dmp -r csv timeliner.Timeliner > timeline.csv

# Sort by time
sort -t',' -k1 timeline.csv > timeline_sorted.csv
```

---

## 🔬 Part 12: Memory Dumps & Extraction

### windows.memmap

Dumps the full memory space of a process:

```bash
python3 vol.py -f memory.dmp -o /output/dir windows.memmap --pid 1234 --dump
```

### windows.pslist --dump

Dumps the executable image of a process:

```bash
python3 vol.py -f memory.dmp -o /output/dir windows.pslist --pid 1234 --dump
```

### Extracting Specific Memory Regions

```bash
# Get VAD information first
python3 vol.py -f memory.dmp windows.vadinfo --pid 1234

# Dump specific VAD region
python3 vol.py -f memory.dmp -o /output/dir windows.vadyarascan --pid 1234 --yara-rules "rule test { strings: $a = \"malware\" condition: $a }"
```

---

## 🔍 Part 13: YARA Integration

### windows.vadyarascan

Scans process memory with YARA rules:

```bash
# Scan with YARA rule file
python3 vol.py -f memory.dmp windows.vadyarascan --yara-file /path/to/rules.yar

# Scan specific process
python3 vol.py -f memory.dmp windows.vadyarascan --pid 1234 --yara-file /path/to/rules.yar
```

### yarascan.YaraScan

Scans all memory (kernel + user space):

```bash
python3 vol.py -f memory.dmp yarascan.YaraScan --yara-file /path/to/rules.yar
```

### Sample YARA Rules

Create `malware_indicators.yar`:

```yara
rule Suspicious_PowerShell {
    meta:
        description = "Detects encoded PowerShell commands"
    strings:
        $enc1 = "-enc" ascii nocase
        $enc2 = "-encodedcommand" ascii nocase
        $enc3 = "FromBase64String" ascii nocase
        $iex = "IEX" ascii nocase
    condition:
        any of them
}

rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz in memory"
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "gentilkiwi" ascii
        $s3 = "sekurlsa::" ascii
        $s4 = "kerberos::" ascii
    condition:
        2 of them
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon"
    strings:
        $s1 = "%s (admin)" ascii
        $s2 = "beacon.dll" ascii
        $s3 = "ReflectiveLoader" ascii
        $pipe = "\\\\.\\pipe\\msagent_" ascii
    condition:
        2 of them
}
```

---

## 📊 Part 14: Investigation Workflows

### Workflow 1: Suspicious Process Investigation

```bash
#!/bin/bash
DUMP="memory.dmp"
OUTPUT="investigation_$(date +%Y%m%d)"
mkdir -p $OUTPUT

echo "[*] Step 1: Process listing"
python3 vol.py -f $DUMP windows.pstree > $OUTPUT/pstree.txt

echo "[*] Step 2: Finding hidden processes"
python3 vol.py -f $DUMP windows.pslist > $OUTPUT/pslist.txt
python3 vol.py -f $DUMP windows.psscan > $OUTPUT/psscan.txt

echo "[*] Step 3: Command lines"
python3 vol.py -f $DUMP windows.cmdline > $OUTPUT/cmdline.txt

echo "[*] Step 4: Network connections"
python3 vol.py -f $DUMP windows.netscan > $OUTPUT/netscan.txt

echo "[*] Step 5: Injection detection"
python3 vol.py -f $DUMP windows.malfind > $OUTPUT/malfind.txt

echo "[*] Analysis complete. Review files in $OUTPUT/"
```

### Workflow 2: Malware Hunt

```bash
# 1. Identify suspicious processes
python3 vol.py -f memory.dmp windows.pstree | grep -E "(cmd|powershell|wscript|cscript|mshta|rundll32)"

# 2. Check for code injection
python3 vol.py -f memory.dmp windows.malfind

# 3. Scan with YARA
python3 vol.py -f memory.dmp windows.vadyarascan --yara-file malware_rules.yar

# 4. Check network for C2
python3 vol.py -f memory.dmp windows.netscan | grep ESTABLISHED

# 5. Dump suspicious process
python3 vol.py -f memory.dmp -o ./dump windows.memmap --pid <SUSPICIOUS_PID> --dump
```

### Workflow 3: Credential Theft Investigation

```bash
# 1. Check for LSASS access
python3 vol.py -f memory.dmp windows.handles | grep -i lsass

# 2. Look for credential tools
python3 vol.py -f memory.dmp windows.cmdline | grep -iE "(mimikatz|procdump|sekurlsa)"

# 3. Extract cached credentials
python3 vol.py -f memory.dmp windows.hashdump
python3 vol.py -f memory.dmp windows.cachedump
python3 vol.py -f memory.dmp windows.lsadump

# 4. Dump LSASS for offline analysis
LSASS_PID=$(python3 vol.py -f memory.dmp windows.pslist | grep lsass | awk '{print $2}')
python3 vol.py -f memory.dmp -o ./dump windows.memmap --pid $LSASS_PID --dump
```

### Workflow 4: Lateral Movement Detection

```bash
# 1. Check for remote connections (RDP, SMB, WinRM)
python3 vol.py -f memory.dmp windows.netscan | grep -E ":(3389|445|5985|5986)"

# 2. Look for PsExec or similar tools
python3 vol.py -f memory.dmp windows.pslist | grep -iE "(psexec|paexec|remcom|winexe)"

# 3. Check scheduled tasks
python3 vol.py -f memory.dmp windows.filescan | grep -i "tasks"

# 4. Review services
python3 vol.py -f memory.dmp windows.svcscan | grep -v "Microsoft"
```

---

## 🔧 Part 15: Advanced Techniques

### Comparing Multiple Dumps

When you have baseline and compromised dumps:

```bash
# Extract process lists
python3 vol.py -f baseline.dmp windows.pslist > baseline_ps.txt
python3 vol.py -f compromised.dmp windows.pslist > compromised_ps.txt

# Compare
diff baseline_ps.txt compromised_ps.txt
```

### Volatility Scripting

Create Python scripts using Volatility as a library:

```python
#!/usr/bin/env python3
import volatility3
from volatility3 import framework
from volatility3.framework import contexts, automagic
from volatility3.plugins.windows import pslist

# Initialize context
ctx = contexts.Context()

# Configure and run
# (Simplified example - full implementation requires more setup)
```

### Bulk Processing

Process multiple dumps:

```bash
#!/bin/bash
for dump in /cases/*.dmp; do
    echo "Processing: $dump"
    name=$(basename $dump .dmp)
    mkdir -p results/$name
    
    python3 vol.py -f $dump windows.pslist > results/$name/pslist.txt
    python3 vol.py -f $dump windows.netscan > results/$name/netscan.txt
    python3 vol.py -f $dump windows.malfind > results/$name/malfind.txt
done
```

---

## ❗ Part 16: Troubleshooting

### "Unable to Validate Profile"

**Problem:** Volatility cannot identify the OS profile.

**Solutions:**
```bash
# Check if dump is valid
file memory.dmp

# Try windows.info to identify the OS
python3 vol.py -f memory.dmp windows.info

# Specify symbol path
python3 vol.py -s /path/to/symbols -f memory.dmp windows.pslist

# Download symbols
python3 vol.py -f memory.dmp windows.pslist
# (Symbols download automatically on first run)
```

### "No Suitable Address Space"

**Problem:** Volatility cannot read the memory format.

**Solutions:**
```bash
# Identify dump format
file memory.dmp

# For hibernation files
python3 vol.py -f hiberfil.sys windows.pslist

# For crash dumps
python3 vol.py -f MEMORY.DMP windows.pslist

# Convert formats if needed
volatility3 -f input.vmem layerwriter.LayerWriter --output raw
```

### Slow Performance

**Optimizations:**
```bash
# Use parallel processing
python3 vol.py -p 4 -f memory.dmp windows.psscan

# Use SSD for output
python3 vol.py -f memory.dmp -o /fast/ssd/output windows.malfind --dump

# Filter before dumping
python3 vol.py -f memory.dmp windows.pslist --pid 1234
```

### Plugin Not Found

```bash
# List available plugins
python3 vol.py --help

# Check plugin path
python3 vol.py --plugin-dirs /path/to/plugins -f memory.dmp <plugin>
```

---

## 📚 Part 17: Additional Resources

### Documentation

- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Volatility GitHub](https://github.com/volatilityfoundation/volatility3)
- [Volatility Foundation](https://www.volatilityfoundation.org/)

### YARA Rules

- [Awesome YARA](https://github.com/InQuest/awesome-yara)
- [YARA Rules Repository](https://github.com/Yara-Rules/rules)
- [Florian Roth's Signature Base](https://github.com/Neo23x0/signature-base)

### Memory Samples for Practice

- [Volatility Memory Samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)
- [NIST CFReDS](https://cfreds.nist.gov/)
- [Digital Corpora](https://digitalcorpora.org/)

### Training

- [SANS FOR508](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)
- [13Cubed YouTube](https://www.youtube.com/c/13Cubed)
- [MemLabs CTF](https://github.com/stuxnet999/MemLabs)

---

## 🗂️ Quick Reference

### Plugin Categories

| Category | Plugins |
|----------|---------|
| Process | `pslist`, `pstree`, `psscan`, `cmdline`, `envars` |
| Network | `netscan`, `netstat` |
| Malware | `malfind`, `ldrmodules`, `hollowprocesses` |
| DLLs | `dlllist`, `modules`, `modscan` |
| Credentials | `hashdump`, `lsadump`, `cachedump` |
| Files | `filescan`, `dumpfiles`, `handles` |
| Registry | `hivelist`, `printkey`, `userassist` |
| Memory | `memmap`, `vadinfo`, `vadyarascan` |

### Common Command Patterns

```bash
# Basic analysis
python3 vol.py -f memory.dmp windows.pslist
python3 vol.py -f memory.dmp windows.pstree
python3 vol.py -f memory.dmp windows.netscan

# Targeted analysis
python3 vol.py -f memory.dmp windows.cmdline --pid 1234
python3 vol.py -f memory.dmp windows.dlllist --pid 1234
python3 vol.py -f memory.dmp windows.handles --pid 1234

# Dumping
python3 vol.py -f memory.dmp -o /output windows.malfind --dump
python3 vol.py -f memory.dmp -o /output windows.memmap --pid 1234 --dump

# Scanning
python3 vol.py -f memory.dmp windows.vadyarascan --yara-file rules.yar
```

### Suspicious Process Checklist

- [ ] `svchost.exe` not spawned by `services.exe`?
- [ ] `lsass.exe` has multiple instances?
- [ ] Misspelled system processes?
- [ ] Processes running from `\Temp\` or `\Users\`?
- [ ] Unsigned processes with network connections?
- [ ] `cmd.exe`/`powershell.exe` spawned by Office apps?
- [ ] Processes with `ExitTime` set but still active?
- [ ] Memory regions with `PAGE_EXECUTE_READWRITE`?

---

*Part of the Incident Response & Log Aggregation Branch*
