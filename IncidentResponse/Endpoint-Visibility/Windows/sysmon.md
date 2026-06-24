# 🪟 Windows Sysmon Deployment Guide

**System Monitor (Sysmon)** is a Windows system service and device driver from Microsoft's Sysinternals suite that logs detailed system activity to the Windows Event Log. It provides visibility into process creation, network connections, file changes, registry modifications, and more—critical telemetry for threat detection and incident response.

This guide covers installing, configuring, and maintaining Sysmon across your environment.

---

## 🎯 Why Sysmon?

Standard Windows logging misses critical security events. Sysmon fills these gaps:

| Capability | Native Windows Logging | With Sysmon |
|------------|----------------------|-------------|
| Process command line arguments | Limited | ✅ Full capture |
| Process GUID tracking | ❌ | ✅ Unique per process |
| Network connections with process context | Limited | ✅ Full details |
| File creation with hash | ❌ | ✅ MD5/SHA256/IMPHASH |
| DLL loading | Limited | ✅ With signatures |
| Registry persistence detection | Basic | ✅ Detailed |
| Parent/child process relationships | Limited | ✅ Complete chain |

---

## 📋 Prerequisites

### System Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Windows 7 SP1 / Server 2008 R2 or later |
| Architecture | x86 or x64 (use appropriate binary) |
| Privileges | Local Administrator |
| Disk Space | ~5 MB (plus log storage) |

### Required Downloads

1. **Sysmon Binary:** [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. **Configuration File:** Choose based on your needs (see Configuration Options below)

---

## 📥 Part 1: Downloading Sysmon

### Method 1: Direct Download

Download from the official Sysinternals page:
```
https://download.sysinternals.com/files/Sysmon.zip
```

### Method 2: PowerShell Download

```powershell
# Create a tools directory
New-Item -ItemType Directory -Path "C:\Tools\Sysmon" -Force

# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon\Sysmon.zip"

# Extract the archive
Expand-Archive -Path "C:\Tools\Sysmon\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force
```

### Method 3: Windows Package Manager (winget)

```powershell
winget install Microsoft.Sysinternals.Sysmon
```

### Verify the Download

Always verify the binary before deployment:

```powershell
# Check digital signature
Get-AuthenticodeSignature "C:\Tools\Sysmon\Sysmon64.exe"

# Verify it's signed by Microsoft
(Get-AuthenticodeSignature "C:\Tools\Sysmon\Sysmon64.exe").SignerCertificate.Subject
```

The signer should be `CN=Microsoft Corporation`.

---

## ⚙️ Part 2: Configuration Options

Sysmon's power comes from its XML configuration file. Choose a configuration based on your environment and expertise.

### Option 1: SwiftOnSecurity Config (Recommended for Most Users)

A well-tuned, community-maintained configuration that balances visibility with noise reduction.

```powershell
# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"
```

**Pros:**
- Battle-tested in production environments
- Good noise filtering out of the box
- Well-documented exclusions
- Regular community updates

**Best for:** General-purpose deployment, SOC environments, beginners

### Option 2: Olaf Hartong's Sysmon Modular

A modular approach allowing granular control over what gets logged.

```powershell
# Clone the repository
git clone https://github.com/olafhartong/sysmon-modular.git C:\Tools\sysmon-modular

# Or download the merged config directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"
```

**Pros:**
- Highly customizable
- Modular structure for easy editing
- Maps to MITRE ATT&CK framework
- Includes attack-specific detection rules

**Best for:** Advanced users, threat hunters, red team detection

### Option 3: Microsoft's Default Config

Microsoft provides a basic configuration for reference:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoft/MSTIC-Sysmon/main/sysmonconfig.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"
```

### Option 4: Custom Configuration

Start with a minimal config and build from there:

```xml
<Sysmon schemaversion="4.90">
    <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
    <EventFiltering>
        <!-- Log all process creation -->
        <ProcessCreate onmatch="exclude" />
        
        <!-- Log all network connections -->
        <NetworkConnect onmatch="exclude" />
        
        <!-- Log file creation in sensitive locations -->
        <FileCreate onmatch="include">
            <TargetFilename condition="contains">\Downloads\</TargetFilename>
            <TargetFilename condition="contains">\Temp\</TargetFilename>
            <TargetFilename condition="contains">\AppData\</TargetFilename>
        </FileCreate>
        
        <!-- Log registry persistence locations -->
        <RegistryEvent onmatch="include">
            <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
            <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
        </RegistryEvent>
    </EventFiltering>
</Sysmon>
```

---

## 🚀 Part 3: Installation

### Single Machine Installation

Open an **Administrator Command Prompt** or **PowerShell**:

```cmd
cd C:\Tools\Sysmon

# Install with configuration (64-bit)
sysmon64.exe -accepteula -i sysmonconfig.xml

# For 32-bit systems
sysmon.exe -accepteula -i sysmonconfig.xml
```

### Installation Options Reference

| Flag | Purpose |
|------|---------|
| `-i <config>` | Install with specified configuration file |
| `-accepteula` | Accept the EULA silently |
| `-h md5,sha256,IMPHASH` | Specify hash algorithms |
| `-n` | Log network connections |
| `-l` | Log module (DLL) loading |
| `-d <name>` | Custom driver name (anti-tampering) |

### Verify Installation

```powershell
# Check service status
Get-Service Sysmon64

# View current configuration
sysmon64.exe -c

# Check driver is loaded
sc query Sysmon64
```

---

## 🏢 Part 4: Enterprise Deployment

### Method 1: Group Policy Deployment

#### Step 4.1: Create a Network Share

```powershell
# On a file server, create and share the Sysmon folder
New-Item -ItemType Directory -Path "C:\Deploy\Sysmon" -Force
New-SmbShare -Name "Sysmon$" -Path "C:\Deploy\Sysmon" -ReadAccess "Domain Computers"
```

Copy `sysmon64.exe`, `sysmon.exe`, and `sysmonconfig.xml` to this share.

#### Step 4.2: Create the Installation Script

Create `Install-Sysmon.bat`:

```batch
@echo off
setlocal

set SYSMON_SHARE=\\fileserver\Sysmon$
set SYSMON_LOCAL=C:\Windows\Sysmon

:: Check if already installed
sc query Sysmon64 >nul 2>&1
if %errorlevel%==0 (
    echo Sysmon already installed, updating configuration...
    "%SYSMON_LOCAL%\Sysmon64.exe" -c "%SYSMON_SHARE%\sysmonconfig.xml"
    goto :end
)

:: Create local directory
if not exist "%SYSMON_LOCAL%" mkdir "%SYSMON_LOCAL%"

:: Copy files locally
copy /Y "%SYSMON_SHARE%\Sysmon64.exe" "%SYSMON_LOCAL%\"
copy /Y "%SYSMON_SHARE%\sysmonconfig.xml" "%SYSMON_LOCAL%\"

:: Install Sysmon
"%SYSMON_LOCAL%\Sysmon64.exe" -accepteula -i "%SYSMON_LOCAL%\sysmonconfig.xml"

:end
endlocal
```

#### Step 4.3: Create GPO

1. Open **Group Policy Management Console**
2. Create a new GPO: `Sysmon Deployment`
3. Navigate to: **Computer Configuration → Policies → Windows Settings → Scripts → Startup**
4. Add `Install-Sysmon.bat`
5. Link the GPO to target OUs

### Method 2: PowerShell Remoting

```powershell
$computers = Get-Content "C:\targets.txt"
$sysmonPath = "\\fileserver\Sysmon$"

foreach ($computer in $computers) {
    Invoke-Command -ComputerName $computer -ScriptBlock {
        param($path)
        
        # Copy files
        Copy-Item "$path\Sysmon64.exe" -Destination "C:\Windows\Sysmon\" -Force
        Copy-Item "$path\sysmonconfig.xml" -Destination "C:\Windows\Sysmon\" -Force
        
        # Install
        Start-Process -FilePath "C:\Windows\Sysmon\Sysmon64.exe" -ArgumentList "-accepteula -i C:\Windows\Sysmon\sysmonconfig.xml" -Wait -NoNewWindow
        
    } -ArgumentList $sysmonPath
    
    Write-Host "Installed on $computer" -ForegroundColor Green
}
```

### Method 3: Microsoft Endpoint Configuration Manager (SCCM/MECM)

1. Create an Application in MECM
2. **Installation Program:** `sysmon64.exe -accepteula -i sysmonconfig.xml`
3. **Uninstall Program:** `sysmon64.exe -u`
4. **Detection Method:** Registry key `HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64`
5. Deploy to target collection

---

## 📝 Part 5: Key Event IDs

Understanding Sysmon Event IDs is crucial for effective monitoring and threat hunting.

### Critical Events for Security Monitoring

| Event ID | Name | Why It Matters |
|----------|------|----------------|
| **1** | Process Create | Full command line capture reveals encoded PowerShell, LOLBins, suspicious arguments |
| **3** | Network Connect | Identifies C2 callbacks, lateral movement, data exfiltration |
| **6** | Driver Load | Detects rootkit installation, vulnerable driver loading |
| **7** | Image Load | DLL side-loading, injection detection |
| **8** | CreateRemoteThread | Process injection indicator (Mimikatz, Cobalt Strike) |
| **10** | Process Access | Credential dumping (LSASS access) |
| **11** | File Create | Malware drops, tool staging, webshells |
| **12/13/14** | Registry Events | Persistence mechanisms, configuration changes |
| **15** | FileCreateStreamHash | Alternate Data Stream abuse (hiding payloads) |
| **17/18** | Pipe Events | Named pipe C2 communication (Cobalt Strike) |
| **22** | DNS Query | DNS-based C2, tunneling, suspicious resolutions |
| **23** | File Delete | Archived file deletion (anti-forensics) |
| **25** | Process Tampering | Process hollowing, herpaderping |

### Event ID 1: Process Creation (Most Important)

This event captures every process execution with full context:

```
Event ID: 1
UtcTime: 2024-01-15 14:23:45.123
ProcessGuid: {12345678-1234-1234-1234-123456789abc}
ProcessId: 4532
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
CurrentDirectory: C:\Users\victim\
User: DOMAIN\username
ParentProcessGuid: {12345678-1234-1234-1234-123456789def}
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ParentCommandLine: "WINWORD.EXE" /n "C:\Users\victim\Downloads\invoice.docm"
```

**Red Flags:**
- Encoded PowerShell (`-enc`, `-e`, `-encodedcommand`)
- Office applications spawning cmd.exe or PowerShell
- Processes running from `\Temp\`, `\Downloads\`, `\AppData\`
- Unusual parent/child relationships

### Event ID 3: Network Connection

```
Event ID: 3
UtcTime: 2024-01-15 14:23:47.456
ProcessGuid: {12345678-1234-1234-1234-123456789abc}
ProcessId: 4532
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: DOMAIN\username
Protocol: tcp
SourceIp: 192.168.1.100
SourcePort: 49234
DestinationIp: 185.234.72.19
DestinationPort: 443
DestinationHostname: evil-c2-server.com
```

**Red Flags:**
- Connections from unexpected processes (notepad.exe, calc.exe)
- Connections to known-bad IPs or unusual geolocations
- Non-browser processes connecting on port 80/443
- High port-count connections (scanning)

### Event ID 10: Process Access

Critical for detecting credential theft:

```
Event ID: 10
SourceImage: C:\Temp\mimikatz.exe
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1010
```

**Red Flags:**
- Any non-system process accessing LSASS
- `GrantedAccess` values: `0x1010`, `0x1410`, `0x1438` (memory read)

### Event ID 22: DNS Query

```
Event ID: 22
ProcessId: 4532
QueryName: data.evil-domain.com
QueryResults: 192.168.1.50
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Red Flags:**
- DNS queries from unexpected processes
- High entropy domain names (DGA)
- Unusually long subdomains (DNS tunneling)

---

## 🧪 Part 6: Testing and Verification

### Basic Functionality Test

1. **Open PowerShell** and run a simple command:

```powershell
whoami
hostname
ipconfig
```

2. **Check Event Viewer:**
   - Navigate to: `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`
   - Look for Event ID 1 entries

3. **PowerShell Query:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | 
    Where-Object { $_.Id -eq 1 } | 
    Format-List TimeCreated, Message
```

### Network Connection Test

```powershell
# Generate a network connection
Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing | Out-Null

# Check for Event ID 3
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 | 
    Where-Object { $_.Id -eq 3 } |
    Select-Object -First 5 |
    Format-List TimeCreated, Message
```

### Atomic Red Team Testing

Use Atomic Red Team to generate realistic attack telemetry:

```powershell
# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

# Run a test (T1059.001 - PowerShell)
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Check Sysmon logs for detection
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Format-Table TimeCreated, Id, Message -Wrap
```

---

## 🔄 Part 7: Configuration Updates

### Update Configuration on Running System

```cmd
# Update config without reinstalling
sysmon64.exe -c sysmonconfig-new.xml
```

### View Current Configuration

```cmd
sysmon64.exe -c
```

### Validate Configuration File

Before deploying, validate your XML:

```powershell
# Check XML is well-formed
[xml]$config = Get-Content "sysmonconfig.xml"
Write-Host "Configuration is valid XML" -ForegroundColor Green
```

### Automated Config Updates via GPO

Create `Update-SysmonConfig.bat`:

```batch
@echo off
set CONFIG_SHARE=\\fileserver\Sysmon$\sysmonconfig.xml
C:\Windows\Sysmon\Sysmon64.exe -c "%CONFIG_SHARE%"
```

Schedule via Group Policy Preferences → Scheduled Tasks.

---

## 🔗 Part 8: SIEM Integration

### Wazuh Integration

Wazuh automatically collects Sysmon events. Ensure the agent configuration includes:

```xml
<!-- In ossec.conf on the Windows agent -->
<localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>
```

### Windows Event Forwarding (WEF)

Create a subscription for Sysmon events:

```xml
<QueryList>
    <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
        <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
    </Query>
</QueryList>
```

### Splunk Universal Forwarder

Add to `inputs.conf`:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = sysmon
```

### Elastic Agent / Winlogbeat

```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 1, 3, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 25
```

---

## 📊 Part 9: Log Management

### Event Log Size Configuration

Increase the default Sysmon log size to prevent rollover:

```powershell
# Set log to 1 GB
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
```

Via Group Policy:
- Navigate to: **Computer Configuration → Administrative Templates → Windows Components → Event Log Service → Sysmon**
- Set **Maximum Log Size** to desired value

### Log Rotation and Archival

```powershell
# Export and clear Sysmon logs
$date = Get-Date -Format "yyyy-MM-dd"
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Logs\Sysmon-$date.evtx"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
```

### Storage Estimation

| Events/Day | Daily Size | Monthly Size |
|------------|------------|--------------|
| 10,000 | ~50 MB | ~1.5 GB |
| 100,000 | ~500 MB | ~15 GB |
| 1,000,000 | ~5 GB | ~150 GB |

Tune your configuration to reduce noise and manage storage effectively.

---

## ❗ Part 10: Troubleshooting

### Sysmon Not Logging Events

**Check service status:**
```powershell
Get-Service Sysmon64
```

**Verify driver is loaded:**
```cmd
fltmc
```
Look for the Sysmon driver in the output.

**Check for configuration errors:**
```cmd
sysmon64.exe -c
```

### High CPU or Memory Usage

**Identify problematic rules:**
1. Start with a minimal config
2. Add rules incrementally
3. Monitor resource usage

**Common culprits:**
- Overly broad `FileCreate` rules
- Logging all `ImageLoad` events
- No exclusions for noisy system processes

**Add performance exclusions:**
```xml
<ProcessCreate onmatch="exclude">
    <Image condition="is">C:\Windows\System32\svchost.exe</Image>
    <Image condition="is">C:\Windows\System32\RuntimeBroker.exe</Image>
</ProcessCreate>
```

### Events Missing

**Check filter logic:**
- `onmatch="include"` = whitelist (only log matching)
- `onmatch="exclude"` = blacklist (log everything except matching)

**Verify event types are enabled:**
```xml
<!-- This logs ALL process creations -->
<ProcessCreate onmatch="exclude" />

<!-- This logs NOTHING (empty include) -->
<ProcessCreate onmatch="include" />
```

### Uninstalling Sysmon

```cmd
# Uninstall and remove driver
sysmon64.exe -u

# Force uninstall if standard fails
sysmon64.exe -u force
```

### Driver Name Conflicts

If you've used a custom driver name and forgot it:

```powershell
# Find the driver
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -like "*sysmon*" }
```

---

## 🛡️ Part 11: Anti-Tampering Measures

### Use a Custom Driver Name

Attackers often look for "Sysmon" to disable logging:

```cmd
sysmon64.exe -accepteula -i sysmonconfig.xml -d MySecurityDriver
```

### Monitor Sysmon Service

Create an alert for Sysmon service stops (Event ID 4):

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | 
    Where-Object { $_.Id -eq 4 } |
    Select-Object TimeCreated, Message
```

### Protect the Sysmon Binary

Apply restrictive NTFS permissions:

```powershell
$acl = Get-Acl "C:\Windows\Sysmon64.exe"
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
$acl.AddAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","ReadAndExecute","Allow")
$acl.AddAccessRule($rule)
Set-Acl "C:\Windows\Sysmon64.exe" $acl
```

---

## 📚 Additional Resources

- [Sysmon Documentation (Microsoft)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sysmon Modular (Olaf Hartong)](https://github.com/olafhartong/sysmon-modular)
- [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
- [MITRE ATT&CK Sysmon Mappings](https://attack.mitre.org/datasources/)

---

## 🗂️ Quick Reference

### Installation Commands

| Action | Command |
|--------|---------|
| Install | `sysmon64.exe -accepteula -i config.xml` |
| Update Config | `sysmon64.exe -c config.xml` |
| View Config | `sysmon64.exe -c` |
| Uninstall | `sysmon64.exe -u` |

### Event Log Locations

| Item | Path |
|------|------|
| Event Log | `Microsoft-Windows-Sysmon/Operational` |
| Event Viewer Path | `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational` |
| Binary Location | `C:\Windows\Sysmon64.exe` (default) |
| Driver | `C:\Windows\SysmonDrv.sys` |

### PowerShell Quick Queries

```powershell
# Last 10 process creations
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.Id -eq 1}

# Network connections in last hour
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 | Where-Object {$_.Id -eq 3 -and $_.TimeCreated -gt (Get-Date).AddHours(-1)}

# LSASS access attempts
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 10 -and $_.Message -like "*lsass*"}
```

---

*Part of the Incident Response & Log Aggregation Branch*
