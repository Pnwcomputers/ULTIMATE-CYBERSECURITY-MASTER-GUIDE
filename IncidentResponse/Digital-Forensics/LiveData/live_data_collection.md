# 🚨 Live Response Collection Guide

**Live Response** is the process of collecting volatile and non-volatile data from a running system during an incident. This data can be lost when a system is powered off, making timely collection critical. Live response captures the current state of a potentially compromised system before forensic imaging or remediation.

This guide covers live response methodology, tools, and scripts for Windows and Linux systems.

---

## 🎯 Why Live Response?

### Volatile vs Non-Volatile Data

| Volatile Data (Lost on Reboot) | Non-Volatile Data (Persists) |
|-------------------------------|------------------------------|
| Running processes | Files on disk |
| Network connections | Event logs |
| Logged-in users | Registry hives |
| Open files/handles | Browser history |
| Clipboard contents | Prefetch files |
| Memory (RAM) | User profiles |
| ARP cache | Scheduled tasks |
| DNS cache | Installed software |
| Routing table | File system metadata |

### Order of Volatility

Collect data in order of volatility (most volatile first):

1. **Registers, cache** (CPU state)
2. **Memory** (RAM)
3. **Network state** (connections, routing)
4. **Running processes**
5. **Disk** (files, logs)
6. **Remote logging** (SIEM data)
7. **Physical configuration**
8. **Archival media** (backups)

---

## 📋 Prerequisites

### Preparation Checklist

- [ ] **Portable storage** - USB drive or network share (write-blocker optional)
- [ ] **Collection tools** - Pre-staged on portable media
- [ ] **Documentation** - Chain of custody forms, notes
- [ ] **Time sync** - Note time offset if system clock differs
- [ ] **Network isolation** - Determine if system should be isolated
- [ ] **Authorization** - Written approval to collect data
- [ ] **Hashes** - Know hashes of your tools to prove integrity

### Collection Drive Structure

```
E:\IR_Toolkit\
├── Windows\
│   ├── KAPE\
│   ├── winpmem.exe
│   ├── Autoruns.exe
│   ├── PsTools\
│   ├── WinAudit.exe
│   └── Scripts\
├── Linux\
│   ├── avml
│   ├── linpmem
│   └── Scripts\
├── Output\
│   └── [Case_Number]\
└── Documentation\
    ├── Chain_of_Custody.docx
    └── Collection_Notes.txt
```

---

## 🖥️ Part 1: Windows Live Response

### Method 1: Manual Collection Script

Create `WindowsLiveResponse.bat`:

```batch
@echo off
:: ============================================
:: Windows Live Response Collection Script
:: ============================================
:: Run as Administrator from portable media

setlocal enabledelayedexpansion

:: Configuration
set CASE_ID=%1
if "%CASE_ID%"=="" set CASE_ID=IR_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%
set OUTPUT_DIR=%~dp0Output\%CASE_ID%
set HOSTNAME=%COMPUTERNAME%

:: Create output directory
mkdir "%OUTPUT_DIR%" 2>nul
mkdir "%OUTPUT_DIR%\System" 2>nul
mkdir "%OUTPUT_DIR%\Network" 2>nul
mkdir "%OUTPUT_DIR%\Processes" 2>nul
mkdir "%OUTPUT_DIR%\Users" 2>nul
mkdir "%OUTPUT_DIR%\Persistence" 2>nul
mkdir "%OUTPUT_DIR%\FileSystem" 2>nul

:: Start logging
echo [%date% %time%] Starting Live Response Collection > "%OUTPUT_DIR%\collection.log"
echo [%date% %time%] Hostname: %HOSTNAME% >> "%OUTPUT_DIR%\collection.log"
echo [%date% %time%] Case ID: %CASE_ID% >> "%OUTPUT_DIR%\collection.log"

:: ============================================
:: SYSTEM INFORMATION
:: ============================================
echo [*] Collecting System Information...

echo --- System Information --- > "%OUTPUT_DIR%\System\systeminfo.txt"
systeminfo >> "%OUTPUT_DIR%\System\systeminfo.txt" 2>&1

echo --- Hostname --- > "%OUTPUT_DIR%\System\hostname.txt"
hostname >> "%OUTPUT_DIR%\System\hostname.txt" 2>&1

echo --- Current Date/Time --- > "%OUTPUT_DIR%\System\datetime.txt"
echo Local: %date% %time% >> "%OUTPUT_DIR%\System\datetime.txt"
wmic os get localdatetime >> "%OUTPUT_DIR%\System\datetime.txt" 2>&1

echo --- Environment Variables --- > "%OUTPUT_DIR%\System\environment.txt"
set >> "%OUTPUT_DIR%\System\environment.txt" 2>&1

echo --- Hotfixes/Patches --- > "%OUTPUT_DIR%\System\hotfixes.txt"
wmic qfe list full >> "%OUTPUT_DIR%\System\hotfixes.txt" 2>&1

:: ============================================
:: NETWORK INFORMATION
:: ============================================
echo [*] Collecting Network Information...

echo --- Network Configuration --- > "%OUTPUT_DIR%\Network\ipconfig.txt"
ipconfig /all >> "%OUTPUT_DIR%\Network\ipconfig.txt" 2>&1

echo --- Active Connections --- > "%OUTPUT_DIR%\Network\netstat.txt"
netstat -anob >> "%OUTPUT_DIR%\Network\netstat.txt" 2>&1

echo --- Routing Table --- > "%OUTPUT_DIR%\Network\routes.txt"
route print >> "%OUTPUT_DIR%\Network\routes.txt" 2>&1

echo --- ARP Cache --- > "%OUTPUT_DIR%\Network\arp.txt"
arp -a >> "%OUTPUT_DIR%\Network\arp.txt" 2>&1

echo --- DNS Cache --- > "%OUTPUT_DIR%\Network\dnscache.txt"
ipconfig /displaydns >> "%OUTPUT_DIR%\Network\dnscache.txt" 2>&1

echo --- Network Shares --- > "%OUTPUT_DIR%\Network\shares.txt"
net share >> "%OUTPUT_DIR%\Network\shares.txt" 2>&1

echo --- Active Sessions --- > "%OUTPUT_DIR%\Network\sessions.txt"
net session >> "%OUTPUT_DIR%\Network\sessions.txt" 2>&1

echo --- Open Files (Shared) --- > "%OUTPUT_DIR%\Network\openfiles.txt"
openfiles /query >> "%OUTPUT_DIR%\Network\openfiles.txt" 2>&1

echo --- Firewall Status --- > "%OUTPUT_DIR%\Network\firewall.txt"
netsh advfirewall show allprofiles >> "%OUTPUT_DIR%\Network\firewall.txt" 2>&1

echo --- Firewall Rules --- > "%OUTPUT_DIR%\Network\firewall_rules.txt"
netsh advfirewall firewall show rule name=all >> "%OUTPUT_DIR%\Network\firewall_rules.txt" 2>&1

echo --- NetBIOS Sessions --- > "%OUTPUT_DIR%\Network\nbtstat.txt"
nbtstat -S >> "%OUTPUT_DIR%\Network\nbtstat.txt" 2>&1

echo --- WiFi Profiles --- > "%OUTPUT_DIR%\Network\wifi_profiles.txt"
netsh wlan show profiles >> "%OUTPUT_DIR%\Network\wifi_profiles.txt" 2>&1

:: ============================================
:: PROCESS INFORMATION
:: ============================================
echo [*] Collecting Process Information...

echo --- Running Processes --- > "%OUTPUT_DIR%\Processes\tasklist.txt"
tasklist /v >> "%OUTPUT_DIR%\Processes\tasklist.txt" 2>&1

echo --- Processes with Services --- > "%OUTPUT_DIR%\Processes\tasklist_svc.txt"
tasklist /svc >> "%OUTPUT_DIR%\Processes\tasklist_svc.txt" 2>&1

echo --- Process Details (WMIC) --- > "%OUTPUT_DIR%\Processes\wmic_process.txt"
wmic process get processid,parentprocessid,name,executablepath,commandline /format:csv >> "%OUTPUT_DIR%\Processes\wmic_process.txt" 2>&1

echo --- Process Modules --- > "%OUTPUT_DIR%\Processes\tasklist_modules.txt"
tasklist /m >> "%OUTPUT_DIR%\Processes\tasklist_modules.txt" 2>&1

:: ============================================
:: USER INFORMATION
:: ============================================
echo [*] Collecting User Information...

echo --- Logged On Users --- > "%OUTPUT_DIR%\Users\loggedon.txt"
query user >> "%OUTPUT_DIR%\Users\loggedon.txt" 2>&1
qwinsta >> "%OUTPUT_DIR%\Users\loggedon.txt" 2>&1

echo --- Local Users --- > "%OUTPUT_DIR%\Users\local_users.txt"
net user >> "%OUTPUT_DIR%\Users\local_users.txt" 2>&1
wmic useraccount list full >> "%OUTPUT_DIR%\Users\local_users.txt" 2>&1

echo --- Local Groups --- > "%OUTPUT_DIR%\Users\local_groups.txt"
net localgroup >> "%OUTPUT_DIR%\Users\local_groups.txt" 2>&1

echo --- Administrators --- > "%OUTPUT_DIR%\Users\administrators.txt"
net localgroup Administrators >> "%OUTPUT_DIR%\Users\administrators.txt" 2>&1

echo --- Recent User Activity --- > "%OUTPUT_DIR%\Users\user_activity.txt"
wmic netlogin get name,lastlogon,badpasswordcount >> "%OUTPUT_DIR%\Users\user_activity.txt" 2>&1

:: ============================================
:: PERSISTENCE MECHANISMS
:: ============================================
echo [*] Collecting Persistence Information...

echo --- Services --- > "%OUTPUT_DIR%\Persistence\services.txt"
sc query >> "%OUTPUT_DIR%\Persistence\services.txt" 2>&1
wmic service get name,displayname,pathname,startmode,state /format:csv >> "%OUTPUT_DIR%\Persistence\services_detail.csv" 2>&1

echo --- Scheduled Tasks --- > "%OUTPUT_DIR%\Persistence\scheduled_tasks.txt"
schtasks /query /fo LIST /v >> "%OUTPUT_DIR%\Persistence\scheduled_tasks.txt" 2>&1

echo --- Startup Programs (Registry) --- > "%OUTPUT_DIR%\Persistence\startup_registry.txt"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%OUTPUT_DIR%\Persistence\startup_registry.txt" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" >> "%OUTPUT_DIR%\Persistence\startup_registry.txt" 2>&1
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%OUTPUT_DIR%\Persistence\startup_registry.txt" 2>&1
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" >> "%OUTPUT_DIR%\Persistence\startup_registry.txt" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices" >> "%OUTPUT_DIR%\Persistence\startup_registry.txt" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce" >> "%OUTPUT_DIR%\Persistence\startup_registry.txt" 2>&1

echo --- Startup Folder --- > "%OUTPUT_DIR%\Persistence\startup_folder.txt"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" >> "%OUTPUT_DIR%\Persistence\startup_folder.txt" 2>&1
dir "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup" >> "%OUTPUT_DIR%\Persistence\startup_folder.txt" 2>&1

echo --- Drivers --- > "%OUTPUT_DIR%\Persistence\drivers.txt"
driverquery /v >> "%OUTPUT_DIR%\Persistence\drivers.txt" 2>&1

echo --- WMI Subscriptions --- > "%OUTPUT_DIR%\Persistence\wmi_subscriptions.txt"
wmic /namespace:\\root\subscription path __EventFilter get /format:list >> "%OUTPUT_DIR%\Persistence\wmi_subscriptions.txt" 2>&1
wmic /namespace:\\root\subscription path __EventConsumer get /format:list >> "%OUTPUT_DIR%\Persistence\wmi_subscriptions.txt" 2>&1
wmic /namespace:\\root\subscription path __FilterToConsumerBinding get /format:list >> "%OUTPUT_DIR%\Persistence\wmi_subscriptions.txt" 2>&1

:: ============================================
:: FILE SYSTEM INFORMATION
:: ============================================
echo [*] Collecting File System Information...

echo --- Drives --- > "%OUTPUT_DIR%\FileSystem\drives.txt"
wmic logicaldisk get caption,description,drivetype,filesystem,freespace,size,volumename >> "%OUTPUT_DIR%\FileSystem\drives.txt" 2>&1

echo --- Recently Modified Files (24h) --- > "%OUTPUT_DIR%\FileSystem\recent_modified.txt"
forfiles /P C:\ /S /D +0 /C "cmd /c echo @path @fdate @ftime" >> "%OUTPUT_DIR%\FileSystem\recent_modified.txt" 2>&1

echo --- Temp Directory --- > "%OUTPUT_DIR%\FileSystem\temp_files.txt"
dir /s /a "%TEMP%" >> "%OUTPUT_DIR%\FileSystem\temp_files.txt" 2>&1
dir /s /a "C:\Windows\Temp" >> "%OUTPUT_DIR%\FileSystem\temp_files.txt" 2>&1

echo --- Prefetch Files --- > "%OUTPUT_DIR%\FileSystem\prefetch.txt"
dir "C:\Windows\Prefetch" >> "%OUTPUT_DIR%\FileSystem\prefetch.txt" 2>&1

echo --- Recent Files --- > "%OUTPUT_DIR%\FileSystem\recent_items.txt"
dir "%APPDATA%\Microsoft\Windows\Recent" >> "%OUTPUT_DIR%\FileSystem\recent_items.txt" 2>&1

:: ============================================
:: SECURITY INFORMATION
:: ============================================
echo [*] Collecting Security Information...

mkdir "%OUTPUT_DIR%\Security" 2>nul

echo --- Security Policy --- > "%OUTPUT_DIR%\Security\secpol.txt"
secedit /export /cfg "%OUTPUT_DIR%\Security\secpol.inf" >> "%OUTPUT_DIR%\Security\secpol.txt" 2>&1

echo --- Audit Policy --- > "%OUTPUT_DIR%\Security\auditpol.txt"
auditpol /get /category:* >> "%OUTPUT_DIR%\Security\auditpol.txt" 2>&1

echo --- Windows Defender Status --- > "%OUTPUT_DIR%\Security\defender.txt"
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -GetFiles >> "%OUTPUT_DIR%\Security\defender.txt" 2>&1
powershell -command "Get-MpComputerStatus" >> "%OUTPUT_DIR%\Security\defender.txt" 2>&1

echo --- Antivirus Products --- > "%OUTPUT_DIR%\Security\antivirus.txt"
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,pathToSignedProductExe,productState /format:list >> "%OUTPUT_DIR%\Security\antivirus.txt" 2>&1

:: ============================================
:: COMPLETION
:: ============================================
echo [%date% %time%] Collection Complete >> "%OUTPUT_DIR%\collection.log"
echo.
echo [*] Live Response Collection Complete!
echo [*] Output saved to: %OUTPUT_DIR%
echo.

pause
endlocal
```

### Method 2: PowerShell Collection Script

Create `WindowsLiveResponse.ps1`:

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Live Response Collection Script
.DESCRIPTION
    Collects volatile and semi-volatile data from a live Windows system
.PARAMETER OutputPath
    Path to save collected data
.PARAMETER CaseID
    Case identifier for this collection
#>

param(
    [string]$OutputPath = ".\Output",
    [string]$CaseID = "IR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Configuration
$Hostname = $env:COMPUTERNAME
$OutputDir = Join-Path $OutputPath $CaseID
$ErrorActionPreference = "SilentlyContinue"

# Create output directories
$Directories = @(
    "System",
    "Network",
    "Processes",
    "Users",
    "Persistence",
    "FileSystem",
    "Security",
    "Memory",
    "EventLogs"
)

foreach ($Dir in $Directories) {
    New-Item -ItemType Directory -Path (Join-Path $OutputDir $Dir) -Force | Out-Null
}

# Start transcript
Start-Transcript -Path (Join-Path $OutputDir "collection_transcript.txt")

Write-Host "[*] Starting Live Response Collection" -ForegroundColor Green
Write-Host "[*] Case ID: $CaseID"
Write-Host "[*] Hostname: $Hostname"
Write-Host "[*] Output: $OutputDir"
Write-Host ""

# ============================================
# SYSTEM INFORMATION
# ============================================
Write-Host "[*] Collecting System Information..." -ForegroundColor Yellow

Get-ComputerInfo | Out-File "$OutputDir\System\computerinfo.txt"
Get-WmiObject Win32_OperatingSystem | Select-Object * | Out-File "$OutputDir\System\os_info.txt"
Get-HotFix | Out-File "$OutputDir\System\hotfixes.txt"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Out-File "$OutputDir\System\windows_version.txt"
Get-TimeZone | Out-File "$OutputDir\System\timezone.txt"
[System.TimeZoneInfo]::Local | Out-File "$OutputDir\System\timezone_detail.txt"
Get-Date | Out-File "$OutputDir\System\current_datetime.txt"
Get-ChildItem Env: | Out-File "$OutputDir\System\environment_variables.txt"

# ============================================
# NETWORK INFORMATION
# ============================================
Write-Host "[*] Collecting Network Information..." -ForegroundColor Yellow

Get-NetIPConfiguration | Out-File "$OutputDir\Network\ip_configuration.txt"
Get-NetIPAddress | Out-File "$OutputDir\Network\ip_addresses.txt"
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).Name}} | Export-Csv "$OutputDir\Network\tcp_connections.csv" -NoTypeInformation
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,@{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).Name}} | Export-Csv "$OutputDir\Network\udp_endpoints.csv" -NoTypeInformation
Get-NetRoute | Out-File "$OutputDir\Network\routes.txt"
Get-NetNeighbor | Out-File "$OutputDir\Network\arp_cache.txt"
Get-DnsClientCache | Out-File "$OutputDir\Network\dns_cache.txt"
Get-SmbShare | Out-File "$OutputDir\Network\smb_shares.txt"
Get-SmbSession | Out-File "$OutputDir\Network\smb_sessions.txt"
Get-SmbOpenFile | Out-File "$OutputDir\Network\smb_openfiles.txt"
Get-NetFirewallProfile | Out-File "$OutputDir\Network\firewall_profiles.txt"
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Out-File "$OutputDir\Network\firewall_rules_enabled.txt"

# ============================================
# PROCESS INFORMATION
# ============================================
Write-Host "[*] Collecting Process Information..." -ForegroundColor Yellow

Get-Process | Select-Object Id,ProcessName,Path,Company,CPU,WorkingSet64,StartTime,@{Name="ParentId";Expression={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}} | Export-Csv "$OutputDir\Processes\processes.csv" -NoTypeInformation

Get-WmiObject Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | Export-Csv "$OutputDir\Processes\processes_wmi.csv" -NoTypeInformation

# Process with network connections
$ProcessNetwork = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        ProcessId = $_.OwningProcess
        ProcessName = $proc.Name
        ProcessPath = $proc.Path
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort = $_.RemotePort
    }
}
$ProcessNetwork | Export-Csv "$OutputDir\Processes\processes_with_network.csv" -NoTypeInformation

# Loaded modules/DLLs
Get-Process | ForEach-Object {
    $proc = $_
    $_.Modules | Select-Object @{Name="ProcessId";Expression={$proc.Id}},@{Name="ProcessName";Expression={$proc.Name}},ModuleName,FileName
} | Export-Csv "$OutputDir\Processes\loaded_modules.csv" -NoTypeInformation

# ============================================
# USER INFORMATION
# ============================================
Write-Host "[*] Collecting User Information..." -ForegroundColor Yellow

Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordLastSet,Description | Export-Csv "$OutputDir\Users\local_users.csv" -NoTypeInformation
Get-LocalGroup | Out-File "$OutputDir\Users\local_groups.txt"
Get-LocalGroupMember -Group "Administrators" | Out-File "$OutputDir\Users\administrators.txt"

# Logged on users
quser 2>$null | Out-File "$OutputDir\Users\logged_on_users.txt"
query session 2>$null | Out-File "$OutputDir\Users\sessions.txt"

# User profiles
Get-WmiObject Win32_UserProfile | Select-Object LocalPath,SID,LastUseTime,Special | Export-Csv "$OutputDir\Users\user_profiles.csv" -NoTypeInformation

# ============================================
# PERSISTENCE MECHANISMS
# ============================================
Write-Host "[*] Collecting Persistence Information..." -ForegroundColor Yellow

# Services
Get-Service | Select-Object Name,DisplayName,Status,StartType | Export-Csv "$OutputDir\Persistence\services.csv" -NoTypeInformation
Get-WmiObject Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | Export-Csv "$OutputDir\Persistence\services_detail.csv" -NoTypeInformation

# Scheduled Tasks
Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author | Export-Csv "$OutputDir\Persistence\scheduled_tasks.csv" -NoTypeInformation
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        TaskName = $task.TaskName
        TaskPath = $task.TaskPath
        State = $task.State
        LastRunTime = $info.LastRunTime
        NextRunTime = $info.NextRunTime
        Actions = ($task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
    }
} | Export-Csv "$OutputDir\Persistence\scheduled_tasks_detail.csv" -NoTypeInformation

# Registry Run Keys
$RunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

$RunKeyData = foreach ($Key in $RunKeys) {
    if (Test-Path $Key) {
        Get-ItemProperty -Path $Key | ForEach-Object {
            $props = $_.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
            foreach ($prop in $props) {
                [PSCustomObject]@{
                    Key = $Key
                    Name = $prop.Name
                    Value = $prop.Value
                }
            }
        }
    }
}
$RunKeyData | Export-Csv "$OutputDir\Persistence\registry_run_keys.csv" -NoTypeInformation

# Startup folders
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Out-File "$OutputDir\Persistence\startup_folder_user.txt"
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Out-File "$OutputDir\Persistence\startup_folder_all.txt"

# Drivers
Get-WmiObject Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName | Export-Csv "$OutputDir\Persistence\drivers.csv" -NoTypeInformation

# WMI Subscriptions
Get-WmiObject -Namespace root\Subscription -Class __EventFilter | Out-File "$OutputDir\Persistence\wmi_eventfilter.txt"
Get-WmiObject -Namespace root\Subscription -Class __EventConsumer | Out-File "$OutputDir\Persistence\wmi_eventconsumer.txt"
Get-WmiObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Out-File "$OutputDir\Persistence\wmi_binding.txt"

# ============================================
# FILE SYSTEM
# ============================================
Write-Host "[*] Collecting File System Information..." -ForegroundColor Yellow

Get-PSDrive -PSProvider FileSystem | Out-File "$OutputDir\FileSystem\drives.txt"
Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID,DriveType,FileSystem,FreeSpace,Size,VolumeName | Export-Csv "$OutputDir\FileSystem\logical_disks.csv" -NoTypeInformation

# Recently modified files (last 24 hours)
$Yesterday = (Get-Date).AddDays(-1)
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.LastWriteTime -gt $Yesterday -and -not $_.PSIsContainer } |
    Select-Object FullName,LastWriteTime,Length -First 1000 |
    Export-Csv "$OutputDir\FileSystem\recently_modified.csv" -NoTypeInformation

# Temp directories
Get-ChildItem $env:TEMP -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime,Length | Export-Csv "$OutputDir\FileSystem\temp_user.csv" -NoTypeInformation
Get-ChildItem "C:\Windows\Temp" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime,Length | Export-Csv "$OutputDir\FileSystem\temp_system.csv" -NoTypeInformation

# Prefetch
Get-ChildItem "C:\Windows\Prefetch" -ErrorAction SilentlyContinue | Select-Object Name,LastWriteTime,CreationTime | Export-Csv "$OutputDir\FileSystem\prefetch.csv" -NoTypeInformation

# Downloads folders
Get-ChildItem "$env:USERPROFILE\Downloads" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime,Length | Export-Csv "$OutputDir\FileSystem\downloads.csv" -NoTypeInformation

# ============================================
# SECURITY
# ============================================
Write-Host "[*] Collecting Security Information..." -ForegroundColor Yellow

# Windows Defender
Get-MpComputerStatus | Out-File "$OutputDir\Security\defender_status.txt"
Get-MpThreatDetection | Out-File "$OutputDir\Security\defender_detections.txt"
Get-MpThreat | Out-File "$OutputDir\Security\defender_threats.txt"

# Audit policy
auditpol /get /category:* | Out-File "$OutputDir\Security\audit_policy.txt"

# Security products
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue | Out-File "$OutputDir\Security\antivirus_products.txt"

# ============================================
# EVENT LOGS (Recent)
# ============================================
Write-Host "[*] Collecting Recent Event Logs..." -ForegroundColor Yellow

# Security events (last 24 hours)
$StartTime = (Get-Date).AddHours(-24)

Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$StartTime} -MaxEvents 5000 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,LevelDisplayName,Message |
    Export-Csv "$OutputDir\EventLogs\security_24h.csv" -NoTypeInformation

Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$StartTime} -MaxEvents 2000 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,LevelDisplayName,Message |
    Export-Csv "$OutputDir\EventLogs\system_24h.csv" -NoTypeInformation

Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$StartTime} -MaxEvents 2000 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,LevelDisplayName,Message |
    Export-Csv "$OutputDir\EventLogs\application_24h.csv" -NoTypeInformation

# PowerShell logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$StartTime} -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,Message |
    Export-Csv "$OutputDir\EventLogs\powershell_24h.csv" -NoTypeInformation

# Sysmon (if installed)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$StartTime} -MaxEvents 5000 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,Message |
    Export-Csv "$OutputDir\EventLogs\sysmon_24h.csv" -NoTypeInformation

# ============================================
# COMPLETION
# ============================================
Write-Host ""
Write-Host "[*] Live Response Collection Complete!" -ForegroundColor Green
Write-Host "[*] Output saved to: $OutputDir" -ForegroundColor Green

Stop-Transcript

# Generate hash of collected files
Get-ChildItem -Path $OutputDir -Recurse -File | ForEach-Object {
    [PSCustomObject]@{
        File = $_.FullName.Replace($OutputDir, "")
        SHA256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    }
} | Export-Csv "$OutputDir\collection_hashes.csv" -NoTypeInformation
```

### Method 3: KAPE Live Collection

```powershell
# Run KAPE for comprehensive live collection
.\kape.exe --tsource C: --tdest E:\Cases\%m --target !SANS_Triage --vss --mdest E:\Cases\%m\Parsed --module !EZParser
```

---

## 🐧 Part 2: Linux Live Response

### Linux Collection Script

Create `linux_live_response.sh`:

```bash
#!/bin/bash
# ============================================
# Linux Live Response Collection Script
# ============================================
# Run as root

# Configuration
CASE_ID="${1:-IR_$(date +%Y%m%d_%H%M%S)}"
OUTPUT_DIR="./Output/$CASE_ID"
HOSTNAME=$(hostname)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[*] Starting Linux Live Response Collection${NC}"
echo "[*] Case ID: $CASE_ID"
echo "[*] Hostname: $HOSTNAME"

# Create directories
mkdir -p "$OUTPUT_DIR"/{system,network,processes,users,persistence,filesystem,logs,memory}

# Start logging
exec > >(tee -a "$OUTPUT_DIR/collection.log") 2>&1
echo "[$(date)] Collection started on $HOSTNAME"

# ============================================
# SYSTEM INFORMATION
# ============================================
echo -e "${YELLOW}[*] Collecting System Information...${NC}"

date > "$OUTPUT_DIR/system/date.txt"
uptime > "$OUTPUT_DIR/system/uptime.txt"
uname -a > "$OUTPUT_DIR/system/uname.txt"
cat /etc/os-release > "$OUTPUT_DIR/system/os_release.txt" 2>/dev/null
cat /etc/*-release > "$OUTPUT_DIR/system/release_info.txt" 2>/dev/null
hostnamectl > "$OUTPUT_DIR/system/hostnamectl.txt" 2>/dev/null
cat /proc/version > "$OUTPUT_DIR/system/proc_version.txt"
cat /proc/cmdline > "$OUTPUT_DIR/system/cmdline.txt"
env > "$OUTPUT_DIR/system/environment.txt"
timedatectl > "$OUTPUT_DIR/system/timedatectl.txt" 2>/dev/null
cat /etc/timezone > "$OUTPUT_DIR/system/timezone.txt" 2>/dev/null

# Hardware info
lscpu > "$OUTPUT_DIR/system/cpu.txt" 2>/dev/null
free -h > "$OUTPUT_DIR/system/memory.txt"
df -h > "$OUTPUT_DIR/system/disk_usage.txt"
lsblk > "$OUTPUT_DIR/system/block_devices.txt"
fdisk -l > "$OUTPUT_DIR/system/fdisk.txt" 2>/dev/null
lspci > "$OUTPUT_DIR/system/pci_devices.txt" 2>/dev/null
lsusb > "$OUTPUT_DIR/system/usb_devices.txt" 2>/dev/null
dmidecode > "$OUTPUT_DIR/system/dmidecode.txt" 2>/dev/null

# ============================================
# NETWORK INFORMATION
# ============================================
echo -e "${YELLOW}[*] Collecting Network Information...${NC}"

ip addr > "$OUTPUT_DIR/network/ip_addr.txt"
ip route > "$OUTPUT_DIR/network/ip_route.txt"
ip neigh > "$OUTPUT_DIR/network/arp_cache.txt"
ss -tulpn > "$OUTPUT_DIR/network/listening_ports.txt"
ss -anp > "$OUTPUT_DIR/network/all_sockets.txt"
netstat -tulpn > "$OUTPUT_DIR/network/netstat_listening.txt" 2>/dev/null
netstat -anp > "$OUTPUT_DIR/network/netstat_all.txt" 2>/dev/null
cat /etc/resolv.conf > "$OUTPUT_DIR/network/resolv_conf.txt"
cat /etc/hosts > "$OUTPUT_DIR/network/hosts.txt"
iptables -L -n -v > "$OUTPUT_DIR/network/iptables.txt" 2>/dev/null
ip6tables -L -n -v > "$OUTPUT_DIR/network/ip6tables.txt" 2>/dev/null
nft list ruleset > "$OUTPUT_DIR/network/nftables.txt" 2>/dev/null
cat /proc/net/tcp > "$OUTPUT_DIR/network/proc_net_tcp.txt"
cat /proc/net/udp > "$OUTPUT_DIR/network/proc_net_udp.txt"

# ============================================
# PROCESS INFORMATION
# ============================================
echo -e "${YELLOW}[*] Collecting Process Information...${NC}"

ps auxwww > "$OUTPUT_DIR/processes/ps_aux.txt"
ps -ef > "$OUTPUT_DIR/processes/ps_ef.txt"
ps auxwwwf > "$OUTPUT_DIR/processes/ps_tree.txt"
pstree -p > "$OUTPUT_DIR/processes/pstree.txt" 2>/dev/null
top -b -n 1 > "$OUTPUT_DIR/processes/top.txt"

# Process details from /proc
mkdir -p "$OUTPUT_DIR/processes/proc_details"
for pid in /proc/[0-9]*; do
    pid_num=$(basename $pid)
    if [ -d "$pid" ]; then
        {
            echo "=== PID: $pid_num ==="
            echo "--- cmdline ---"
            cat "$pid/cmdline" 2>/dev/null | tr '\0' ' '
            echo ""
            echo "--- exe ---"
            ls -la "$pid/exe" 2>/dev/null
            echo "--- cwd ---"
            ls -la "$pid/cwd" 2>/dev/null
            echo "--- environ ---"
            cat "$pid/environ" 2>/dev/null | tr '\0' '\n'
            echo ""
            echo "--- fd ---"
            ls -la "$pid/fd" 2>/dev/null
            echo ""
        } >> "$OUTPUT_DIR/processes/proc_details/$pid_num.txt" 2>/dev/null
    fi
done

# Open files
lsof > "$OUTPUT_DIR/processes/lsof_all.txt" 2>/dev/null
lsof -i > "$OUTPUT_DIR/processes/lsof_network.txt" 2>/dev/null

# Loaded modules
lsmod > "$OUTPUT_DIR/processes/kernel_modules.txt"
cat /proc/modules > "$OUTPUT_DIR/processes/proc_modules.txt"

# ============================================
# USER INFORMATION
# ============================================
echo -e "${YELLOW}[*] Collecting User Information...${NC}"

cat /etc/passwd > "$OUTPUT_DIR/users/passwd.txt"
cat /etc/shadow > "$OUTPUT_DIR/users/shadow.txt" 2>/dev/null
cat /etc/group > "$OUTPUT_DIR/users/group.txt"
cat /etc/sudoers > "$OUTPUT_DIR/users/sudoers.txt" 2>/dev/null
cat /etc/sudoers.d/* > "$OUTPUT_DIR/users/sudoers_d.txt" 2>/dev/null
who > "$OUTPUT_DIR/users/who.txt"
w > "$OUTPUT_DIR/users/w.txt"
last -a > "$OUTPUT_DIR/users/last.txt"
lastlog > "$OUTPUT_DIR/users/lastlog.txt"
lastb > "$OUTPUT_DIR/users/lastb.txt" 2>/dev/null

# User home directories
for user_home in /home/* /root; do
    if [ -d "$user_home" ]; then
        user=$(basename "$user_home")
        mkdir -p "$OUTPUT_DIR/users/$user"
        
        # Bash history
        cat "$user_home/.bash_history" > "$OUTPUT_DIR/users/$user/bash_history.txt" 2>/dev/null
        cat "$user_home/.zsh_history" > "$OUTPUT_DIR/users/$user/zsh_history.txt" 2>/dev/null
        
        # SSH
        ls -la "$user_home/.ssh/" > "$OUTPUT_DIR/users/$user/ssh_dir.txt" 2>/dev/null
        cat "$user_home/.ssh/authorized_keys" > "$OUTPUT_DIR/users/$user/authorized_keys.txt" 2>/dev/null
        cat "$user_home/.ssh/known_hosts" > "$OUTPUT_DIR/users/$user/known_hosts.txt" 2>/dev/null
        
        # Recently accessed
        ls -lat "$user_home" | head -50 > "$OUTPUT_DIR/users/$user/recent_files.txt" 2>/dev/null
    fi
done

# ============================================
# PERSISTENCE MECHANISMS
# ============================================
echo -e "${YELLOW}[*] Collecting Persistence Information...${NC}"

# Cron jobs
crontab -l > "$OUTPUT_DIR/persistence/crontab_root.txt" 2>/dev/null
cat /etc/crontab > "$OUTPUT_DIR/persistence/etc_crontab.txt"
ls -la /etc/cron.* > "$OUTPUT_DIR/persistence/cron_dirs.txt" 2>/dev/null
cat /etc/cron.d/* > "$OUTPUT_DIR/persistence/cron_d.txt" 2>/dev/null
cat /etc/cron.daily/* > "$OUTPUT_DIR/persistence/cron_daily.txt" 2>/dev/null
cat /etc/cron.hourly/* > "$OUTPUT_DIR/persistence/cron_hourly.txt" 2>/dev/null

# At jobs
atq > "$OUTPUT_DIR/persistence/at_queue.txt" 2>/dev/null
ls -la /var/spool/at/ > "$OUTPUT_DIR/persistence/at_spool.txt" 2>/dev/null

# Systemd services
systemctl list-units --type=service --all > "$OUTPUT_DIR/persistence/systemd_services.txt" 2>/dev/null
systemctl list-unit-files --type=service > "$OUTPUT_DIR/persistence/systemd_unit_files.txt" 2>/dev/null
ls -la /etc/systemd/system/ > "$OUTPUT_DIR/persistence/systemd_system.txt" 2>/dev/null
ls -la /lib/systemd/system/ > "$OUTPUT_DIR/persistence/systemd_lib.txt" 2>/dev/null
ls -la /usr/lib/systemd/system/ > "$OUTPUT_DIR/persistence/systemd_usrlib.txt" 2>/dev/null

# Init scripts
ls -la /etc/init.d/ > "$OUTPUT_DIR/persistence/init_d.txt" 2>/dev/null
cat /etc/rc.local > "$OUTPUT_DIR/persistence/rc_local.txt" 2>/dev/null

# Startup scripts
ls -la /etc/profile.d/ > "$OUTPUT_DIR/persistence/profile_d.txt" 2>/dev/null
cat /etc/profile > "$OUTPUT_DIR/persistence/profile.txt"
cat /etc/bash.bashrc > "$OUTPUT_DIR/persistence/bashrc.txt" 2>/dev/null

# ============================================
# FILE SYSTEM
# ============================================
echo -e "${YELLOW}[*] Collecting File System Information...${NC}"

mount > "$OUTPUT_DIR/filesystem/mount.txt"
cat /etc/fstab > "$OUTPUT_DIR/filesystem/fstab.txt"
cat /proc/mounts > "$OUTPUT_DIR/filesystem/proc_mounts.txt"

# Recently modified files
find / -type f -mtime -1 2>/dev/null | head -1000 > "$OUTPUT_DIR/filesystem/modified_24h.txt"

# SUID/SGID binaries
find / -perm -4000 -type f 2>/dev/null > "$OUTPUT_DIR/filesystem/suid_files.txt"
find / -perm -2000 -type f 2>/dev/null > "$OUTPUT_DIR/filesystem/sgid_files.txt"

# World-writable files
find / -perm -002 -type f 2>/dev/null | head -500 > "$OUTPUT_DIR/filesystem/world_writable.txt"

# Temp directories
ls -la /tmp/ > "$OUTPUT_DIR/filesystem/tmp.txt"
ls -la /var/tmp/ > "$OUTPUT_DIR/filesystem/var_tmp.txt"
ls -la /dev/shm/ > "$OUTPUT_DIR/filesystem/dev_shm.txt" 2>/dev/null

# Hidden files in common locations
find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null > "$OUTPUT_DIR/filesystem/hidden_temp.txt"

# ============================================
# LOGS
# ============================================
echo -e "${YELLOW}[*] Collecting Log Files...${NC}"

# Copy important logs
cp /var/log/auth.log "$OUTPUT_DIR/logs/" 2>/dev/null
cp /var/log/secure "$OUTPUT_DIR/logs/" 2>/dev/null
cp /var/log/syslog "$OUTPUT_DIR/logs/" 2>/dev/null
cp /var/log/messages "$OUTPUT_DIR/logs/" 2>/dev/null
cp /var/log/kern.log "$OUTPUT_DIR/logs/" 2>/dev/null
cp /var/log/dmesg "$OUTPUT_DIR/logs/" 2>/dev/null
cp /var/log/cron "$OUTPUT_DIR/logs/" 2>/dev/null
cp /var/log/wtmp "$OUTPUT_DIR/logs/" 2>/dev/null
cp /var/log/btmp "$OUTPUT_DIR/logs/" 2>/dev/null
cp /var/log/lastlog "$OUTPUT_DIR/logs/" 2>/dev/null

# Audit logs
cp -r /var/log/audit/ "$OUTPUT_DIR/logs/" 2>/dev/null

# Journal
journalctl --since "24 hours ago" > "$OUTPUT_DIR/logs/journal_24h.txt" 2>/dev/null
journalctl -k --since "24 hours ago" > "$OUTPUT_DIR/logs/journal_kernel_24h.txt" 2>/dev/null

# ============================================
# DOCKER (if present)
# ============================================
if command -v docker &> /dev/null; then
    echo -e "${YELLOW}[*] Collecting Docker Information...${NC}"
    mkdir -p "$OUTPUT_DIR/docker"
    
    docker ps -a > "$OUTPUT_DIR/docker/containers.txt" 2>/dev/null
    docker images > "$OUTPUT_DIR/docker/images.txt" 2>/dev/null
    docker network ls > "$OUTPUT_DIR/docker/networks.txt" 2>/dev/null
    docker volume ls > "$OUTPUT_DIR/docker/volumes.txt" 2>/dev/null
    docker info > "$OUTPUT_DIR/docker/info.txt" 2>/dev/null
fi

# ============================================
# COMPLETION
# ============================================
echo "[$(date)] Collection completed"

# Create archive
echo -e "${YELLOW}[*] Creating archive...${NC}"
tar -czf "$OUTPUT_DIR.tar.gz" -C "$(dirname $OUTPUT_DIR)" "$(basename $OUTPUT_DIR)"

# Generate hashes
echo -e "${YELLOW}[*] Generating hashes...${NC}"
find "$OUTPUT_DIR" -type f -exec sha256sum {} \; > "$OUTPUT_DIR/collection_hashes.txt"
sha256sum "$OUTPUT_DIR.tar.gz" > "$OUTPUT_DIR.tar.gz.sha256"

echo -e "${GREEN}[*] Live Response Collection Complete!${NC}"
echo "[*] Output: $OUTPUT_DIR"
echo "[*] Archive: $OUTPUT_DIR.tar.gz"
```

Make executable:

```bash
chmod +x linux_live_response.sh
sudo ./linux_live_response.sh IR-2024-001
```

---

## 💾 Part 3: Memory Acquisition

### Windows Memory Acquisition

#### WinPMEM

```powershell
# Download WinPMEM
# https://github.com/Velocidex/WinPmem/releases

# Capture memory
.\winpmem_mini_x64.exe output.raw

# With extended options
.\winpmem_mini_x64.exe --format raw --output E:\Cases\memory.raw
```

#### DumpIt

```powershell
# Simply run DumpIt.exe
# It creates a raw memory dump in current directory
.\DumpIt.exe
```

#### Magnet RAM Capture

```powershell
# GUI-based tool
# Download from Magnet Forensics
.\MagnetRAMCapture.exe
```

### Linux Memory Acquisition

#### AVML (Microsoft)

```bash
# Download AVML
wget https://github.com/microsoft/avml/releases/latest/download/avml

# Capture memory
chmod +x avml
sudo ./avml memory.lime

# With compression
sudo ./avml --compress memory.lime.compressed
```

#### LiME

```bash
# Build LiME module
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make

# Load and capture
sudo insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"
```

---

## 📋 Part 4: Documentation

### Chain of Custody Form

```
CHAIN OF CUSTODY FORM
=====================

Case Number: _________________
Date: _________________

EVIDENCE ITEM
Item #: _________________
Description: _________________
Serial/ID: _________________
Hash (SHA256): _________________

COLLECTION INFORMATION
Collected By: _________________
Date/Time: _________________
Location: _________________
Method: _________________

TRANSFER LOG
| Date/Time | Released By | Received By | Purpose | Location |
|-----------|-------------|-------------|---------|----------|
|           |             |             |         |          |
|           |             |             |         |          |
|           |             |             |         |          |

Notes:
_______________________________________________________
_______________________________________________________
```

### Collection Notes Template

```
LIVE RESPONSE COLLECTION NOTES
==============================

Case: _________________
Date/Time Started: _________________
Date/Time Ended: _________________
Examiner: _________________

SYSTEM INFORMATION
Hostname: _________________
IP Address: _________________
OS Version: _________________
System Time: _________________
Time Zone: _________________
UTC Offset: _________________

COLLECTION DETAILS
Tools Used: _________________
Collection Method: _________________
Output Location: _________________

OBSERVATIONS
- 
- 
- 

ANOMALIES NOTED
- 
- 
- 

HASH VERIFICATION
Collection Hash (SHA256): _________________
```

---

## ❗ Part 5: Best Practices

### Before Collection

1. **Document everything** - Take photos, note system state
2. **Verify time** - Note system time vs actual time
3. **Check network** - Decide if isolation is needed
4. **Use trusted tools** - Run from portable media
5. **Hash your tools** - Prove tool integrity

### During Collection

1. **Minimize footprint** - Limit changes to system
2. **Order of volatility** - Memory first, then processes, then disk
3. **Log your actions** - Document every command
4. **Don't trust the system** - Use your own tools
5. **Collect, don't analyze** - Analysis comes later

### After Collection

1. **Verify integrity** - Check hashes
2. **Secure the data** - Encrypt if needed
3. **Document transfer** - Chain of custody
4. **Make working copies** - Analyze copies, preserve originals
5. **Store securely** - Follow evidence handling procedures

---

## 🗂️ Quick Reference

### Windows Commands

| Command | Purpose |
|---------|---------|
| `systeminfo` | System details |
| `netstat -anob` | Network connections with PIDs |
| `tasklist /v` | Process list with details |
| `wmic process get` | Process details via WMI |
| `query user` | Logged-on users |
| `schtasks /query` | Scheduled tasks |
| `reg query` | Registry queries |
| `net session` | Active sessions |

### Linux Commands

| Command | Purpose |
|---------|---------|
| `ps auxwww` | All processes with full commands |
| `ss -tulpn` | Listening ports |
| `lsof -i` | Open network files |
| `who` / `w` | Logged-on users |
| `last` | Login history |
| `crontab -l` | User cron jobs |
| `systemctl list-units` | Active services |
| `find / -mtime -1` | Recently modified files |

### Essential Tools

| Tool | Platform | Purpose |
|------|----------|---------|
| KAPE | Windows | Artifact collection |
| WinPMEM | Windows | Memory acquisition |
| DumpIt | Windows | Memory acquisition |
| Autoruns | Windows | Persistence analysis |
| AVML | Linux | Memory acquisition |
| LiME | Linux | Memory acquisition |

### File Locations to Collect

**Windows:**
- `C:\Windows\System32\winevt\Logs\` (Event logs)
- `C:\Windows\System32\config\` (Registry)
- `C:\Windows\Prefetch\` (Execution history)
- `C:\Users\*\NTUSER.DAT` (User registry)
- `C:\Users\*\AppData\` (User data)

**Linux:**
- `/var/log/` (System logs)
- `/etc/` (Configuration)
- `/home/*/.*history` (Command history)
- `/home/*/.ssh/` (SSH keys)
- `/tmp/`, `/var/tmp/` (Temp files)

---

*Part of the Incident Response & Log Aggregation Branch*
