# PowerShell System Enumeration Script
# WARNING: For educational purposes only. Use only in authorized testing environments.

Write-Host "=== System Enumeration Script ===" -ForegroundColor Cyan
Write-Host ""

# System Information
Write-Host "[+] System Information" -ForegroundColor Green
Get-ComputerInfo | Select-Object CsName, OsArchitecture, OsVersion, OsLocalDateTime | Format-List

# Current User
Write-Host "[+] Current User" -ForegroundColor Green
whoami
whoami /priv
whoami /groups

# Network Configuration
Write-Host "[+] Network Configuration" -ForegroundColor Green
Get-NetIPConfiguration | Format-Table

# Running Processes
Write-Host "[+] Running Processes" -ForegroundColor Green
Get-Process | Select-Object Name, Id, Path | Format-Table -AutoSize

# Services
Write-Host "[+] Running Services" -ForegroundColor Green
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, Status | Format-Table -AutoSize

# Local Users
Write-Host "[+] Local Users" -ForegroundColor Green
Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize

# Local Administrators
Write-Host "[+] Local Administrators" -ForegroundColor Green
Get-LocalGroupMember Administrators | Format-Table

# Scheduled Tasks
Write-Host "[+] Scheduled Tasks" -ForegroundColor Green
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, State | Format-Table -AutoSize

# Installed Software
Write-Host "[+] Installed Software" -ForegroundColor Green
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Select-Object DisplayName, DisplayVersion, Publisher | 
    Format-Table -AutoSize

# Environment Variables
Write-Host "[+] Environment Variables" -ForegroundColor Green
Get-ChildItem Env: | Format-Table -AutoSize

# PowerShell History
Write-Host "[+] PowerShell History Location" -ForegroundColor Green
(Get-PSReadlineOption).HistorySavePath

Write-Host ""
Write-Host "[+] Enumeration Complete" -ForegroundColor Cyan
