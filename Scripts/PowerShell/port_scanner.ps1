# PowerShell Port Scanner
# WARNING: For educational purposes only. Use only in authorized testing environments.
# Usage: .\port_scanner.ps1 -Target 192.168.1.1 -StartPort 1 -EndPort 1024

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    
    [Parameter(Mandatory=$true)]
    [int]$StartPort,
    
    [Parameter(Mandatory=$true)]
    [int]$EndPort,
    
    [int]$Timeout = 1000
)

Write-Host "=== PowerShell Port Scanner ===" -ForegroundColor Cyan
Write-Host "[+] Target: $Target" -ForegroundColor Green
Write-Host "[+] Port Range: $StartPort - $EndPort" -ForegroundColor Green
Write-Host "[+] Timeout: $Timeout ms`n" -ForegroundColor Green

$openPorts = @()

$StartPort..$EndPort | ForEach-Object {
    $port = $_
    $socket = New-Object System.Net.Sockets.TcpClient
    
    try {
        $connection = $socket.BeginConnect($Target, $port, $null, $null)
        $wait = $connection.AsyncWaitHandle.WaitOne($Timeout, $false)
        
        if ($wait) {
            $socket.EndConnect($connection)
            Write-Host "[+] Port $port is OPEN" -ForegroundColor Green
            $openPorts += $port
        }
    } catch {
        # Port is closed
    } finally {
        $socket.Close()
    }
    
    # Progress indicator
    if ($port % 50 == 0) {
        Write-Host "[*] Scanned up to port $port..." -ForegroundColor Yellow
    }
}

Write-Host "`n[+] Scan Complete!" -ForegroundColor Cyan
Write-Host "[+] Found $($openPorts.Count) open ports" -ForegroundColor Green

if ($openPorts.Count -gt 0) {
    Write-Host "[+] Open Ports: $($openPorts -join ', ')" -ForegroundColor Green
}
