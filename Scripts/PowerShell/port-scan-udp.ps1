function port-scan-udp {
  param($hosts, $ports)

  if (!$hosts -or !$ports) {
    Write-Host "usage: port-scan-udp <authorized-host|hosts> <port|ports>"
    Write-Host " e.g.: port-scan-udp 192.0.2.10 445"
    return
  }

  # This sends a one-byte UDP probe. Run only for individual hosts and ports
  # explicitly included in your written test scope; a service may process it.
  $out = Join-Path (Get-Location).Path ("scanresults-{0}.csv" -f [guid]::NewGuid().ToString("N"))
  $fileStream = [System.IO.File]::Open(
    $out,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None
  )
  $writer = New-Object System.IO.StreamWriter($fileStream)
  $writer.WriteLine("host,protocol,port,state")

  try {
    foreach ($p in [array]$ports) {
      $portNumber = 0
      if (-not [int]::TryParse([string]$p, [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) {
        Write-Warning "Skipping invalid UDP port: $p"
        continue
      }

      foreach ($h in [array]$hosts) {
        $u = New-Object System.Net.Sockets.UdpClient
        try {
          $u.Client.ReceiveTimeout = 1000
          $u.Connect([string]$h, $portNumber)
          [byte[]]$probe = @(1)
          [void]$u.Send($probe, $probe.Length)

          $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
          $state = "Open|Filtered"
          try {
            $response = $u.Receive([ref]$remote)
            if ($null -ne $response) {
              # A response is evidence of a reachable UDP service, but not proof
              # that the service is safe or that the target is correctly attributed.
              $state = "Open"
            }
          }
          catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
              # Windows commonly reports an ICMP port-unreachable this way.
              $state = "Closed"
            } elseif ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
              $state = "Open|Filtered"
            } else {
              $state = "Open|Filtered"
            }
          }
          catch {
            $state = "Error"
            Write-Warning ("Probe failed for {0}:{1}: {2}" -f $h, $portNumber, $_.Exception.Message)
          }

          $row = "{0},udp,{1},{2}" -f $h, $portNumber, $state
          Write-Host $row
          $writer.WriteLine($row)
        }
        catch {
          Write-Warning ("Could not probe {0}:{1}: {2}" -f $h, $portNumber, $_.Exception.Message)
        }
        finally {
          if ($null -ne $u) { $u.Dispose() }
        }
      }
    }
  }
  finally {
    $writer.Flush()
    $writer.Dispose()
    Write-Host "Results saved to $out"
  }
}

# Examples (use only individually scoped lab hosts):
# port-scan-udp 192.0.2.10 137
# port-scan-udp 192.0.2.10 (135,137,445)
# 192.0.2.10,192.0.2.11 | ForEach-Object { port-scan-udp $_ 137 }
