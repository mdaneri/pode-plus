try {
    Write-Host 'Connecting to localhost:8081...'
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.Connect('localhost', 8081)
    $stream = $tcpClient.GetStream()

    Write-Host 'Sending HTTP/2 connection preface (all at once)...'
    $http2Preface = 'PRI * HTTP/2.0' + "`r`n`r`n" + 'SM' + "`r`n`r`n"
    $prefaceBytes = [System.Text.Encoding]::ASCII.GetBytes($http2Preface)

    # Send the entire preface at once
    $stream.Write($prefaceBytes, 0, $prefaceBytes.Length)
    $stream.Flush()

    Write-Host 'HTTP/2 preface sent, waiting for response...'

    # Wait for response (a bit longer to allow processing)
    Start-Sleep -Milliseconds 500
    $buffer = New-Object byte[] 1024
    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)

    if ($bytesRead -gt 0) {
        $response = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
        Write-Host "Server response: $response"
    } else {
        Write-Host 'No response received'
    }

    $stream.Close()
    $tcpClient.Close()
    Write-Host 'Connection closed'
} catch {
    Write-Host "Error: $($_.Exception.Message)"
}
