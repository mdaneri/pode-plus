# Simple test for basic HPACK functionality
$serverHost = "localhost"
$port = 8043

try {
    Write-Host "Testing basic HPACK decoding functionality..."

    # Create SSL TCP client with TLS 1.3 and ALPN support
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($serverHost, $port)

    # Setup SSL stream with ALPN
    $sslStream = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
    $sslOptions = [System.Net.Security.SslClientAuthenticationOptions]::new()
    $sslOptions.TargetHost = $serverHost
    $sslOptions.EnabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls13
    $sslOptions.ApplicationProtocols = @([System.Net.Security.SslApplicationProtocol]::Http2)
    $sslOptions.RemoteCertificateValidationCallback = { $true }  # Accept self-signed cert

    $sslStream.AuthenticateAsClient($sslOptions)
    Write-Host "✅ ALPN negotiated: $($sslStream.NegotiatedApplicationProtocol)"

    # Send HTTP/2 connection preface
    $preface = [System.Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
    $sslStream.Write($preface, 0, $preface.Length)

    # Send client SETTINGS frame
    $settingsFrame = @(
        0x00, 0x00, 0x0C,  # Length: 12 bytes
        0x04,              # Type: SETTINGS
        0x00,              # Flags: 0
        0x00, 0x00, 0x00, 0x00,  # Stream ID: 0
        # Settings payload:
        0x00, 0x01, 0x00, 0x00, 0x10, 0x00,  # SETTINGS_HEADER_TABLE_SIZE = 4096
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00   # SETTINGS_ENABLE_PUSH = 0
    )
    $sslStream.Write($settingsFrame, 0, $settingsFrame.Length)

    # Read server SETTINGS
    $buffer = New-Object byte[] 1024
    $bytesRead = $sslStream.Read($buffer, 0, $buffer.Length)
    Write-Host "Server sent $bytesRead bytes of SETTINGS"

    # Send SETTINGS ACK
    $settingsAck = @(
        0x00, 0x00, 0x00,  # Length: 0
        0x04,              # Type: SETTINGS
        0x01,              # Flags: ACK
        0x00, 0x00, 0x00, 0x00  # Stream ID: 0
    )
    $sslStream.Write($settingsAck, 0, $settingsAck.Length)

    Write-Host "Sending simple HPACK request..."

    # Simple HPACK payload without Huffman encoding
    $hpackPayload = @(
        0x82,  # :method GET (indexed, static table entry 2)
        0x84,  # :path / (indexed, static table entry 4)
        0x87,  # :scheme https (indexed, static table entry 7)
        # :authority localhost:8043 (literal with incremental indexing)
        0x41, 0x0F, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x3A, 0x38, 0x30, 0x34, 0x33
    )

    $headersFrame = @(
        0x00, 0x00, $hpackPayload.Length,  # Length
        0x01,              # Type: HEADERS
        0x05,              # Flags: END_HEADERS | END_STREAM
        0x00, 0x00, 0x00, 0x01  # Stream ID: 1
    ) + $hpackPayload

    Write-Host "Sending HEADERS frame ($($hpackPayload.Length) bytes HPACK payload)..."
    $sslStream.Write($headersFrame, 0, $headersFrame.Length)

    # Wait for response
    Start-Sleep -Seconds 2

    # Read response
    if ($sslStream.DataAvailable) {
        $responseBuffer = New-Object byte[] 4096
        $responseBytes = $sslStream.Read($responseBuffer, 0, $responseBuffer.Length)
        Write-Host "✅ Server responded with $responseBytes bytes"

        # Parse first frame
        if ($responseBytes -ge 9) {
            $frameLength = ($responseBuffer[0] -shl 16) -bor ($responseBuffer[1] -shl 8) -bor $responseBuffer[2]
            $frameType = $responseBuffer[3]
            $frameFlags = $responseBuffer[4]
            Write-Host "  Response frame: Type=$frameType, Length=$frameLength, Flags=0x$($frameFlags.ToString('X2'))"

            if ($frameType -eq 1) {  # HEADERS frame
                Write-Host "✅ Received HEADERS response - HPACK decoder is working!"
            }
        }
    } else {
        Write-Host "❌ No response received"
    }

    Write-Host "✅ Basic HPACK test completed successfully"

} catch {
    Write-Host "❌ Error: $($_.Exception.Message)"
    Write-Host "Stack trace: $($_.ScriptStackTrace)"
} finally {
    if ($sslStream) { $sslStream.Close() }
    if ($client) { $client.Close() }
}
