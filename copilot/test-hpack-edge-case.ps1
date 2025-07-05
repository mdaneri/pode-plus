# Test HPACK decoder with the problematic payload from Edge browser
$serverHost = "localhost"
$port = 8043

try {
    Write-Host "Testing problematic HPACK payload from Edge browser..."

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
    Write-Host "✅ SSL/TLS handshake completed successfully"
    Write-Host "   Negotiated Protocol: $($sslStream.SslProtocol)"
    Write-Host "   Negotiated Application Protocol (ALPN): $($sslStream.NegotiatedApplicationProtocol)"

    # Send HTTP/2 connection preface
    Write-Host "Sending HTTP/2 connection preface..."
    $preface = [System.Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
    $sslStream.Write($preface, 0, $preface.Length)

    # Send client SETTINGS frame
    Write-Host "Sending client SETTINGS frame..."
    $settingsFrame = @(
        0x00, 0x00, 0x18,  # Length: 24 bytes (4 settings)
        0x04,              # Type: SETTINGS
        0x00,              # Flags: 0
        0x00, 0x00, 0x00, 0x00,  # Stream ID: 0
        # Settings payload:
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00,  # SETTINGS_HEADER_TABLE_SIZE = 65536
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,  # SETTINGS_ENABLE_PUSH = 0
        0x00, 0x04, 0x00, 0x5F, 0xFF, 0x00,  # SETTINGS_INITIAL_WINDOW_SIZE = 6291456
        0x00, 0x06, 0x00, 0x04, 0x00, 0x00   # SETTINGS_MAX_HEADER_LIST_SIZE = 262144
    )
    $sslStream.Write($settingsFrame, 0, $settingsFrame.Length)

    # Wait for server SETTINGS frame
    Write-Host "Reading server SETTINGS frame..."
    $buffer = New-Object byte[] 1024
    $bytesRead = $sslStream.Read($buffer, 0, $buffer.Length)
    Write-Host "Server sent $bytesRead bytes"

    # Send SETTINGS ACK
    Write-Host "Sending SETTINGS ACK..."
    $settingsAck = @(
        0x00, 0x00, 0x00,  # Length: 0
        0x04,              # Type: SETTINGS
        0x01,              # Flags: ACK
        0x00, 0x00, 0x00, 0x00  # Stream ID: 0
    )
    $sslStream.Write($settingsAck, 0, $settingsAck.Length)

    # Create problematic HPACK payload similar to Edge browser
    Write-Host "Sending problematic HEADERS frame with Edge-like HPACK payload..."

    # This is a simplified version of the problematic payload from your log
    # Starting with indexed header with index 0 (invalid) followed by problematic data
    $hpackPayload = @(
        0x80,              # Indexed header field with index 0 (INVALID)
        0x00, 0x00, 0x00,  # More problematic bytes
        0xFF,              # This should trigger variable-length decoding issues
        0x82, 0x41, 0x8A,  # Some bytes from the original problematic payload
        0xA0, 0xE4, 0x1D, 0x13, 0x9D, 0x09, 0xB8, 0xF0
    )

    $headersFrame = @(
        0x00, 0x00          # Length will be filled
    ) + @($hpackPayload.Length) + @(
        0x01,              # Type: HEADERS
        0x25,              # Flags: END_HEADERS | END_STREAM | PRIORITY
        0x00, 0x00, 0x00, 0x01  # Stream ID: 1
    ) + $hpackPayload

    # Fix the length field
    $headersFrame[0] = 0x00
    $headersFrame[1] = 0x00
    $headersFrame[2] = $hpackPayload.Length

    Write-Host "Sending HEADERS frame with problematic HPACK payload ($($hpackPayload.Length) bytes)..."
    $sslStream.Write($headersFrame, 0, $headersFrame.Length)

    # Wait for response or error
    Write-Host "Waiting for server response..."
    Start-Sleep -Seconds 2

    # Try to read response
    if ($sslStream.DataAvailable) {
        $responseBuffer = New-Object byte[] 4096
        $responseBytes = $sslStream.Read($responseBuffer, 0, $responseBuffer.Length)
        Write-Host "Server responded with $responseBytes bytes"

        if ($responseBytes -gt 0) {
            $hexString = ($responseBuffer[0..($responseBytes-1)] | ForEach-Object { "{0:X2}" -f $_ }) -join " "
            Write-Host "Response data: $hexString"
        }
    } else {
        Write-Host "No immediate response from server"
    }

    Write-Host "✅ Test completed - check server logs for HPACK decoder debug output"

} catch {
    Write-Host "❌ Error: $($_.Exception.Message)"
} finally {
    if ($sslStream) { $sslStream.Close() }
    if ($client) { $client.Close() }
}
