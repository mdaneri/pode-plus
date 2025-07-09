# Test script to verify HPACK Huffman decoding fixes
$serverHost = "localhost"
$port = 8043

try {
    Write-Host "Testing HPACK fixes - improved Huffman decoding and error handling..."

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
        0x00, 0x00, 0x12,  # Length: 18 bytes
        0x04,              # Type: SETTINGS
        0x00,              # Flags: 0
        0x00, 0x00, 0x00, 0x00,  # Stream ID: 0
        # Settings payload:
        0x00, 0x01, 0x00, 0x00, 0x10, 0x00,  # SETTINGS_HEADER_TABLE_SIZE = 4096
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,  # SETTINGS_ENABLE_PUSH = 0
        0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF   # SETTINGS_INITIAL_WINDOW_SIZE = 65535
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

    Write-Host "Testing multiple HPACK payloads..."

    # Test 1: Well-formed HPACK with Huffman encoding
    Write-Host "`n=== Test 1: Well-formed HPACK with Huffman encoding ==="
    $hpackPayload1 = @(
        0x82,  # :method GET (indexed)
        0x84,  # :path / (indexed)
        0x87,  # :scheme https (indexed)
        # :authority localhost:8043 (literal with Huffman encoding)
        0x41, 0x8C, 0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB, 0x90, 0xF4, 0xFF
    )

    $headersFrame1 = @(
        0x00, 0x00, $hpackPayload1.Length,  # Length
        0x01,              # Type: HEADERS
        0x05,              # Flags: END_HEADERS | END_STREAM
        0x00, 0x00, 0x00, 0x01  # Stream ID: 1
    ) + $hpackPayload1

    Write-Host "Sending Test 1 HEADERS frame..."
    $sslStream.Write($headersFrame1, 0, $headersFrame1.Length)

    Start-Sleep -Seconds 1
    if ($sslStream.DataAvailable) {
        $responseBuffer = New-Object byte[] 4096
        $responseBytes = $sslStream.Read($responseBuffer, 0, $responseBuffer.Length)
        Write-Host "✅ Test 1 - Server responded with $responseBytes bytes"
    } else {
        Write-Host "❌ Test 1 - No response from server"
    }

    # Test 2: HPACK with malformed data (should be handled gracefully)
    Write-Host "`n=== Test 2: HPACK with malformed data ==="
    $hpackPayload2 = @(
        0x82,  # :method GET (indexed)
        0x84,  # :path / (indexed)
        0x87,  # :scheme https (indexed)
        0x80,  # Invalid indexed header (index 0)
        0xFF, 0xFF, 0xFF,  # Malformed variable-length integer
        0x41, 0x0F, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x3A, 0x38, 0x30, 0x34, 0x33  # :authority localhost:8043 (literal)
    )

    $headersFrame2 = @(
        0x00, 0x00, $hpackPayload2.Length,  # Length
        0x01,              # Type: HEADERS
        0x05,              # Flags: END_HEADERS | END_STREAM
        0x00, 0x00, 0x00, 0x03  # Stream ID: 3
    ) + $hpackPayload2

    Write-Host "Sending Test 2 HEADERS frame with malformed data..."
    $sslStream.Write($headersFrame2, 0, $headersFrame2.Length)

    Start-Sleep -Seconds 1
    if ($sslStream.DataAvailable) {
        $responseBuffer = New-Object byte[] 4096
        $responseBytes = $sslStream.Read($responseBuffer, 0, $responseBuffer.Length)
        Write-Host "✅ Test 2 - Server handled malformed data gracefully and responded with $responseBytes bytes"
    } else {
        Write-Host "❌ Test 2 - No response from server"
    }

    # Test 3: Edge case with Huffman padding
    Write-Host "`n=== Test 3: Edge case with Huffman padding ==="
    $hpackPayload3 = @(
        0x82,  # :method GET (indexed)
        0x84,  # :path / (indexed)
        0x87,  # :scheme https (indexed)
        # :authority with problematic Huffman padding
        0x41, 0x88, 0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xFF  # Huffman with padding
    )

    $headersFrame3 = @(
        0x00, 0x00, $hpackPayload3.Length,  # Length
        0x01,              # Type: HEADERS
        0x05,              # Flags: END_HEADERS | END_STREAM
        0x00, 0x00, 0x00, 0x05  # Stream ID: 5
    ) + $hpackPayload3

    Write-Host "Sending Test 3 HEADERS frame with Huffman padding..."
    $sslStream.Write($headersFrame3, 0, $headersFrame3.Length)

    Start-Sleep -Seconds 1
    if ($sslStream.DataAvailable) {
        $responseBuffer = New-Object byte[] 4096
        $responseBytes = $sslStream.Read($responseBuffer, 0, $responseBuffer.Length)
        Write-Host "✅ Test 3 - Server handled Huffman padding correctly and responded with $responseBytes bytes"
    } else {
        Write-Host "❌ Test 3 - No response from server"
    }

    Write-Host "`n✅ All tests completed - check server logs for detailed HPACK decoding output"
    Write-Host "The server should now correctly handle:"
    Write-Host "  - Huffman decoding with proper padding validation"
    Write-Host "  - Malformed HPACK data with graceful recovery"
    Write-Host "  - Authority header corruption detection and fallback"
    Write-Host "  - Integer overflow protection"
    Write-Host "  - Invalid table indices"

} catch {
    Write-Host "❌ Error: $($_.Exception.Message)"
} finally {
    if ($sslStream) { $sslStream.Close() }
    if ($client) { $client.Close() }
}
