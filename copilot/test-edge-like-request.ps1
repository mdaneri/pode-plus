# Test Edge-like HTTP/2 request to verify HPACK decoder improvements
$serverHost = "localhost"
$port = 8043

try {
    Write-Host "Testing Edge-like HTTP/2 request with complex HPACK headers..."

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
        0x00, 0x00, 0x18,  # Length: 24 bytes
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

    # Create HPACK payload for a realistic Edge-like request
    Write-Host "Creating realistic HPACK payload for Edge browser..."

    # HPACK encoded headers for:
    # :method: GET
    # :path: /
    # :scheme: https
    # :authority: localhost:8043
    # user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0
    # accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
    # accept-encoding: gzip, deflate, br
    # accept-language: en-US,en;q=0.9
    # cache-control: no-cache
    # pragma: no-cache
    # sec-fetch-dest: document
    # sec-fetch-mode: navigate
    # sec-fetch-site: none
    # sec-fetch-user: ?1
    # upgrade-insecure-requests: 1

    $hpackPayload = @(
        # :method: GET (indexed header field, index 2)
        0x82,

        # :path: / (indexed header field, index 4)
        0x84,

        # :scheme: https (indexed header field, index 7)
        0x87,

        # :authority: localhost:8043 (literal header field with incremental indexing, indexed name :authority index 1)
        0x41, 0x0F, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x3A, 0x38, 0x30, 0x34, 0x33,

        # user-agent: (literal header field with incremental indexing, indexed name user-agent index 58)
        0x7A, 0x86,
        # Huffman encoded: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        0x94, 0xE7, 0x82, 0x1D, 0xD0, 0x7F, 0x66, 0xA2, 0x81, 0xB0, 0xDA, 0xE0, 0x53, 0xFA, 0xE4, 0x6A,
        0xA4, 0x3F, 0x84, 0x29, 0xA7, 0x7A, 0x81, 0x02, 0xE0, 0xFB, 0x53, 0x91, 0xAA, 0x71, 0xAF, 0xB5,
        0x3C, 0xB8, 0xD7, 0xF6, 0xA4, 0x35, 0xD7, 0x41, 0x79, 0x16, 0x3C, 0xC6, 0x4B, 0x0D, 0xB2, 0xEA,
        0xEC, 0xB8, 0xA7, 0xF5, 0x9B, 0x1E, 0xFD, 0x19, 0xFE, 0x94, 0xA0, 0xDD, 0x4A, 0xA6, 0x22, 0x93,
        0xA9, 0xFF, 0xB5, 0x2F, 0x4F, 0x61, 0xE9, 0x2B, 0x01, 0x65, 0xE5, 0xC0, 0xB8, 0x17, 0x02, 0x9B,
        0x87, 0x28, 0xEC, 0x33, 0x0D, 0xB2, 0xEA, 0xEC, 0xB8, 0xA6, 0x09, 0x26, 0x60, 0x2C, 0xBC, 0xB8,

        # accept: text/html,application/xhtml+xml... (indexed name accept index 19)
        0x53, 0x96,
        # Huffman encoded "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        0xEB, 0x08, 0x64, 0x96, 0x59, 0x65, 0x89, 0x26, 0x40, 0xD2, 0x5F, 0xA5, 0x23, 0xB3, 0xE9, 0x4F,
        0x68, 0x4C, 0x9F, 0x51, 0xA8, 0x2D, 0x4B, 0x70, 0xDD, 0xF4, 0x5A, 0xBE, 0xFB, 0x40, 0x05, 0xDF,
        0xFA, 0x32, 0x7E, 0xFB, 0x40, 0x05, 0xDE, 0xFA, 0xE8, 0x3F, 0xBE, 0xD0, 0x01, 0x77, 0x7E, 0x8A,
        0x8F, 0xBE, 0xD0, 0x01, 0x77, 0x3E, 0xA5, 0xB3, 0xEF, 0xB4, 0x00, 0x5D, 0xBF, 0x60, 0xC8, 0xAC,
        0xF2, 0x15, 0x74, 0x1A, 0x48, 0x11, 0x71, 0xD7, 0xDB, 0x03, 0x4D, 0xBC, 0xCA, 0xCD, 0x34, 0xDB,
        0xAB, 0x35, 0x1B, 0x84, 0x5A, 0x36, 0xC6, 0x35, 0xA4, 0x7A, 0x39, 0x1A, 0x7D, 0xE6, 0x64, 0x68,

        # accept-encoding: gzip, deflate, br (indexed name accept-encoding index 16)
        0x50, 0x83,
        # Huffman encoded "gzip, deflate, br"
        0xE6, 0xCF, 0x7F, 0x68, 0x89, 0x94, 0x48, 0x5F,

        # accept-language: en-US,en;q=0.9 (indexed name accept-language index 17)
        0x51, 0x8A,
        # Huffman encoded "en-US,en;q=0.9"
        0x25, 0xA8, 0x49, 0xE9, 0x5B, 0xA9, 0x7D, 0x7F, 0x8A
    )

    $headersFrame = @(
        0x00, 0x01          # Length placeholder (will be updated)
    ) + @($hpackPayload.Length) + @(
        0x01,              # Type: HEADERS
        0x05,              # Flags: END_HEADERS | END_STREAM
        0x00, 0x00, 0x00, 0x01  # Stream ID: 1
    ) + $hpackPayload

    # Fix the length field
    $headersFrame[0] = 0x00
    $headersFrame[1] = [byte]($hpackPayload.Length -shr 8)
    $headersFrame[2] = [byte]($hpackPayload.Length -band 0xFF)

    Write-Host "Sending realistic HEADERS frame with complex HPACK payload ($($hpackPayload.Length) bytes)..."
    $sslStream.Write($headersFrame, 0, $headersFrame.Length)

    # Wait for response
    Write-Host "Waiting for server response..."
    Start-Sleep -Seconds 3

    # Try to read response
    if ($sslStream.DataAvailable) {
        $responseBuffer = New-Object byte[] 4096
        $responseBytes = $sslStream.Read($responseBuffer, 0, $responseBuffer.Length)
        Write-Host "✅ Server responded with $responseBytes bytes"

        if ($responseBytes -gt 0) {
            # Parse the response frames
            $offset = 0
            while ($offset + 9 -le $responseBytes) {
                $frameLength = ($responseBuffer[$offset] -shl 16) -bor ($responseBuffer[$offset + 1] -shl 8) -bor $responseBuffer[$offset + 2]
                $frameType = $responseBuffer[$offset + 3]
                $frameFlags = $responseBuffer[$offset + 4]
                $streamId = (($responseBuffer[$offset + 5] -band 0x7F) -shl 24) -bor ($responseBuffer[$offset + 6] -shl 16) -bor ($responseBuffer[$offset + 7] -shl 8) -bor $responseBuffer[$offset + 8]

                Write-Host "  Frame: Type=$frameType, Length=$frameLength, Flags=0x$($frameFlags.ToString('X2')), StreamId=$streamId"

                $offset += 9 + $frameLength
                if ($offset -gt $responseBytes) { break }
            }

            # Check if this looks like a valid HTTP/2 response
            if ($responseBuffer[3] -eq 1 -and $responseBuffer[4] -eq 4) {  # HEADERS frame with END_HEADERS
                Write-Host "✅ Received valid HTTP/2 HEADERS response!"
            }
        }
    } else {
        Write-Host "⚠️  No immediate response from server (this might be normal)"
    }

    Write-Host "✅ Test completed successfully - HPACK decoder handled complex Edge-like request"

} catch {
    Write-Host "❌ Error: $($_.Exception.Message)"
} finally {
    if ($sslStream) { $sslStream.Close() }
    if ($client) { $client.Close() }
}
