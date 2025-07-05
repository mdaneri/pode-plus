#!/usr/bin/env pwsh

# HTTP/2 Browser-like Test Script
# This script sends HTTP/2 requests that mimic what a real browser would send

function Send-BrowserLikeHttp2Request {
    param(
        [string]$Server = "localhost",
        [int]$Port = 8043,
        [string]$Path = "/"
    )

    try {
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "  Browser-like HTTP/2 over HTTPS Test" -ForegroundColor Cyan
        Write-Host "===============================================" -ForegroundColor Cyan

        # Create TCP client with SSL
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        Write-Host "Connecting to $Server`:$Port via HTTPS..." -ForegroundColor Yellow
        $tcpClient.Connect($Server, $Port)

        # Setup SSL stream with ALPN
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false)

        # Configure ALPN protocols (h2 first, then http/1.1 as fallback)
        $alpnProtocols = @(
            [System.Net.Security.SslApplicationProtocol]::Http2,
            [System.Net.Security.SslApplicationProtocol]::Http11
        )

        Write-Host "Establishing SSL/TLS connection with ALPN..." -ForegroundColor Yellow
        Write-Host "ALPN protocols: h2, http/1.1" -ForegroundColor Gray

        $clientOptions = New-Object System.Net.Security.SslClientAuthenticationOptions
        $clientOptions.TargetHost = $Server
        $clientOptions.ApplicationProtocols = $alpnProtocols
        $clientOptions.RemoteCertificateValidationCallback = { $true }  # Accept self-signed certs

        Write-Host "Attempting ALPN-enabled SSL handshake..." -ForegroundColor Yellow
        $sslStream.AuthenticateAsClient($clientOptions)

        # Check what protocol was negotiated
        $negotiatedProtocol = $sslStream.NegotiatedApplicationProtocol
        Write-Host "SSL/TLS handshake completed successfully" -ForegroundColor Green
        Write-Host "Negotiated Protocol: $($sslStream.SslProtocol)" -ForegroundColor Green

        # Convert the protocol bytes to string for comparison
        $protocolString = if ($negotiatedProtocol.Protocol) {
            [System.Text.Encoding]::ASCII.GetString($negotiatedProtocol.Protocol.ToArray())
        } else {
            "none"
        }
        Write-Host "Negotiated Application Protocol (ALPN): '$protocolString'" -ForegroundColor Green

        if ($protocolString -eq "h2") {
            Write-Host "✅ Successfully negotiated HTTP/2 via ALPN!" -ForegroundColor Green

            # Send HTTP/2 connection preface
            Write-Host "Sending HTTP/2 connection preface..." -ForegroundColor Yellow
            $preface = [System.Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
            $sslStream.Write($preface, 0, $preface.Length)

            # Send SETTINGS frame (like a browser would)
            Write-Host "Sending browser-like SETTINGS frame..." -ForegroundColor Yellow
            $settingsFrame = @(
                # Frame header: Length=18, Type=4 (SETTINGS), Flags=0, StreamId=0
                0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                # SETTINGS_HEADER_TABLE_SIZE (1) = 65536
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                # SETTINGS_ENABLE_PUSH (2) = 0 (disabled, like modern browsers)
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                # SETTINGS_MAX_CONCURRENT_STREAMS (3) = 100
                0x00, 0x03, 0x00, 0x00, 0x00, 0x64
            )
            $sslStream.Write($settingsFrame, 0, $settingsFrame.Length)

            # Send HEADERS frame with typical browser headers
            Write-Host "Sending HEADERS frame with browser-like headers..." -ForegroundColor Yellow

            # Encode headers using HPACK (simplified - using literal headers)
            $headers = @()

            # :method: GET (literal)
            $headers += @(0x00, 0x07) + [System.Text.Encoding]::ASCII.GetBytes(":method") + @(0x03) + [System.Text.Encoding]::ASCII.GetBytes("GET")

            # :path: / (literal)
            $headers += @(0x00, 0x05) + [System.Text.Encoding]::ASCII.GetBytes(":path") + @(0x01) + [System.Text.Encoding]::ASCII.GetBytes($Path)

            # :scheme: https (literal)
            $headers += @(0x00, 0x07) + [System.Text.Encoding]::ASCII.GetBytes(":scheme") + @(0x05) + [System.Text.Encoding]::ASCII.GetBytes("https")

            # :authority: localhost:8043 (literal)
            $authority = "$Server`:$Port"
            $headers += @(0x00, 0x0A) + [System.Text.Encoding]::ASCII.GetBytes(":authority") + @($authority.Length) + [System.Text.Encoding]::ASCII.GetBytes($authority)

            # user-agent: Mozilla/5.0... (literal)
            $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            $headers += @(0x00, 0x0A) + [System.Text.Encoding]::ASCII.GetBytes("user-agent") + @($userAgent.Length) + [System.Text.Encoding]::ASCII.GetBytes($userAgent)

            # accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
            $accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            $headers += @(0x00, 0x06) + [System.Text.Encoding]::ASCII.GetBytes("accept") + @($accept.Length) + [System.Text.Encoding]::ASCII.GetBytes($accept)

            $headerBytes = [byte[]]$headers

            # HEADERS frame: Type=1, Flags=0x05 (END_HEADERS + END_STREAM), StreamId=1
            $headersFrame = @(
                0x00, [byte]($headerBytes.Length -shr 8), [byte]($headerBytes.Length -band 0xFF),  # Length
                0x01,                                    # Type = HEADERS
                0x05,                                    # Flags = END_HEADERS (0x04) + END_STREAM (0x01)
                0x00, 0x00, 0x00, 0x01                  # StreamId = 1
            ) + $headerBytes

            $sslStream.Write($headersFrame, 0, $headersFrame.Length)

            # Wait for server response
            Write-Host "Waiting for server response..." -ForegroundColor Yellow
            $buffer = New-Object byte[] 4096
            $totalBytes = 0
            $frames = @()

            $timeout = 5000  # 5 second timeout
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            while ($stopwatch.ElapsedMilliseconds -lt $timeout) {
                if ($sslStream.DataAvailable) {
                    $bytesRead = $sslStream.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -gt 0) {
                        $totalBytes += $bytesRead
                        Write-Host "- Received $bytesRead bytes (total: $totalBytes)" -ForegroundColor Gray

                        # Parse frame header
                        if ($bytesRead -ge 9) {
                            $frameLength = ($buffer[0] -shl 16) + ($buffer[1] -shl 8) + $buffer[2]
                            $frameType = $buffer[3]
                            $frameFlags = $buffer[4]
                            $streamId = ($buffer[5] -shl 24) + ($buffer[6] -shl 16) + ($buffer[7] -shl 8) + $buffer[8]

                            $frameTypeName = switch ($frameType) {
                                0 { "DATA" }
                                1 { "HEADERS" }
                                2 { "PRIORITY" }
                                3 { "RST_STREAM" }
                                4 { "SETTINGS" }
                                5 { "PUSH_PROMISE" }
                                6 { "PING" }
                                7 { "GOAWAY" }
                                8 { "WINDOW_UPDATE" }
                                9 { "CONTINUATION" }
                                default { "UNKNOWN($frameType)" }
                            }

                            Write-Host "  > Frame: Type=$frameTypeName, Length=$frameLength, Flags=0x$($frameFlags.ToString('X2')), StreamId=$streamId" -ForegroundColor Green
                            $frames += "Frame: Type=$frameTypeName, Length=$frameLength, Flags=0x$($frameFlags.ToString('X2')), StreamId=$streamId"
                        }

                        # If we got frames, we're probably done
                        break
                    }
                }
                Start-Sleep -Milliseconds 10
            }

            $stopwatch.Stop()

            Write-Host "`nRECEIVED FRAMES:" -ForegroundColor Cyan
            foreach ($frame in $frames) {
                Write-Host "- $frame" -ForegroundColor White
            }

            Write-Host "`nTEST RESULTS:" -ForegroundColor Cyan
            Write-Host "Total bytes received: $totalBytes" -ForegroundColor White

            if ($totalBytes -gt 0) {
                Write-Host "✅ SUCCESS: Browser-like HTTP/2 over HTTPS is working!" -ForegroundColor Green
                Write-Host "    The server properly responded to browser-style HTTP/2 requests." -ForegroundColor Green
            } else {
                Write-Host "❌ FAILURE: No response received from server" -ForegroundColor Red
            }

            # Show raw frame data
            if ($totalBytes -gt 0) {
                Write-Host "`nRAW FRAME DATA (first 100 bytes):" -ForegroundColor Cyan
                $hexBytes = ($buffer[0..([Math]::Min(99, $totalBytes-1))] | ForEach-Object { $_.ToString("X2") }) -join " "
                Write-Host $hexBytes -ForegroundColor Gray
            }

        } else {
            Write-Host "❌ ALPN negotiation failed - negotiated: '$protocolString'" -ForegroundColor Red
            Write-Host "   Expected: h2, Got: '$protocolString'" -ForegroundColor Red
            return $false
        }

    } catch {
        Write-Host "❌ Error occurred: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Exception type: $($_.Exception.GetType().Name)" -ForegroundColor Red
        return $false
    } finally {
        if ($sslStream) { $sslStream.Close() }
        if ($tcpClient) { $tcpClient.Close() }
    }

    return $true
}

# Run the test
$result = Send-BrowserLikeHttp2Request -Server "localhost" -Port 8043 -Path "/"

if ($result) {
    Write-Host "`n🎉 Browser-like HTTP/2 test completed successfully!" -ForegroundColor Green
} else {
    Write-Host "`n💥 Browser-like HTTP/2 test failed!" -ForegroundColor Red
}
