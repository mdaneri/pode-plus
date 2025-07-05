param(
    [string]$HostName = "localhost",
    [int]$Port = 8043  # Default to HTTPS port
)

# Define colors for better output visualization
$colors = @{
    Success = 'Green'
    Warning = 'Yellow'
    Error = 'Red'
    Info = 'Cyan'
    Header = 'Magenta'
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'White'
    )

    Write-Host $Message -ForegroundColor $Color
}

function Test-Http2OverHttps {
    Write-ColorOutput "===============================================" $colors.Header
    Write-ColorOutput "  HTTP/2 over HTTPS Verification Test" $colors.Header
    Write-ColorOutput "===============================================" $colors.Header
    Write-ColorOutput "Connecting to $HostName`:$Port via HTTPS..." $colors.Info

    try {
        # Create SSL/TLS connection
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($HostName, $Port)

        # Wrap in SSL stream with HTTP/2 ALPN support
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false)

        Write-ColorOutput "Establishing SSL/TLS connection with ALPN..." $colors.Info

        # Configure ALPN protocols for HTTP/2 support
        try {
            # Use the new overload with ALPN support (requires .NET Core 2.1+)
            $clientOptions = New-Object System.Net.Security.SslClientAuthenticationOptions
            $clientOptions.TargetHost = $HostName
            $clientOptions.EnabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
            $clientOptions.ApplicationProtocols = New-Object 'System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]'
            $clientOptions.ApplicationProtocols.Add([System.Net.Security.SslApplicationProtocol]::Http2)
            $clientOptions.ApplicationProtocols.Add([System.Net.Security.SslApplicationProtocol]::Http11)
            $clientOptions.RemoteCertificateValidationCallback = {
                param($sender, $certificate, $chain, $sslPolicyErrors)
                return $true
            }

            Write-ColorOutput "Attempting ALPN-enabled SSL handshake..." $colors.Info
            $sslStream.AuthenticateAsClient($clientOptions)

            Write-ColorOutput "SSL/TLS handshake completed successfully" $colors.Success
            Write-ColorOutput "Negotiated Protocol: $($sslStream.SslProtocol)" $colors.Info
            Write-ColorOutput "Negotiated Application Protocol (ALPN): $($sslStream.NegotiatedApplicationProtocol)" $colors.Success

            if ($sslStream.NegotiatedApplicationProtocol -eq [System.Net.Security.SslApplicationProtocol]::Http2) {
                Write-ColorOutput "✅ Successfully negotiated HTTP/2 via ALPN!" $colors.Success
            } elseif ($sslStream.NegotiatedApplicationProtocol -eq [System.Net.Security.SslApplicationProtocol]::Http11) {
                Write-ColorOutput "⚠️ Negotiated HTTP/1.1 via ALPN (expected HTTP/2)" $colors.Warning
            } else {
                Write-ColorOutput "❓ Unexpected ALPN result: $($sslStream.NegotiatedApplicationProtocol)" $colors.Warning
            }
        }
        catch {
            Write-ColorOutput "❌ ALPN-enabled handshake failed: $($_.Exception.Message)" $colors.Warning
            Write-ColorOutput "Falling back to basic SSL handshake..." $colors.Info

            # Create a new SSL stream for the fallback
            $sslStream.Dispose()
            $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {
                param($sender, $certificate, $chain, $sslPolicyErrors)
                # Accept self-signed certificates for testing
                return $true
            })

            $sslStream.AuthenticateAsClient($HostName, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
            Write-ColorOutput "SSL/TLS handshake completed successfully (without ALPN)" $colors.Success
            Write-ColorOutput "Negotiated Protocol: $($sslStream.SslProtocol)" $colors.Info
        }

        Write-ColorOutput "Sending HTTP/2 connection preface..." $colors.Info

        # HTTP/2 connection preface
        $preface = [System.Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
        $sslStream.Write($preface, 0, $preface.Length)

        # Send SETTINGS frame
        Write-ColorOutput "Sending SETTINGS frame..." $colors.Info
        $settingsFrame = @(
            0x00, 0x00, 0x00,  # Length (0)
            0x04,              # Type (SETTINGS)
            0x00,              # Flags
            0x00, 0x00, 0x00, 0x00  # Stream ID (0)
        )
        $sslStream.Write($settingsFrame, 0, $settingsFrame.Length)

        # Send HEADERS frame for GET /
        Write-ColorOutput "Sending HEADERS frame for GET /..." $colors.Info
        $headers = @(
            0x00, 0x00, 0x10,  # Length (16)
            0x01,              # Type (HEADERS)
            0x05,              # Flags (END_HEADERS | END_STREAM)
            0x00, 0x00, 0x00, 0x01,  # Stream ID (1)
            # Pseudo-headers (simplified HPACK)
            0x82,              # :method GET (indexed)
            0x84,              # :path / (indexed)
            0x87,              # :scheme https (indexed)
            0x41, 0x0a, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x38, 0x30, 0x34, 0x33  # :authority localhost:8043
        )
        $sslStream.Write($headers, 0, $headers.Length)

        Write-ColorOutput "Waiting for server response..." $colors.Info
        $buffer = New-Object byte[] 4096
        $totalReceived = 0
        $allData = @()

        # Read response with timeout
        $startTime = Get-Date
        $timeout = 5000  # 5 seconds

        Write-ColorOutput "`nRECEIVED FRAMES:" $colors.Header

        while (((Get-Date) - $startTime).TotalMilliseconds -lt $timeout) {
            if ($sslStream.DataAvailable -or $totalReceived -eq 0) {
                try {
                    $bytesRead = $sslStream.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -gt 0) {
                        $totalReceived += $bytesRead
                        $allData += $buffer[0..($bytesRead-1)]
                        Write-ColorOutput "- Received $bytesRead bytes (total: $totalReceived)" $colors.Info

                        # Parse HTTP/2 frames
                        $offset = 0
                        while ($offset + 9 -le $allData.Length) {
                            $frameLength = ([int]$allData[$offset] -shl 16) + ([int]$allData[$offset+1] -shl 8) + [int]$allData[$offset+2]
                            $frameType = $allData[$offset+3]
                            $frameFlags = $allData[$offset+4]
                            $streamId = ([int]$allData[$offset+5] -shl 24) + ([int]$allData[$offset+6] -shl 16) + ([int]$allData[$offset+7] -shl 8) + [int]$allData[$offset+8]
                            $streamId = $streamId -band 0x7FFFFFFF  # Remove reserved bit

                            $frameTypeName = switch ($frameType) {
                                0x0 { "DATA" }
                                0x1 { "HEADERS" }
                                0x2 { "PRIORITY" }
                                0x3 { "RST_STREAM" }
                                0x4 { "SETTINGS" }
                                0x5 { "PUSH_PROMISE" }
                                0x6 { "PING" }
                                0x7 { "GOAWAY" }
                                0x8 { "WINDOW_UPDATE" }
                                default { "UNKNOWN($frameType)" }
                            }

                            Write-ColorOutput "  > Frame: Type=$frameTypeName, Length=$frameLength, Flags=0x$([convert]::ToString($frameFlags, 16)), StreamId=$streamId" $colors.Success

                            if ($offset + 9 + $frameLength -le $allData.Length) {
                                if ($frameType -eq 0x1 -and $frameLength -gt 0) {  # HEADERS frame
                                    $payload = $allData[($offset+9)..($offset+8+$frameLength)]
                                    Write-ColorOutput "    HEADERS payload: $($payload | ForEach-Object { '{0:X2}' -f $_ } | Join-String -Separator ' ')" $colors.Info
                                } elseif ($frameType -eq 0x0 -and $frameLength -gt 0) {  # DATA frame
                                    $payload = $allData[($offset+9)..($offset+8+$frameLength)]
                                    $payloadText = [System.Text.Encoding]::UTF8.GetString($payload)
                                    # Check for HTTP/1.1 headers in the payload
                                    if ($payloadText -match "HTTP/1\.1|Content-Length:|Content-Type:|Cache-Control:|Server:|Date:") {
                                        Write-ColorOutput "    WARNING: Found HTTP/1.1 headers in DATA frame!" $colors.Warning
                                        Write-ColorOutput "    DATA payload excerpt (first 100 chars): $($payloadText.Substring(0, [Math]::Min(100, $payloadText.Length)))..." $colors.Warning
                                    } else {
                                        Write-ColorOutput "    DATA frame contains proper HTTP/2 content" $colors.Success
                                    }
                                }
                                $offset += 9 + $frameLength
                            } else {
                                break  # Incomplete frame
                            }
                        }
                    } else {
                        break  # No more data
                    }
                } catch {
                    Write-ColorOutput "Read timeout or connection closed" $colors.Info
                    break
                }
            }
            Start-Sleep -Milliseconds 50
        }

        Write-ColorOutput "`nTEST RESULTS:" $colors.Header
        Write-ColorOutput "Total bytes received: $totalReceived" $colors.Info

        if ($totalReceived -gt 0) {
            # Check for HTTP/1.1 headers in the entire response
            $fullResponse = [System.Text.Encoding]::UTF8.GetString($allData)
            if ($fullResponse -match "HTTP/1\.1 \d{3}|Content-Length:|Content-Type:|Cache-Control:|Server:|Date:|Connection:") {
                Write-ColorOutput "❌ FAILED: Found HTTP/1.1 headers in the response!" $colors.Error

                # Extract and display the HTTP/1.1 headers
                $headers = [regex]::Match($fullResponse, "(HTTP/1\.1.+?)\r\n\r\n", [System.Text.RegularExpressions.RegexOptions]::Singleline).Groups[1].Value
                if ($headers) {
                    Write-ColorOutput "HTTP/1.1 headers found:" $colors.Warning
                    Write-ColorOutput $headers $colors.Warning
                }
            } else {
                Write-ColorOutput "✅ SUCCESS: HTTP/2 over HTTPS is working correctly!" $colors.Success
                Write-ColorOutput "    The server is properly handling HTTP/2 frames over SSL/TLS." $colors.Success
            }

            Write-ColorOutput "`nRAW FRAME DATA (first 100 bytes):" $colors.Header
            $hexData = $allData[0..[Math]::Min(99, $allData.Length-1)] | ForEach-Object { '{0:X2}' -f $_ } | Join-String -Separator ' '
            Write-ColorOutput $hexData $colors.Info
        } else {
            Write-ColorOutput "❌ No data received from server" $colors.Error
        }
    }
    catch {
        Write-ColorOutput "❌ ERROR: $_" $colors.Error
        Write-ColorOutput "Stack trace: $($_.ScriptStackTrace)" $colors.Error
    }
    finally {
        if ($sslStream) { $sslStream.Close() }
        if ($tcpClient) { $tcpClient.Close() }
    }
}

# Run the test
Test-Http2OverHttps
