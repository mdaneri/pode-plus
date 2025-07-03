param(
    [string]$HostName = "localhost",
    [int]$Port = 8081
)

try {
    Write-Host "Connecting to $HostName`:$Port..."
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.Connect($HostName, $Port)
    $stream = $tcpClient.GetStream()
    
    Write-Host "Sending HTTP/2 connection preface..."
    
    # HTTP/2 connection preface
    $preface = [System.Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
    $stream.Write($preface, 0, $preface.Length)
    
    # Send SETTINGS frame
    Write-Host "Sending SETTINGS frame..."
    $settingsFrame = @(
        0x00, 0x00, 0x00,  # Length (0)
        0x04,              # Type (SETTINGS)
        0x00,              # Flags
        0x00, 0x00, 0x00, 0x00  # Stream ID (0)
    )
    $stream.Write($settingsFrame, 0, $settingsFrame.Length)
    
    # Send HEADERS frame for GET /
    Write-Host "Sending HEADERS frame for GET /..."
    $headers = @(
        0x00, 0x00, 0x10,  # Length (16)
        0x01,              # Type (HEADERS)
        0x05,              # Flags (END_HEADERS | END_STREAM)
        0x00, 0x00, 0x00, 0x01,  # Stream ID (1)
        # Pseudo-headers (simplified HPACK)
        0x82,              # :method GET (indexed)
        0x84,              # :path / (indexed)
        0x87,              # :scheme https (indexed)
        0x41, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x38, 0x30, 0x38, 0x31  # :authority localhost:8081
    )
    $stream.Write($headers, 0, $headers.Length)
    
    Write-Host "Waiting for server response..."
    $buffer = New-Object byte[] 4096
    $totalReceived = 0
    $allData = @()
    
    # Read response with timeout
    $startTime = Get-Date
    $timeout = 5000  # 5 seconds
    
    while (((Get-Date) - $startTime).TotalMilliseconds -lt $timeout) {
        if ($stream.DataAvailable) {
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -gt 0) {
                $totalReceived += $bytesRead
                $allData += $buffer[0..($bytesRead-1)]
                Write-Host "Received $bytesRead bytes (total: $totalReceived)"
                
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
                    
                    Write-Host "Frame: Type=$frameTypeName, Length=$frameLength, Flags=$frameFlags, StreamId=$streamId"
                    
                    if ($offset + 9 + $frameLength -le $allData.Length) {
                        if ($frameType -eq 0x1 -and $frameLength -gt 0) {  # HEADERS frame
                            $payload = $allData[($offset+9)..($offset+8+$frameLength)]
                            Write-Host "  HEADERS payload: $($payload | ForEach-Object { '{0:X2}' -f $_ } | Join-String -Separator ' ')"
                        } elseif ($frameType -eq 0x0 -and $frameLength -gt 0) {  # DATA frame
                            $payload = $allData[($offset+9)..($offset+8+$frameLength)]
                            $payloadText = [System.Text.Encoding]::UTF8.GetString($payload)
                            Write-Host "  DATA payload: $payloadText"
                        }
                        $offset += 9 + $frameLength
                    } else {
                        break  # Incomplete frame
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 10
    }
    
    Write-Host "Total bytes received: $totalReceived"
    if ($totalReceived -gt 0) {
        Write-Host "Raw response (hex): $($allData | ForEach-Object { '{0:X2}' -f $_ } | Join-String -Separator ' ')"
    }
    
} catch {
    Write-Host "Error: $_"
} finally {
    if ($stream) { $stream.Close() }
    if ($tcpClient) { $tcpClient.Close() }
}
