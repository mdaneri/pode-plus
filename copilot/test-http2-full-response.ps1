#!/usr/bin/env pwsh

# Test HTTP/2 full request/response cycle
param(
    [string]$Server = "localhost",
    [int]$Port = 8081,
    [int]$TimeoutSeconds = 10
)

Write-Host "Testing HTTP/2 full request/response cycle..."
Write-Host "Server: $Server"
Write-Host "Port: $Port"
Write-Host ""

try {
    # Create TCP client
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($Server, $Port)
    $stream = $client.GetStream()
    
    Write-Host "✅ Connected to ${Server}:${Port}"
    
    # Send HTTP/2 connection preface
    Write-Host "Sending HTTP/2 connection preface..."
    $preface = [System.Text.Encoding]::UTF8.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
    $stream.Write($preface, 0, $preface.Length)
    $stream.Flush()
    
    # Send client SETTINGS frame
    Write-Host "Sending client SETTINGS frame..."
    $settingsFrame = @(
        # Frame length (24 bits) = 12 bytes (2 settings)
        0x00, 0x00, 0x0C,
        # Frame type (SETTINGS = 4)
        0x04,
        # Flags (0)
        0x00,
        # Stream ID (0)
        0x00, 0x00, 0x00, 0x00,
        # SETTINGS_HEADER_TABLE_SIZE (1) = 4096
        0x00, 0x01, 0x00, 0x00, 0x10, 0x00,
        # SETTINGS_ENABLE_PUSH (2) = 0
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00
    )
    $stream.Write($settingsFrame, 0, $settingsFrame.Length)
    $stream.Flush()
    
    # Send HEADERS frame with GET request
    Write-Host "Sending HEADERS frame with GET request..."
    $headers = @(
        # :method GET (indexed from static table)
        0x82,
        # :path / (indexed from static table)  
        0x84,
        # :authority localhost:8081
        0x41, 0x0F, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x3A, 0x38, 0x30, 0x38, 0x31,
        # :scheme http (indexed from static table)
        0x86
    )
    
    $headersFrame = @(
        # Frame length (24 bits)
        0x00, 0x00, ($headers.Length -band 0xFF),
        # Frame type (HEADERS = 1)
        0x01,
        # Flags (END_HEADERS = 4, END_STREAM = 1)
        0x05,
        # Stream ID (1)
        0x00, 0x00, 0x00, 0x01
    ) + $headers
    
    $stream.Write($headersFrame, 0, $headersFrame.Length)
    $stream.Flush()
    
    # Read response with timeout
    Write-Host "Reading server response..."
    $responseBuffer = New-Object byte[] 8192
    $totalBytesRead = 0
    $timeoutMs = $TimeoutSeconds * 1000
    $startTime = Get-Date
    
    while (((Get-Date) - $startTime).TotalMilliseconds -lt $timeoutMs) {
        if ($stream.DataAvailable) {
            $bytesRead = $stream.Read($responseBuffer, $totalBytesRead, $responseBuffer.Length - $totalBytesRead)
            if ($bytesRead -gt 0) {
                $totalBytesRead += $bytesRead
                Write-Host "Read $bytesRead bytes (total: $totalBytesRead)"
                
                # Try to parse frames
                $offset = 0
                while ($offset + 9 -le $totalBytesRead) {
                    # Parse frame header
                    $frameLength = ($responseBuffer[$offset] -shl 16) -bor ($responseBuffer[$offset + 1] -shl 8) -bor $responseBuffer[$offset + 2]
                    $frameType = $responseBuffer[$offset + 3]
                    $frameFlags = $responseBuffer[$offset + 4]
                    $streamId = (($responseBuffer[$offset + 5] -band 0x7F) -shl 24) -bor ($responseBuffer[$offset + 6] -shl 16) -bor ($responseBuffer[$offset + 7] -shl 8) -bor $responseBuffer[$offset + 8]
                    
                    Write-Host "Frame: Type=$frameType, Length=$frameLength, Flags=0x$('{0:X2}' -f $frameFlags), StreamId=$streamId"
                    
                    # Check if we have the complete frame
                    if ($offset + 9 + $frameLength -le $totalBytesRead) {
                        # Process frame based on type
                        switch ($frameType) {
                            4 { # SETTINGS
                                Write-Host "  SETTINGS frame"
                                if ($frameFlags -band 0x01) {
                                    Write-Host "    SETTINGS ACK"
                                } else {
                                    Write-Host "    SETTINGS with $($frameLength / 6) settings"
                                }
                            }
                            1 { # HEADERS
                                Write-Host "  HEADERS frame"
                                if ($frameLength -gt 0) {
                                    $headerData = $responseBuffer[($offset + 9)..($offset + 8 + $frameLength)]
                                    Write-Host "    Headers data: $([System.BitConverter]::ToString($headerData))"
                                }
                            }
                            0 { # DATA
                                Write-Host "  DATA frame"
                                if ($frameLength -gt 0) {
                                    $dataBytes = $responseBuffer[($offset + 9)..($offset + 8 + $frameLength)]
                                    $dataString = [System.Text.Encoding]::UTF8.GetString($dataBytes)
                                    Write-Host "    Data: $dataString"
                                }
                                if ($frameFlags -band 0x01) {
                                    Write-Host "    END_STREAM flag set"
                                }
                            }
                            default {
                                Write-Host "  Unknown frame type: $frameType"
                            }
                        }
                        
                        $offset += 9 + $frameLength
                    } else {
                        # Incomplete frame, wait for more data
                        break
                    }
                }
                
                # Check if we got END_STREAM
                if ($frameType -eq 0 -and ($frameFlags -band 0x01)) {
                    Write-Host "✅ Received END_STREAM, response complete"
                    break
                }
            }
        }
        Start-Sleep -Milliseconds 100
    }
    
    if ($totalBytesRead -eq 0) {
        Write-Host "❌ No response received within timeout"
    } else {
        Write-Host "✅ HTTP/2 full request/response cycle completed"
        Write-Host "Total bytes received: $totalBytesRead"
    }
    
} catch {
    Write-Host "❌ Error: $($_.Exception.Message)"
} finally {
    if ($stream) { $stream.Close() }
    if ($client) { $client.Close() }
}
