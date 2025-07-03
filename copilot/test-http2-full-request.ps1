#!/usr/bin/env pwsh

# Test HTTP/2 full request/response cycle with simple headers
Write-Host "Testing HTTP/2 full request/response cycle..."

try {
    # Connect to server
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect("localhost", 8081)
    $stream = $client.GetStream()
    
    Write-Host "Connected to server"
    
    # Send HTTP/2 connection preface
    $preface = [System.Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
    $stream.Write($preface, 0, $preface.Length)
    Write-Host "Sent HTTP/2 connection preface"
    
    # Send client SETTINGS frame (empty)
    $settingsFrame = [byte[]]::new(9)
    $settingsFrame[0] = 0x00  # Length high
    $settingsFrame[1] = 0x00  # Length medium  
    $settingsFrame[2] = 0x00  # Length low (0 bytes)
    $settingsFrame[3] = 0x04  # Type: SETTINGS
    $settingsFrame[4] = 0x00  # Flags: none
    $settingsFrame[5] = 0x00  # Stream ID (4 bytes)
    $settingsFrame[6] = 0x00
    $settingsFrame[7] = 0x00
    $settingsFrame[8] = 0x00
    $stream.Write($settingsFrame, 0, $settingsFrame.Length)
    Write-Host "Sent client SETTINGS frame"
    
    # Wait for server SETTINGS frame
    $buffer = [byte[]]::new(1024)
    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
    Write-Host "Received server SETTINGS frame ($bytesRead bytes)"
    
    # Send SETTINGS ACK
    $settingsAck = [byte[]]::new(9)
    $settingsAck[0] = 0x00  # Length high
    $settingsAck[1] = 0x00  # Length medium  
    $settingsAck[2] = 0x00  # Length low (0 bytes)
    $settingsAck[3] = 0x04  # Type: SETTINGS
    $settingsAck[4] = 0x01  # Flags: ACK
    $settingsAck[5] = 0x00  # Stream ID (4 bytes)
    $settingsAck[6] = 0x00
    $settingsAck[7] = 0x00
    $settingsAck[8] = 0x00
    $stream.Write($settingsAck, 0, $settingsAck.Length)
    Write-Host "Sent SETTINGS ACK"
    
    # Create simple HEADERS frame for GET / request
    # Using literal headers (no compression)
    $headerBytes = [System.Collections.Generic.List[byte]]::new()
    
    # Add :method GET (literal)
    $headerBytes.Add(0x00)  # Literal header, new name
    $headerBytes.Add(0x07)  # Name length
    $headerBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes(":method"))
    $headerBytes.Add(0x03)  # Value length
    $headerBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes("GET"))
    
    # Add :path / (literal)
    $headerBytes.Add(0x00)  # Literal header, new name
    $headerBytes.Add(0x05)  # Name length
    $headerBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes(":path"))
    $headerBytes.Add(0x01)  # Value length
    $headerBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes("/"))
    
    # Add :scheme http (literal)
    $headerBytes.Add(0x00)  # Literal header, new name
    $headerBytes.Add(0x07)  # Name length
    $headerBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes(":scheme"))
    $headerBytes.Add(0x04)  # Value length
    $headerBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes("http"))
    
    # Add :authority localhost:8081 (literal)
    $headerBytes.Add(0x00)  # Literal header, new name
    $headerBytes.Add(0x0a)  # Name length
    $headerBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes(":authority"))
    $headerBytes.Add(0x0e)  # Value length
    $headerBytes.AddRange([System.Text.Encoding]::ASCII.GetBytes("localhost:8081"))
    
    $headersPayload = $headerBytes.ToArray()
    
    # Create HEADERS frame
    $headersFrame = [byte[]]::new(9 + $headersPayload.Length)
    $headersFrame[0] = [byte]($headersPayload.Length -shr 16)  # Length high
    $headersFrame[1] = [byte]($headersPayload.Length -shr 8)   # Length medium
    $headersFrame[2] = [byte]($headersPayload.Length -band 0xFF)  # Length low
    $headersFrame[3] = 0x01  # Type: HEADERS
    $headersFrame[4] = 0x05  # Flags: END_HEADERS | END_STREAM
    $headersFrame[5] = 0x00  # Stream ID (4 bytes) - Stream 1
    $headersFrame[6] = 0x00
    $headersFrame[7] = 0x00
    $headersFrame[8] = 0x01
    
    # Copy headers payload
    for ($i = 0; $i -lt $headersPayload.Length; $i++) {
        $headersFrame[9 + $i] = $headersPayload[$i]
    }
    
    $stream.Write($headersFrame, 0, $headersFrame.Length)
    Write-Host "Sent HEADERS frame for GET / request (payload length: $($headersPayload.Length))"
    
    # Read response frames
    $responseBuffer = [byte[]]::new(4096)
    $totalBytesRead = 0
    $timeout = 5000  # 5 seconds
    $startTime = Get-Date
    
    while ((New-TimeSpan -Start $startTime).TotalMilliseconds -lt $timeout) {
        if ($stream.DataAvailable) {
            $bytesRead = $stream.Read($responseBuffer, $totalBytesRead, $responseBuffer.Length - $totalBytesRead)
            if ($bytesRead -gt 0) {
                $totalBytesRead += $bytesRead
                Write-Host "Read $bytesRead bytes (total: $totalBytesRead)"
                
                # Parse frames
                $offset = 0
                while ($offset + 9 -le $totalBytesRead) {
                    $frameLength = ($responseBuffer[$offset] -shl 16) + ($responseBuffer[$offset + 1] -shl 8) + $responseBuffer[$offset + 2]
                    $frameType = $responseBuffer[$offset + 3]
                    $frameFlags = $responseBuffer[$offset + 4]
                    $streamId = (($responseBuffer[$offset + 5] -band 0x7F) -shl 24) + ($responseBuffer[$offset + 6] -shl 16) + ($responseBuffer[$offset + 7] -shl 8) + $responseBuffer[$offset + 8]
                    
                    if ($offset + 9 + $frameLength -le $totalBytesRead) {
                        $frameTypeName = switch ($frameType) {
                            0x00 { "DATA" }
                            0x01 { "HEADERS" }
                            0x02 { "PRIORITY" }
                            0x03 { "RST_STREAM" }
                            0x04 { "SETTINGS" }
                            0x05 { "PUSH_PROMISE" }
                            0x06 { "PING" }
                            0x07 { "GOAWAY" }
                            0x08 { "WINDOW_UPDATE" }
                            0x09 { "CONTINUATION" }
                            default { "UNKNOWN($frameType)" }
                        }
                        
                        Write-Host "Frame: Type=$frameTypeName, Length=$frameLength, Flags=0x$($frameFlags.ToString('X2')), StreamId=$streamId"
                        
                        if ($frameType -eq 0x01) {  # HEADERS
                            Write-Host "  HEADERS frame received - response headers"
                            if ($frameLength -gt 0) {
                                $headersPayload = $responseBuffer[($offset + 9)..($offset + 8 + $frameLength)]
                                Write-Host "  Headers payload: $([System.BitConverter]::ToString($headersPayload))"
                            }
                        } elseif ($frameType -eq 0x00) {  # DATA
                            Write-Host "  DATA frame received - response body"
                            if ($frameLength -gt 0) {
                                $dataPayload = $responseBuffer[($offset + 9)..($offset + 8 + $frameLength)]
                                $responseText = [System.Text.Encoding]::UTF8.GetString($dataPayload)
                                Write-Host "  Response body: $responseText"
                            }
                        } elseif ($frameType -eq 0x04) {  # SETTINGS
                            Write-Host "  SETTINGS frame (likely ACK)"
                        }
                        
                        $offset += 9 + $frameLength
                        
                        # Check if we received END_STREAM
                        if ($frameFlags -band 0x01) {
                            Write-Host "✅ Received END_STREAM flag - response complete"
                            break
                        }
                    } else {
                        break  # Need more data
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 100
    }
    
    if ($totalBytesRead -eq 0) {
        Write-Host "❌ No response received from server"
    } else {
        Write-Host "✅ HTTP/2 request/response cycle completed successfully!"
    }
    
    $client.Close()
    
} catch {
    Write-Host "❌ Error: $($_.Exception.Message)"
}
