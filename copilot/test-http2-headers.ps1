# Test HTTP/2 with actual HEADERS frame
$serverHost = "localhost"
$port = 8081

try {
    Write-Host "Connecting to $serverHost`:$port..."
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($serverHost, $port)
    
    $stream = $client.GetStream()
    
    # Send HTTP/2 connection preface
    Write-Host "Sending HTTP/2 connection preface..."
    $preface = [System.Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
    $stream.Write($preface, 0, $preface.Length)
    
    # Send initial SETTINGS frame (client settings)
    Write-Host "Sending client SETTINGS frame..."
    $settingsFrame = @(
        0x00, 0x00, 0x0C,  # Length: 12 bytes (2 settings)
        0x04,              # Type: SETTINGS
        0x00,              # Flags: none
        0x00, 0x00, 0x00, 0x00,  # Stream ID: 0
        
        # Setting 1: SETTINGS_HEADER_TABLE_SIZE = 4096
        0x00, 0x01,        # Setting ID: 1
        0x00, 0x00, 0x10, 0x00,  # Value: 4096
        
        # Setting 2: SETTINGS_ENABLE_PUSH = 0
        0x00, 0x02,        # Setting ID: 2
        0x00, 0x00, 0x00, 0x00   # Value: 0
    )
    $stream.Write($settingsFrame, 0, $settingsFrame.Length)
    
    # Send HEADERS frame with HTTP request
    Write-Host "Sending HEADERS frame with HTTP request..."
    
    # Simple literal encoding for headers (not proper HPACK, but for testing)
    # This creates a simple GET request for /
    $headerPayload = @(
        # Literal Header Field — New Name — Literal Value
        # :method: GET
        0x00,              # Literal header, new name
        0x07,              # Name length: 7
        0x3A, 0x6D, 0x65, 0x74, 0x68, 0x6F, 0x64,  # ":method"
        0x03,              # Value length: 3  
        0x47, 0x45, 0x54,  # "GET"
        
        # :path: /
        0x00,              # Literal header, new name
        0x05,              # Name length: 5
        0x3A, 0x70, 0x61, 0x74, 0x68,  # ":path"
        0x01,              # Value length: 1
        0x2F,              # "/"
        
        # :authority: localhost:8081
        0x00,              # Literal header, new name
        0x0A,              # Name length: 10
        0x3A, 0x61, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x74, 0x79,  # ":authority"
        0x0E,              # Value length: 14
        0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x3A, 0x38, 0x30, 0x38, 0x31  # "localhost:8081"
    )
    
    $headersFrame = @(
        0x00, 0x00, ($headerPayload.Length),  # Length: payload length
        0x01,              # Type: HEADERS
        0x05,              # Flags: END_STREAM (0x01) + END_HEADERS (0x04) = 0x05
        0x00, 0x00, 0x00, 0x01   # Stream ID: 1
    ) + $headerPayload
    
    $stream.Write($headersFrame, 0, $headersFrame.Length)
    $stream.Flush()
    
    # Read server response
    Write-Host "Reading server response..."
    $buffer = New-Object byte[] 1024
    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
    
    if ($bytesRead -gt 0) {
        Write-Host "Server sent $bytesRead bytes:"
        
        # Parse HTTP/2 frames
        $offset = 0
        while ($offset -lt $bytesRead) {
            if ($offset + 9 -gt $bytesRead) {
                Write-Host "Incomplete frame at offset $offset"
                break
            }
            
            # Parse frame header
            $length = ($buffer[$offset] -shl 16) -bor ($buffer[$offset + 1] -shl 8) -bor $buffer[$offset + 2]
            $type = $buffer[$offset + 3]
            $flags = $buffer[$offset + 4]
            $streamId = (($buffer[$offset + 5] -band 0x7F) -shl 24) -bor ($buffer[$offset + 6] -shl 16) -bor ($buffer[$offset + 7] -shl 8) -bor $buffer[$offset + 8]
            
            $typeName = switch ($type) {
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
                default { "UNKNOWN($type)" }
            }
            
            Write-Host "Frame: Type=$typeName, Length=$length, Flags=0x$($flags.ToString('X2')), StreamId=$streamId"
            
            if ($type -eq 4) {  # SETTINGS frame
                if ($flags -band 0x01) {
                    Write-Host "  SETTINGS ACK frame"
                } else {
                    Write-Host "  SETTINGS frame with $($length / 6) settings"
                }
            } elseif ($type -eq 1) {  # HEADERS frame
                Write-Host "  HEADERS response frame"
            } elseif ($type -eq 0) {  # DATA frame
                Write-Host "  DATA response frame"
            }
            
            $offset += 9 + $length
        }
        
        Write-Host "✅ HTTP/2 request/response cycle successful!"
    } else {
        Write-Host "❌ No response from server"
    }
    
} catch {
    Write-Host "❌ Error: $($_.Exception.Message)"
} finally {
    if ($client) {
        $client.Close()
    }
}
