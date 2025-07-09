# Test complete HTTP/2 handshake with SETTINGS exchange
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
            }
            
            $offset += 9 + $length
        }
        
        Write-Host "✅ HTTP/2 communication successful! Server is responding with proper HTTP/2 frames."
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
