#!/usr/bin/env pwsh

# Test HTTP/2 with extended waiting
param(
    [string]$Server = "localhost",
    [int]$Port = 8081
)

Write-Host "Testing HTTP/2 with extended waiting..."

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
        0x00, 0x00, 0x0C, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00
    )
    $stream.Write($settingsFrame, 0, $settingsFrame.Length)
    $stream.Flush()
    
    # Read initial SETTINGS response
    Write-Host "Reading initial SETTINGS response..."
    Start-Sleep -Milliseconds 500
    $responseBuffer = New-Object byte[] 4096
    $totalBytesRead = 0
    
    if ($stream.DataAvailable) {
        $bytesRead = $stream.Read($responseBuffer, 0, $responseBuffer.Length)
        $totalBytesRead = $bytesRead
        Write-Host "Read $bytesRead bytes of SETTINGS response"
    }
    
    # Send HEADERS frame with GET request
    Write-Host "Sending HEADERS frame with GET request..."
    $headers = @(0x82, 0x84, 0x41, 0x0E, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x3A, 0x38, 0x30, 0x38, 0x31, 0x86)
    $headersFrame = @(
        0x00, 0x00, ($headers.Length -band 0xFF), 0x01, 0x05, 0x00, 0x00, 0x00, 0x01
    ) + $headers
    
    $stream.Write($headersFrame, 0, $headersFrame.Length)
    $stream.Flush()
    
    # Wait for HTTP response
    Write-Host "Waiting for HTTP response..."
    $maxWait = 5000  # 5 seconds
    $waited = 0
    
    while ($waited -lt $maxWait) {
        Start-Sleep -Milliseconds 100
        $waited += 100
        
        if ($stream.DataAvailable) {
            $bytesRead = $stream.Read($responseBuffer, $totalBytesRead, $responseBuffer.Length - $totalBytesRead)
            if ($bytesRead -gt 0) {
                Write-Host "Read additional $bytesRead bytes (total: $($totalBytesRead + $bytesRead))"
                
                # Show new bytes
                Write-Host "New bytes:"
                for ($i = $totalBytesRead; $i -lt $totalBytesRead + $bytesRead; $i += 16) {
                    $line = ""
                    for ($j = 0; $j -lt 16 -and ($i + $j) -lt $totalBytesRead + $bytesRead; $j++) {
                        $line += "{0:X2} " -f $responseBuffer[$i + $j]
                    }
                    Write-Host "  $("{0:X4}" -f $i): $line"
                }
                
                $totalBytesRead += $bytesRead
                
                # Try to parse new frames
                $offset = 54  # Skip the SETTINGS frames we already saw
                while ($offset + 9 -le $totalBytesRead) {
                    # Parse frame header
                    $frameLength = ($responseBuffer[$offset] -shl 16) -bor ($responseBuffer[$offset + 1] -shl 8) -bor $responseBuffer[$offset + 2]
                    $frameType = $responseBuffer[$offset + 3]
                    $frameFlags = $responseBuffer[$offset + 4]
                    $streamId = (($responseBuffer[$offset + 5] -band 0x7F) -shl 24) -bor ($responseBuffer[$offset + 6] -shl 16) -bor ($responseBuffer[$offset + 7] -shl 8) -bor $responseBuffer[$offset + 8]
                    
                    Write-Host "Frame at offset ${offset}:"
                    Write-Host "  Length: $frameLength"
                    Write-Host "  Type: $frameType"
                    Write-Host "  Flags: 0x$('{0:X2}' -f $frameFlags)"
                    Write-Host "  StreamId: $streamId"
                    
                    if ($offset + 9 + $frameLength -le $totalBytesRead) {
                        if ($frameLength -gt 0) {
                            $payload = $responseBuffer[($offset + 9)..($offset + 8 + $frameLength)]
                            Write-Host "  Payload: $([System.BitConverter]::ToString($payload))"
                            
                            # If it's a DATA frame, try to decode as text
                            if ($frameType -eq 0 -and $frameLength -gt 0) {
                                try {
                                    $text = [System.Text.Encoding]::UTF8.GetString($payload)
                                    Write-Host "  Text: $text"
                                } catch {
                                    Write-Host "  (Not valid UTF-8)"
                                }
                            }
                        }
                        $offset += 9 + $frameLength
                    } else {
                        Write-Host "  Incomplete frame"
                        break
                    }
                }
                
                # Check if we got END_STREAM
                if ($frameType -eq 0 -and ($frameFlags -band 0x01)) {
                    Write-Host "✅ Received END_STREAM"
                    break
                }
            }
        }
    }
    
    Write-Host "Final total bytes read: $totalBytesRead"
    
} catch {
    Write-Host "❌ Error: $($_.Exception.Message)"
} finally {
    if ($stream) { $stream.Close() }
    if ($client) { $client.Close() }
}
