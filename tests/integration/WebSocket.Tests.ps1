[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param()

Describe 'WebSocket' {

    BeforeAll {
        $helperPath = (Split-Path -Parent -Path $PSCommandPath) -ireplace 'integration', 'shared'
        . "$helperPath/TestHelper.ps1"

        $Port = 8080
        $Endpoint = "http://localhost:$($Port)"

        # Ensure the port is free
        Wait-ForWebServer -Port $Port -Offline
        
        # Start the Pode server in a job
        Start-Job -Name 'Pode' -ErrorAction Stop -ScriptBlock {
            Import-Module -Name "$($using:PSScriptRoot)\..\..\src\Pode.psm1"

            Start-PodeServer -RootPath $using:PSScriptRoot -Quiet -ScriptBlock {
                # listen
                Add-PodeEndpoint -Address localhost -Port $using:Port -Protocol Http
                Add-PodeEndpoint -Address localhost -Port $using:Port -Protocol Ws

                New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging
                Add-PodeRoute -Method Get -Path '/close' -ScriptBlock {
                    Close-PodeServer
                }

                # set view engine to pode renderer
                Set-PodeViewEngine -Type Html

                # GET request for web page
                Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
                    Write-PodeViewResponse -Path 'websockets'
                }

                # SIGNAL route, to return current date
                Add-PodeSignalRoute -Path '/' -ScriptBlock {
                    $msg = $SignalEvent.Data.Message

                    if ($msg -ieq '[date]') {
                        $msg = [datetime]::Now.ToString()
                    }

                    Send-PodeSignal -Value @{ message = $msg }
                }
            }
        }

        Wait-ForWebServer -Port $Port
    }

    AfterAll {
        Receive-Job -Name 'Pode' | Out-Default
        Invoke-RestMethod -Uri "$($Endpoint)/close" -Method Get | Out-Null
        Get-Job -Name 'Pode' | Remove-Job -Force
    }

    It 'sends and receives a WebSocket signal with current date' {
        # Create a new WebSocket client
        $client = [System.Net.WebSockets.ClientWebSocket]::new()
        $wsUri = "ws://localhost:$Port/"

        # Connect to the WebSocket endpoint
        $client.ConnectAsync([uri]$wsUri, [Threading.CancellationToken]::None).Wait()
        $client.State | Should -Be 'Open'

        # Prepare a JSON message that the server will interpret to return the current date/time
        $jsonMessage = '{"message": "[date]"}'
        $sendBuffer = [System.Text.Encoding]::UTF8.GetBytes($jsonMessage)
        $sendSegment = [System.ArraySegment[byte]]::new($sendBuffer)

        # Send the JSON message
        $client.SendAsync($sendSegment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).Wait()

        # Wait briefly to allow the response to be processed
        Start-Sleep -Seconds 1

        # Prepare a buffer to receive the response
        $receiveBuffer = [byte[]]::new(1024)
        $receiveSegment = [System.ArraySegment[byte]]::new($receiveBuffer, 0, $receiveBuffer.Length)

        # Receive a message from the server
        $receiveResult = $client.ReceiveAsync($receiveSegment, [Threading.CancellationToken]::None).Result
        $receivedText = [System.Text.Encoding]::UTF8.GetString($receiveBuffer, 0, $receiveResult.Count)

        # Convert the JSON response to a PowerShell object
        $response = $receivedText | ConvertFrom-Json

        # Cleanly close the WebSocket connection
        $client.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'Closing', [Threading.CancellationToken]::None).Wait()

        # Verify that the returned message appears to be a date (for example, by matching a date pattern).
        # Adjust the regex as needed based on your date format.
        $response.message | Should -Match '\d{1,2}\/\d{1,2}\/\d{4}'
    }

    It 'handles sending and receiving Max default size (16KB for 5.1 and 32KB for 7.0 or greater)' {
        $client = [System.Net.WebSockets.ClientWebSocket]::new()
        $wsUri = "ws://localhost:$Port/"

        $client.ConnectAsync([uri]$wsUri, [Threading.CancellationToken]::None).Wait()
        $client.State | Should -Be 'Open'

        # Generate a large message (~3MB)
        $largeMessage = if ($PSVersionTable.PSEdition -eq 'Desktop') { ('a' * ((16KB) - 32)) } else { ('a' * ((32KB) - 16)) }
        $jsonMessage = ('{"message": "' + $largeMessage + '"}')
        $sendBuffer = [System.Text.Encoding]::UTF8.GetBytes($jsonMessage)
        $sendSegment = [System.ArraySegment[byte]]::new($sendBuffer)

        $client.SendAsync($sendSegment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).Wait()

        Start-Sleep -Seconds 2

        $receiveBuffer = [byte[]]::new(8192)
        $memoryStream = [System.IO.MemoryStream]::new()

        do {
            $receiveSegment = [System.ArraySegment[byte]]::new($receiveBuffer, 0, $receiveBuffer.Length)
            $receiveResult = $client.ReceiveAsync($receiveSegment, [Threading.CancellationToken]::None).Result

            # Write the received bytes into the memory stream
            $memoryStream.Write($receiveBuffer, 0, $receiveResult.Count)

        } while (!$receiveResult.EndOfMessage)

        # Convert the full message to string
        $memoryStream.Seek(0, 'Begin') | Out-Null
        $reader = [System.IO.StreamReader]::new($memoryStream, [System.Text.Encoding]::UTF8)
        $receivedText = $reader.ReadToEnd()

        # Optionally convert from JSON if it's a JSON payload
        $response = $receivedText | ConvertFrom-Json

        $client.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'Closing', [Threading.CancellationToken]::None).Wait()

        $response.message.Length | Should -Be $largeMessage.Length
        $response.message | Should -BeExactly $largeMessage
    }

    It 'handles sending and receiving large messages (>3MB)' {
        $client = [System.Net.WebSockets.ClientWebSocket]::new()
        $wsUri = "ws://localhost:$Port/"

        $client.ConnectAsync([uri]$wsUri, [Threading.CancellationToken]::None).Wait()
        $client.State | Should -Be 'Open'

        # Generate a large message (~3MB)
        $largeMessage = ('a' * ((3MB) - 16))
        $jsonMessage = ('{"message": "' + $largeMessage + '"}')
        $sendBuffer = [System.Text.Encoding]::UTF8.GetBytes($jsonMessage)
        $sendSegment = [System.ArraySegment[byte]]::new($sendBuffer)

        $client.SendAsync($sendSegment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).Wait()

        Start-Sleep -Seconds 2

        $receiveBuffer = [byte[]]::new(8192)
        $memoryStream = [System.IO.MemoryStream]::new()

        do {
            $receiveSegment = [System.ArraySegment[byte]]::new($receiveBuffer, 0, $receiveBuffer.Length)
            $receiveResult = $client.ReceiveAsync($receiveSegment, [Threading.CancellationToken]::None).Result

            # Write the received bytes into the memory stream
            $memoryStream.Write($receiveBuffer, 0, $receiveResult.Count)

        } while (!$receiveResult.EndOfMessage)

        # Convert the full message to string
        $memoryStream.Seek(0, 'Begin') | Out-Null
        $reader = [System.IO.StreamReader]::new($memoryStream, [System.Text.Encoding]::UTF8)
        $receivedText = $reader.ReadToEnd()

        # Optionally convert from JSON if it's a JSON payload
        $response = $receivedText | ConvertFrom-Json

        $client.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'Closing', [Threading.CancellationToken]::None).Wait()

        $response.message.Length | Should -Be $largeMessage.Length
        $response.message | Should -BeExactly $largeMessage
    }
}