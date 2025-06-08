[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
param()


Describe 'ASYNC REST API Requests' {

    BeforeAll {

        $helperPath = (Split-Path -Parent -Path $PSCommandPath) -ireplace 'integration', 'shared'
        . "$helperPath/TestHelper.ps1"

        $mindyCommonHeaders = @{
            'accept'        = 'application/json'
            'X-API-KEY'     = 'test2-api-key'
            'Authorization' = 'Basic bWluZHk6cGlja2xl'
        }

        $mortyCommonHeaders = @{
            'accept'        = 'application/json'
            'X-API-KEY'     = 'test-api-key'
            'Authorization' = 'Basic bW9ydHk6cGlja2xl'
        }
        $Port = 8080
        $Endpoint = "http://127.0.0.1:$($Port)"
        $scriptPath = "$($PSScriptRoot)\..\..\examples\Web-AsyncRoute.ps1"

        Start-Process  (Get-Process -Id $PID).Path -ArgumentList "-NoProfile -File `"$scriptPath`" -Port $Port  -Daemon"  -NoNewWindow
        Wait-ForWebServer -Port $Port
    }

    AfterAll {
        Start-Sleep -Seconds 5
        Invoke-RestMethod -Uri "$($Endpoint)/close" -Method Post | Out-Null
        Start-Sleep -Seconds 10
    }

    Describe 'Hello Server' {
        it 'Hello Server' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/hello" -Method Get
            $response.message | Should -Be 'Hello!'
        }
    }


    Describe 'Create Async Route Task on behalf of Mindy' {

        It 'Create Async Route Task /auth/asyncUsingNotCancellable' {

            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncUsingNotCancellable" -Method Put -Headers $mindyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'MINDY021'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncUsingNotCancellable'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $false
        }

        It 'Create Async Route Task /auth/asyncUsingCancellable' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncUsingCancellable" -Method Put -Headers $mindyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'MINDY021'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncUsingCancellable'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $true
        }

        It 'Create Async Route Task /auth/asyncUsingCallback with JSON body and capture callback' {
            $callbackPort = ([int]$Port) + 1
            $callbackUrl = "http://localhost:$callbackPort/receive/callback"

            # Prepare body with callback URL
            $body = @{ callbackUrl = $callbackUrl } | ConvertTo-Json

            # Prepare headers
            $headersWithContentType = $mindyCommonHeaders.Clone()
            $headersWithContentType['Content-Type'] = 'application/json'

            # Start temporary HTTP listener to capture callback
            $listener = [System.Net.HttpListener]::new()
            $listener.Prefixes.Add("$callbackUrl/")
            $listener.Start()

            try {
                # Trigger the async route
                $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncUsingCallback" -Method Put -Headers $headersWithContentType -Body $body

                # Assertions for the route response
                $response | Should -Not -BeNullOrEmpty
                $response.User | Should -Be 'MINDY021'
                $response.AsyncRouteId | Should -Be '[Put]/auth/asyncUsingCallback'
                $response.State | Should -BeIn @('NotStarted', 'Running')
                $response.Cancellable | Should -Be $true
                try {
                    $callbackContext = $listener.GetContext()    # returns as soon as callback arrives
                    # Validate callback received
                    $callbackContext | Should -Not -BeNullOrEmpty

                    $callbackContext.Request.HttpMethod | Should -Be 'POST'
                    # Read callback body
                    $callbackRequest = $callbackContext.Request
                    $callbackBody = [IO.StreamReader]::new($callbackRequest.InputStream).ReadToEnd()
                    $callbackBody | Should -Not -BeNullOrEmpty
                }
                finally {
                    # Respond with 200 OK
                    $callbackContext.Response.StatusCode = 200
                    $callbackContext.Response.Close()
                }
                # Assert callback body (you can adjust this depending on your callback content)
                $callbackBody | Should -Not -BeNullOrEmpty
                $callbackBody | Should  -be '{"Url":"http://localhost:8080/auth/asyncUsingCallback","Method":"put","EventName":"_auth_asyncUsingCallback_Callback","State":"Completed","Result":{"InnerValue":"coming from using"}}'
            }
            finally {

                # Ensure listener is stopped
                $listener.Stop()
                $listener.Close()
            }
        }

        It 'Create Async Route Task /auth/asyncStateNoColumn' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncStateNoColumn" -Method Put -Headers $mindyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'MINDY021'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncStateNoColumn'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $true
        }

        It 'Create Async Route Task /auth/asyncState' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncState" -Method Put -Headers $mindyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'MINDY021'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncState'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $true
        }

        It 'Create Async Route Task /auth/asyncParam' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncParam" -Method Put -Headers $mindyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'MINDY021'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncParam'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $true
        }
    }

    Describe 'Create Async Route Task on behalf of Morty' {
        It 'Create Async Route Task /auth/asyncUsingNotCancellable' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncUsingNotCancellable" -Method Put -Headers $mortyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'M0R7Y302'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncUsingNotCancellable'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $false
        }

        It 'Create Async Route Task /auth/asyncUsingCancellable' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncUsingCancellable" -Method Put -Headers $mortyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'M0R7Y302'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncUsingCancellable'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $true
        }

        It 'Create Async Route Task /auth/asyncUsingCallback with JSON body and capture callback' {
            $callbackPort = ([int]$Port) + 1
            $callbackUrl = "http://localhost:$callbackPort/receive/callback"

            # Prepare body with callback URL
            $body = @{ callbackUrl = $callbackUrl } | ConvertTo-Json

            # Prepare headers
            $headersWithContentType = $mortyCommonHeaders.Clone()
            $headersWithContentType['Content-Type'] = 'application/json'

            # Start temporary HTTP listener to capture callback
            $listener = [System.Net.HttpListener]::new()
            $listener.Prefixes.Add("$callbackUrl/")
            $listener.Start()

            try {
                # Trigger the async route
                $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncUsingCallback" -Method Put -Headers $headersWithContentType -Body $body

                # Assertions for the route response
                $response | Should -Not -BeNullOrEmpty
                $response.User | Should -Be 'M0R7Y302'
                $response.AsyncRouteId | Should -Be '[Put]/auth/asyncUsingCallback'
                $response.State | Should -BeIn @('NotStarted', 'Running')
                $response.Cancellable | Should -Be $true
                try {
                    $callbackContext = $listener.GetContext()    # returns as soon as callback arrives
                    # Validate callback received
                    $callbackContext | Should -Not -BeNullOrEmpty

                    $callbackContext.Request.HttpMethod | Should -Be 'POST'
                    # Read callback body
                    $callbackRequest = $callbackContext.Request
                    $callbackBody = [IO.StreamReader]::new($callbackRequest.InputStream).ReadToEnd()
                    $callbackBody | Should -Not -BeNullOrEmpty
                }
                finally {
                    # Respond with 200 OK
                    $callbackContext.Response.StatusCode = 200
                    $callbackContext.Response.Close()
                }
                # Assert callback body (you can adjust this depending on your callback content)
                $callbackBody | Should -Not -BeNullOrEmpty
                $callbackBody | Should  -be '{"Url":"http://localhost:8080/auth/asyncUsingCallback","Method":"put","EventName":"_auth_asyncUsingCallback_Callback","State":"Completed","Result":{"InnerValue":"coming from using"}}'
            }
            finally {
                # Ensure listener is stopped
                $listener.Stop()
                $listener.Close()
            }
        }

        It 'Throws exception - Create Async Route Task /auth/asyncStateNoColumn' {
            { Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncStateNoColumn" -Method Put -Headers $mortyCommonHeaders } | Should -Throw
        }

        It 'Create Async Route Task /auth/asyncState' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncState" -Method Put -Headers $mortyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'M0R7Y302'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncState'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $true
        }

        It 'Create Async Route Task /auth/asyncParam' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncParam" -Method Put -Headers $mortyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'M0R7Y302'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncParam'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $true
        }

        It 'Create Async Route Task /asyncWaitForeverTimeout' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncInfiniteLoopTimeout" -Method Put -Headers $mortyCommonHeaders

            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'M0R7Y302'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncInfiniteLoopTimeout'
            $response.State | Should -BeIn @('NotStarted', 'Running')
            $response.Cancellable | Should -Be $false
        }
    }

    Describe -Name 'Get Async Route Task' {
        BeforeAll {
            $responseCreateAsync = Invoke-RestMethod -Uri "http://localhost:$($Port)/auth/asyncInfiniteLoop" -Method Put -Headers $mindyCommonHeaders
        }
        it 'Throws exception - Get Async Route Task as Morty' {
            { Invoke-RestMethod -Uri "http://localhost:$($Port)/task/$($responseCreateAsync.ID)" -Method Get -Headers $mortyCommonHeaders } |
                Should -Throw #-ExceptionType ([Microsoft.PowerShell.Commands.HttpResponseException])
        }
        it 'Throws exception - Terminate Async Route Task as Morty' {
            { Invoke-RestMethod -Uri "http://localhost:$($Port)/task?id=$($responseCreateAsync.ID)" -Method Delete -Headers $mortyCommonHeaders } |
                Should -Throw  #-Exception Type ([Microsoft.PowerShell.Commands.HttpResponseException])
        }

        it 'Get Async Route Task as Mindy' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/task/$($responseCreateAsync.ID)" -Method Get -Headers $mindyCommonHeaders
            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'MINDY021'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncInfiniteLoop'
            $response.State | Should -BeIn 'Running'
            $response.Cancellable | Should -Be $true
        }

        it 'Terminate Async Route Task as Mindy' {
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/task?id=$($responseCreateAsync.ID)" -Method Delete -Headers $mindyCommonHeaders
            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.User | Should -Be 'MINDY021'
            $response.AsyncRouteId | Should -Be '[Put]/auth/asyncInfiniteLoop'
            $response.State | Should -BeIn 'Aborted'
            $response.Error | Should -BeIn 'Aborted by the user'
            $response.Cancellable | Should -Be $true
        }
    }

    Describe -Name 'Query Async Route Task' {
        it 'Get Query Async Route Task as Mindy' {
            $body = @{} | ConvertTo-Json
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/tasks" -Method Post -Body $body -Headers $mindyCommonHeaders
            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.Count | Should -Be 7
            $response.state.where({ $_ -eq 'Aborted' }).count | Should -Be 1
        }

        it 'Get Query Async Route Task as Morty' {
            $body = @{} | ConvertTo-Json
            $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/tasks" -Method Post -Body $body -Headers $mortyCommonHeaders
            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.Count | Should -Be 6
            $response.state.where({ $_ -eq 'Aborted' }).count | Should -Be 0
        }
    }

    Describe -Name 'Waiting for results ' {
        it 'Wendy results' {
            $counter = 0
            do {
                $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/tasks" -Method Post -Body '{}' -Headers $mindyCommonHeaders
                Start-Sleep 2

            } until (($response.state.where({ $_ -eq 'Running' -or $_ -eq 'NotStarted' }).count -eq 0) -or (++$counter -gt 60))
            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $counter | Should -BeLessOrEqual 60
            $response.Count | Should -Be 7
            $response.state.where({ $_ -eq 'Aborted' }).count | Should -Be 1
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncUsingCancellable' }).Result.InnerValue | Should -Be 'coming from using'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncUsingCallback' }).Result.InnerValue | Should -Be 'coming from using'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncUsingNotCancellable' }).Result.InnerValue | Should -Be 'coming from using'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncInfiniteLoop' }).State | Should -Be 'Aborted'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncParam' }).Result.InnerValue | Should -Be 'coming as argument'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncStateNoColumn' }).Result.InnerValue | Should -Be 'coming from a PodeState'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncState' }).Result.InnerValue | Should -Be 'coming from a PodeState'
        }
        it 'Morty results' {
            $counter = 0
            do {
                $body = @{'AsyncRouteId' = @{
                        'value' = '[Put]/auth/asyncInfiniteLoopTimeout'
                        'op'    = 'NE'
                    }
                } | ConvertTo-Json
                $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/tasks" -Method Post -Body $body -Headers $mortyCommonHeaders
                Start-Sleep 2
            } until (($response.state.where({ $_ -eq 'Running' -or $_ -eq 'NotStarted' }).count -eq 0) -or (++$counter -gt 60))
            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.Count | Should -Be 5
            $response.state.where({ $_ -eq 'Aborted' }).count | Should -Be 0
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncUsingCancellable' }).Result.InnerValue | Should -Be 'coming from using'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncUsingCallback' }).Result.InnerValue | Should -Be 'coming from using'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncUsingNotCancellable' }).Result.InnerValue | Should -Be 'coming from using'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncParam' }).Result.InnerValue | Should -Be 'coming as argument'
            $response.where({ $_.AsyncRouteId -eq '[Put]/auth/asyncState' }).Result.InnerValue | Should -Be 'coming from a PodeState'
        }

        it 'Timeout' {
            do {
                $body = @{'AsyncRouteId' = @{
                        'value' = '[Put]/auth/asyncInfiniteLoopTimeout'
                        'op'    = 'EQ'
                    }
                } | ConvertTo-Json
                $response = Invoke-RestMethod -Uri "http://localhost:$($Port)/tasks" -Method Post -Body $body -Headers $mortyCommonHeaders
            } until ($response.state.where({ $_ -eq 'Aborted' }).count -eq 1)
            # Assertions to validate the response
            $response | Should -Not -BeNullOrEmpty
            $response.Count | Should -Be 1
            $response.state.where({ $_ -eq 'Aborted' }).count | Should -Be 1
        }

    }

    Describe 'Pode SSE endpoint' {
        It 'emits the expected sequence of events' {
            $events = Get-SseEvent -BaseUrl "http://localhost:$($Port)" -TimeoutSeconds 10

            # Quick sanity checks – amend / add assertions as needed
            $events.Where{ $_.event -eq 'pode.open' }.Count |
                Should -Be 1

            #    $events.Where{ $_.event -eq 'pode.progress' }.Count |
            #      Should -BeGreaterOrEqual 1

            $events[0].event |
                Should -Be 'pode.open'

            $events[-1].event |
                Should -BeIn @('pode.close', 'pode.taskCompleted')
        }
    }

}