[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
param()

Describe 'Session Requests' {

    BeforeAll {
        $helperPath = (Split-Path -Parent -Path $PSCommandPath) -ireplace 'integration', 'shared'
        . "$helperPath/TestHelper.ps1"

        $Port = 8080
        $Endpoint = "http://127.0.0.1:$($Port)"

         # Ensure the port is free
        Wait-ForWebServer -Port $Port -Offline

        # Start the Pode server in a job
        Start-Job -Name 'Pode' -ErrorAction Stop -ScriptBlock {
            Import-Module -Name "$($using:PSScriptRoot)\..\..\src\Pode.psm1"

            Start-PodeServer   -Daemon -ScriptBlock {
                Add-PodeEndpoint -Address localhost -Port $using:Port -Protocol Http
                Add-PodeRoute -Method Get -Path '/close' -ScriptBlock {
                    Close-PodeServer
                }

                Enable-PodeSessionMiddleware -Secret 'schwifty' -Duration 5 -Extend -UseHeaders

                New-PodeAuthScheme -Basic | Add-PodeAuth -Name 'Auth' -ScriptBlock {
                    param($username, $password)

                    if (($username -eq 'morty') -and ($password -eq 'pickle')) {
                        return @{ User = @{ ID = 'M0R7Y302' } }
                    }

                    return @{ Message = 'Invalid details supplied' }
                }

                Add-PodeRoute -Method Post -Path '/auth/basic' -Authentication Auth -ScriptBlock {
                    $WebEvent.Session.Data.Views++

                    Write-PodeJsonResponse -Value @{
                        Result   = 'OK'
                        Username = $WebEvent.Auth.User.ID
                        Views    = $WebEvent.Session.Data.Views
                    }
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


    It 'returns ok for valid creds' {
        $result = Invoke-WebRequest -Uri "$($Endpoint)/auth/basic" -Method Post -Headers @{ Authorization = 'Basic bW9ydHk6cGlja2xl' }
        $content = ($result.Content | ConvertFrom-Json)

        $content.Result | Should -Be 'OK'
        $content.Views | Should -Be 1
        $result.Headers['pode.sid'] | Should -Not -BeNullOrEmpty
    }

    It 'returns 401 for invalid creds' {
        { Invoke-RestMethod -Uri "$($Endpoint)/auth/basic" -Method Post -Headers @{ Authorization = 'Basic cmljazpwaWNrbGU=' } -ErrorAction Stop } | Should -Throw -ExpectedMessage '*401*'
    }

    It 'returns ok for session requests' {
        $result = Invoke-WebRequest -Uri "$($Endpoint)/auth/basic" -Method Post -Headers @{ Authorization = 'Basic bW9ydHk6cGlja2xl' }
        $content = ($result.Content | ConvertFrom-Json)

        $content.Result | Should -Be 'OK'
        $content.Views | Should -Be 1
        $result.Headers['pode.sid'] | Should -Not -BeNullOrEmpty

        $session = ($result.Headers['pode.sid'] | Select-Object -First 1)
        $result = Invoke-WebRequest -Uri "$($Endpoint)/auth/basic" -Method Post -Headers @{ 'pode.sid' = $session }
        $content = ($result.Content | ConvertFrom-Json)
        $content.Result | Should -Be 'OK'
        $content.Views | Should -Be 2

        $session = ($result.Headers['pode.sid'] | Select-Object -First 1)
        $result = Invoke-WebRequest -Uri "$($Endpoint)/auth/basic" -Method Post -Headers @{ 'pode.sid' = $session }
        $content = ($result.Content | ConvertFrom-Json)
        $content.Result | Should -Be 'OK'
        $content.Views | Should -Be 3
    }

    It 'returns 401 for invalid session' {
        { Invoke-RestMethod -Uri "$($Endpoint)/auth/basic" -Method Post -Headers @{ 'pode.sid' = 'some-fake-session' } -ErrorAction Stop } | Should -Throw -ExpectedMessage '*401*'
    }

    It 'returns 401 for session timeout' {
        $result = Invoke-WebRequest -Uri "$($Endpoint)/auth/basic" -Method Post -Headers @{ Authorization = 'Basic bW9ydHk6cGlja2xl' }
        $content = ($result.Content | ConvertFrom-Json)

        $content.Result | Should -Be 'OK'
        $content.Views | Should -Be 1
        $result.Headers['pode.sid'] | Should -Not -BeNullOrEmpty

        $session = ($result.Headers['pode.sid'] | Select-Object -First 1)
        $result = Invoke-WebRequest -Uri "$($Endpoint)/auth/basic" -Method Post -Headers @{ 'pode.sid' = $session }
        $content = ($result.Content | ConvertFrom-Json)
        $content.Result | Should -Be 'OK'
        $content.Views | Should -Be 2

        Start-Sleep -Seconds 6

        $session = ($result.Headers['pode.sid'] | Select-Object -First 1)
        { Invoke-RestMethod -Uri "$($Endpoint)/auth/basic" -Method Post -Headers @{ 'pode.sid' = $session } -ErrorAction Stop } | Should -Throw -ExpectedMessage '*401*'
    }
}