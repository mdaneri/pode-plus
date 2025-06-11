[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param()

Describe 'Timers' {

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

            Start-PodeServer -RootPath $using:PSScriptRoot -Quiet -ScriptBlock {
                Add-PodeEndpoint -Address localhost -Port $using:Port -Protocol Http

                New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging
                Add-PodeRoute -Method Get -Path '/close' -ScriptBlock {
                    Close-PodeServer
                }

                Set-PodeState -Name 'Test1' -Value 0
                Add-PodeTimer -Name 'Test1' -Interval 1 -ScriptBlock {
                    Set-PodeState -Name 'Test1' -Value 1337
                }

                Add-PodeRoute -Method Get -Path '/test1' -ScriptBlock {
                    Invoke-PodeTimer -Name 'Test1'
                    Write-PodeJsonResponse -Value @{ Result = (Get-PodeState -Name 'Test1') }
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


    It 'timer updates state value' {
        $result = Invoke-RestMethod -Uri "$($Endpoint)/test1" -Method Get
        $result.Result | Should -Be 1337
    }
}