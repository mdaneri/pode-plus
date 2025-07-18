[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
param()

Describe 'OpenAPI integration tests' {

    BeforeAll {

        $helperPath = (Split-Path -Parent -Path $PSCommandPath) -ireplace 'integration', 'shared'
        . "$helperPath/TestHelper.ps1"

        $PortV3 = 8080
        $PortV3_1 = 8081

        # Ensure the port is free
        Wait-ForWebServer -Port $PortV3 -Offline
        # Ensure the port is free
        Wait-ForWebServer -Port $PortV3_1 -Offline
        
        $scriptPath = "$($PSScriptRoot)\..\..\examples\OpenApi-TuttiFrutti.ps1"
        Start-Process (Get-Process -Id $PID).Path -ArgumentList "-NoProfile -File `"$scriptPath`" -PortV3 $PortV3 -PortV3_1 $PortV3_1 -Daemon -IgnoreServerConfig" -NoNewWindow

        Wait-ForWebServer -Port $PortV3
        Wait-ForWebServer -Port $PortV3_1
    }

    AfterAll {
        Start-Sleep -Seconds 5
        Invoke-RestMethod -Uri "http://localhost:$($PortV3)/close" -Method Post | Out-Null

    }

    Describe 'OpenAPI' {
        it 'Open API v3.0.3' {

            $fileContent = Get-Content -Path "$PSScriptRoot/specs/OpenApi-TuttiFrutti_3.0.3.json"

            $webResponse = Invoke-WebRequest -Uri "http://localhost:$($PortV3)/docs/openapi/v3.0" -Method Get
            $json = $webResponse.Content
            if (   $PSVersionTable.PSEdition -eq 'Desktop') {
                $expected = $fileContent | ConvertFrom-Json | Convert-PsCustomObjectToOrderedHashtable
                $response = $json | ConvertFrom-Json | Convert-PsCustomObjectToOrderedHashtable
            }
            else {
                $expected = $fileContent | ConvertFrom-Json -AsHashtable
                $response = $json | ConvertFrom-Json -AsHashtable
            }

            Compare-Hashtable $response $expected | Should -BeTrue

        }

        it 'Open API v3.1.0' {
            $fileContent = Get-Content -Path "$PSScriptRoot/specs/OpenApi-TuttiFrutti_3.1.0.json"

            $webResponse = Invoke-WebRequest -Uri "http://localhost:$($PortV3_1)/docs/openapi/v3.1" -Method Get
            $json = $webResponse.Content
            if (  $PSVersionTable.PSEdition -eq 'Desktop') {
                $expected = $fileContent | ConvertFrom-Json | Convert-PsCustomObjectToOrderedHashtable
                $response = $json | ConvertFrom-Json | Convert-PsCustomObjectToOrderedHashtable
            }
            else {
                $expected = $fileContent | ConvertFrom-Json -AsHashtable
                $response = $json | ConvertFrom-Json -AsHashtable
            }
            Compare-Hashtable $response $expected | Should -BeTrue
        }
    }

}