[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param()

Describe 'Service Lifecycle' {

    BeforeAll {
        $helperPath = (Split-Path -Parent -Path $PSCommandPath) -ireplace 'integration', 'shared'
        . "$helperPath/TestHelper.ps1"
        $isAgent = $false
        if ($IsMacOS) {
            $isAgent = $true
        }
        $Port = 8080
        $Uri = "http://localhost:$($Port)"
        $SleepTime = 15
        $HelloService_ps1 = Join-Path -Path (Join-Path -Path (Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'examples') -ChildPath 'HelloService') -ChildPath 'HelloService.ps1'
        # Ensure the port is free
        Wait-ForWebServer -Port $Port -Offline
    }
    it 'register' {
        $success = & $HelloService_ps1 -Register -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error registering service: $(Get-Error)"
            $success = & $HelloService_ps1 -Unregister -Force -Agent:$isAgent
            if (-not $success) {
                Write-Host "Error stopping service: $(Get-Error)"
            }
            else {
                $success = & $HelloService_ps1 -Register -Agent:$isAgent
            }
        }
        $success | Should -BeTrue
        Start-Sleep -Seconds $SleepTime
        if ($IsMacOS) {
            Wait-ForWebServer -Port $Port
            $status = & $HelloService_ps1 -Query -Agent:$isAgent
            $status.Status | Should -Be 'Running'
            $status.Pid | Should -BeGreaterThan 0


        }
        else {
            $status = & $HelloService_ps1 -Query -Agent:$isAgent
            $status.Status | Should -Be 'Stopped'
            $status.Pid | Should -Be 0
        }

        $status.Name | Should -Be 'Hello Service'

    }


    it 'start' -Skip:( $IsMacOS) {
        $success = & $HelloService_ps1 -Start -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Wait-ForWebServer -Port $Port
        $webRequest = Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue
        $status = & $HelloService_ps1 -Query -Agent:$isAgent
        $status.Status | Should -Be 'Running'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -BeGreaterThan 0
        $webRequest.Content | Should -Be 'Hello, Service!'
    }

    it  'pause' {
        $success = & $HelloService_ps1 -Suspend -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Wait-ForWebServer -Port $Port -Offline

        $status = & $HelloService_ps1 -Query -Agent:$isAgent
        $status.Status | Should -Be 'Suspended'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -BeGreaterThan 0
        { Invoke-WebRequest -Uri $Uri } | Should -Throw
    }

    it  'resume' {

        $success = & $HelloService_ps1 -resume -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error resuming service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Wait-ForWebServer -Port $Port
        $webRequest = Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue
        $status = & $HelloService_ps1 -Query -Agent:$isAgent
        $status.Status | Should -Be 'Running'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -BeGreaterThan 0
        $webRequest.Content | Should -Be 'Hello, Service!'
    }
    it 'stop' {

        $success = & $HelloService_ps1 -Stop -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Wait-ForWebServer -Port $Port -Offline

        $status = & $HelloService_ps1 -Query -Agent:$isAgent
        $status.Status | Should -Be 'Stopped'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -Be 0

        { Invoke-WebRequest -Uri $Uri } | Should -Throw
    }

    it 're-start' {

        $success = & $HelloService_ps1 -Start -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Wait-ForWebServer -Port $Port
        $webRequest = Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue
        $status = & $HelloService_ps1 -Query -Agent:$isAgent
        $status.Status | Should -Be 'Running'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -BeGreaterThan 0
        $webRequest.Content | Should -Be 'Hello, Service!'
    }

    it 'unregister' {
        $status = & $HelloService_ps1 -Query -Agent:$isAgent
        $status.Status | Should -Be 'Running'
        $status.Name | Should -Be 'Hello Service'
        if ($isAgent) {
            $status.Type | Should -Be 'Agent'
        }
        $success = & $HelloService_ps1 -Unregister -Force -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Wait-ForWebServer -Port $Port -Offline
        $status = & $HelloService_ps1 -Query -Agent:$isAgent
        $status | Should -BeNullOrEmpty
        { Invoke-WebRequest -Uri $Uri } | Should -Throw
    }

}