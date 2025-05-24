[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param()

Describe 'Service Lifecycle' {

    BeforeAll {
        $isAgent = $false
        if ($IsMacOS) {
            $isAgent = $true
        }

        $Uri = 'http://localhost:8080'
        $SleepTime = 5

    }
    it 'register' {
        $success = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Register -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Start-Sleep -Seconds $SleepTime
        $status = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Query -Agent:$isAgent
        if ($IsMacOS) {
            Start-Sleep -Seconds 10
            $status = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Query -Agent:$isAgent
            $status.Status | Should -Be 'Running'
            $status.Pid | Should -BeGreaterThan 0
        }
        else {
            $status.Status | Should -Be 'Stopped'
            $status.Pid | Should -Be 0
        }

        $status.Name | Should -Be 'Hello Service'

    }


    it 'start' -Skip:( $IsMacOS) {
        $success = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Start -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        $webRequest = Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue
        $status = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Query -Agent:$isAgent
        $status.Status | Should -Be 'Running'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -BeGreaterThan 0
        $webRequest.Content | Should -Be 'Hello, Service!'
    }

    it  'pause' {
        $success = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Suspend -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Start-Sleep -Seconds $SleepTime

        $status = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Query -Agent:$isAgent
        $status.Status | Should -Be 'Suspended'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -BeGreaterThan 0
        { Invoke-WebRequest -Uri $Uri } | Should -Throw
    }

    it  'resume' {
        $success = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -resume -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Start-Sleep -Seconds $SleepTime
        $webRequest = Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue
        $status = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Query -Agent:$isAgent
        $status.Status | Should -Be 'Running'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -BeGreaterThan 0
        $webRequest.Content | Should -Be 'Hello, Service!'
    }
    it 'stop' {
        $success = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Stop -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Start-Sleep -Seconds $SleepTime
        $status = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Query -Agent:$isAgent
        $status.Status | Should -Be 'Stopped'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -Be 0

        { Invoke-WebRequest -Uri $Uri } | Should -Throw
    }

    it 're-start' {
        $success = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Start -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Start-Sleep -Seconds $SleepTime
        $webRequest = Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue
        $status = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Query -Agent:$isAgent
        $status.Status | Should -Be 'Running'
        $status.Name | Should -Be 'Hello Service'
        $status.Pid | Should -BeGreaterThan 0
        $webRequest.Content | Should -Be 'Hello, Service!'
    }



    it 'unregister' {
        $status = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Query -Agent:$isAgent
        $status.Status | Should -Be 'Running'
        $status.Name | Should -Be 'Hello Service'
        if ($isAgent) {
            $status.Type | Should -Be 'Agent'
        }
        $success = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Unregister -Force -Agent:$isAgent
        if (-not $success) {
            Write-Host "Error stopping service: $(Get-Error)"
        }
        $success | Should -BeTrue
        Start-Sleep -Seconds $SleepTime
        $status = & "$($PSScriptRoot)\..\..\examples\HelloService\HelloService.ps1" -Query -Agent:$isAgent
        $status | Should -BeNullOrEmpty
        { Invoke-WebRequest -Uri $Uri } | Should -Throw
    }

}