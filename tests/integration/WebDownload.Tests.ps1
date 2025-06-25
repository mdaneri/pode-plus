# Download.Tests.ps1  – Pester 5.x
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param()


Describe 'Download endpoints' {


    # ----------  2.  Environment set-up  ----------
    BeforeAll {
        $helperPath = (Split-Path -Parent -Path $PSCommandPath) -ireplace 'integration', 'shared'
        . "$helperPath/TestHelper.ps1"

        $Port = 8080
        $Endpoint = "http://127.0.0.1:$Port"


        Wait-ForWebServer -Port $Port -Offline

        $TestFolder = Join-Path -Path ([System.IO.Path]::GetTempPath()) 'pode-test'
        $DownloadFolder = Join-Path -Path ([System.IO.Path]::GetTempPath()) 'pode-test-downloads'
        # fresh test area
        if (Test-Path $TestFolder) { Remove-Item $TestFolder -Recurse -Force }
        New-Item $TestFolder -ItemType Directory | Out-Null

        if (Test-Path $DownloadFolder) { Remove-Item $DownloadFolder -Recurse -Force }
        New-Item $DownloadFolder -ItemType Directory | Out-Null
        # start Pode in a job
        Start-Job -Name Pode -ScriptBlock {
            Import-Module "$($using:PSScriptRoot)\..\..\src\Pode.psm1"

            Start-PodeServer -RootPath $using:PSScriptRoot -Quiet -ScriptBlock {
                Add-PodeEndpoint -Address localhost -Port $using:Port -Protocol Http -DualMode
                Add-PodeRoute    -Method Get -Path '/close' -ScriptBlock { Close-PodeServer }

                Add-PodeStaticRoute -Path '/standard'  -Source $using:TestFolder -FileBrowser

                Add-PodeStaticRoute -Path '/compress'  -Source $using:TestFolder  -FileBrowser -PassThru |
                    Add-PodeRouteCompression -Enable -Encoding gzip

                Add-PodeStaticRoute -Path '/cache'  -Source $using:TestFolder  -FileBrowser -PassThru |
                    Add-PodeRouteCache -Enable -MaxAge 3600 -Visibility public -ETagMode mtime -Immutable -PassThru |
                    Add-PodeRouteCompression -Enable -Encoding gzip

            }
        }

        Wait-ForWebServer -Port $Port           # server is now up
    }

    AfterAll {
        Receive-Job -Name 'Pode' | Out-Default
        Invoke-RestMethod -Uri "$($Endpoint1)/close" -Method Get | Out-Null
        Get-Job -Name 'Pode' | Remove-Job -Force
        if ((Test-Path $TestFolder)) {
            Remove-Item $TestFolder -Recurse -Force
        }
        if ((Test-Path $DownloadFolder)) {
            Remove-Item $DownloadFolder -Recurse -Force
        }
    }

    # ----------  3.  DATA-DRIVEN TESTS  ----------
    Context 'Pode download  standard, ranged, compressed' {
        BeforeDiscovery {
            $Sizes = @(
                @{ Label = '1MB'; Bytes = 1MB; Tag = 'Quick' },
                @{ Label = '1GB'; Bytes = 1GB; Tag = 'Medium' },
                @{ Label = '3GB'; Bytes = 3GB; Tag = 'Large' },
                @{ Label = '8GB'; Bytes = 8GB; Tag = 'Huge' },
                @{ Label = '13GB'; Bytes = 13GB; Tag = 'Enormous' }
            )
            $Kinds = @('Text', 'Binary')

            $TestCases = foreach ($size in $Sizes) {
                foreach ($kind in $Kinds) {
                    @{
                        Kind  = $kind
                        Label = $size.Label
                        Bytes = $size.Bytes
                        Tag   = $size.Tag
                        Ext   = $(if ($kind -eq 'Text') { '.txt' } else { '.bin' })
                    }
                }
            }

            # expose to later blocks
            #  Set-Variable -Name TestCases -Value $TestCases -Scope Script
        }


        It 'Creates test files <Tag><Ext>' -ForEach $TestCases {
            New-TestFile -Path "$TestFolder\$Tag$Ext" `
                -SizeBytes $Bytes -Kind $Kind
            (Test-Path "$TestFolder\$Tag$Ext") | Should -Be $true
        }
        #
        # a) full download
        #
        It 'Full download matches for <Kind> <Label>' -ForEach $TestCases {
            $url = "$Endpoint/standard/$Tag$Ext"
            $dest = (Join-Path $DownloadFolder "full-$Label$Ext")
            $response = Invoke-CurlRequest $url -OutFile $dest  -PassThru
            $response.StatusCode | Should -Be 200
            $response.Headers['Pragma'] | Should -Be 'no-cache'
            # $response.Headers['Content-Type'] | Should -Be 'text/plain; charset=utf-8'
            $response.Headers['Content-Disposition'] | Should -Be "inline; filename=""$Tag$Ext"""
            $directives = $response.Headers['Cache-Control'] -split '\s*,\s*'

            $directives | Should -Contain 'no-store'
            $directives | Should -Contain 'must-revalidate'
            $directives | Should -Contain 'no-cache'
            (Test-Path $dest) | Should -BeTrue
            (Get-FileHash $dest -Algo SHA256).Hash |
                Should -Be (Get-FileHash "$TestFolder\$Tag$Ext" -Algo SHA256).Hash
            Remove-Item $dest -Force
            (Test-Path $dest) | Should -BeFalse
        }

        #
        # b) ranged download
        #
        It 'Range download matches for <Kind> <Label>' -ForEach $TestCases {
            $url = "$Endpoint/standard/$Tag$Ext"
            $dir = (Join-Path  $DownloadFolder "range-$Label")
            if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
            New-Item $dir -ItemType Directory | Out-Null
            $joined = Get-RangeFile -Url $url -DownloadDir $dir

            (Test-Path $joined) | Should -BeTrue
            (Get-FileHash $joined -Algo SHA256).Hash |
                Should -Be (Get-FileHash "$TestFolder\$Tag$Ext" -Algo SHA256).Hash

            Remove-Item $joined -Force
            (Test-Path $joined) | Should -BeFalse
        }

        #
        # c) compressed – only relevant for text
        #
        It 'Gzip download matches for text <Label>' -ForEach $($TestCases |
                Where-Object { $_.Kind -eq 'Text' }) {

            $url = "$Endpoint/compress/$Tag$Ext"
            $dest = (Join-Path $DownloadFolder "gzip-$Label$Ext")
            #    $response = Invoke-WebRequest $url -OutFile $dest -Headers @{ 'Accept-Encoding' = 'gzip' } -PassThru
            $response = Invoke-CurlRequest -Uri $url -OutFile $dest -Headers @{ 'Accept-Encoding' = 'gzip' } -PassThru
            $response.StatusCode | Should -Be 200
            $response.Headers['Vary'] | Should -Be 'Accept-Encoding'
            $response.Headers['Pragma'] | Should -Be 'no-cache'
            $response.Headers['Content-Type'] | Should -Be 'text/plain; charset=utf-8'
            $response.Headers['Content-Disposition'] | Should -Be "inline; filename=""$Tag$Ext"""
            $directives = $response.Headers['Cache-Control'] -split '\s*,\s*'
            $directives | Should -Contain 'no-store'
            $directives | Should -Contain 'must-revalidate'
            $directives | Should -Contain 'no-cache'
            $response.Headers['Content-Encoding'] | Should -Be 'gzip'


            (Get-FileHash $dest -Algo SHA256).Hash |
                Should -Be (Get-FileHash "$TestFolder\$Tag$Ext" -Algo SHA256).Hash
        }

        


        It 'Cache download matches for text <Label>' -ForEach $($TestCases |
                Where-Object { $_.Kind -eq 'Text' }) {

            $url = "$Endpoint/cache/$Tag$Ext"
            $dest = (Join-Path $DownloadFolder "cache-$Label$Ext")
            $response = Invoke-CurlRequest $url -OutFile $dest -Headers @{ 'Accept-Encoding' = 'gzip' } -PassThru
            $response.StatusCode | Should -Be 200
            $response.Headers['Vary'] | Should -Be 'Accept-Encoding'
            $response.Headers['Content-Type'] | Should -Be 'text/plain; charset=utf-8'
            $response.Headers['Content-Disposition'] | Should -Be "inline; filename=""$Tag$Ext"""

            (Get-FileHash $dest -Algo SHA256).Hash |
                Should -Be (Get-FileHash "$TestFolder\$Tag$Ext" -Algo SHA256).Hash
        }
    }
}
