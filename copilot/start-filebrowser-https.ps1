#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Starts the FileBrowser server with HTTPS support for HTTP/2 browser testing.

.DESCRIPTION
    This script starts the Pode FileBrowser server with both HTTP and HTTPS endpoints.
    The HTTPS endpoint (port 8043) is required for HTTP/2 browser testing, as modern
    browsers only support HTTP/2 over secure connections.

.PARAMETER Port
    The HTTPS port to use. Default is 8043.

.EXAMPLE
    .\start-filebrowser-https.ps1

    Starts the FileBrowser server with default HTTPS port 8043.

.EXAMPLE
    .\start-filebrowser-https.ps1 -Port 8443

    Starts the FileBrowser server with HTTPS port 8443.
#>

param(
    [int]$Port = 8043
)

# Define colors for better output visualization
$colors = @{
    Success = 'Green'
    Warning = 'Yellow'
    Error = 'Red'
    Info = 'Cyan'
    Header = 'Magenta'
    Highlight = 'White'
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'White'
    )

    Write-Host $Message -ForegroundColor $Color
}

Write-ColorOutput "`n=========================================================" $colors.Header
Write-ColorOutput "  PODE FILEBROWSER SERVER (HTTP/2 READY)" $colors.Header
Write-ColorOutput "=========================================================" $colors.Header

Write-ColorOutput "`nStarting FileBrowser server with HTTPS support..." $colors.Info
Write-ColorOutput "This server includes both HTTP and HTTPS endpoints:" $colors.Info
Write-ColorOutput "- HTTP:  http://localhost:8081" $colors.Info
Write-ColorOutput "- HTTPS: https://localhost:$Port (self-signed certificate)" $colors.Success

Write-ColorOutput "`nFor HTTP/2 browser testing, use the HTTPS endpoint!" $colors.Warning
Write-ColorOutput "Browsers require HTTPS for HTTP/2 connections." $colors.Warning

Write-ColorOutput "`nStarting server..." $colors.Info

try {
    # Get the current script directory to find the examples folder
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $rootDir = Split-Path -Parent $scriptDir
    $fileBrowserPath = Join-Path $rootDir "examples\FileBrowser\FileBrowser.ps1"

    if (-not (Test-Path $fileBrowserPath)) {
        Write-ColorOutput "❌ ERROR: FileBrowser.ps1 not found at: $fileBrowserPath" $colors.Error
        Write-ColorOutput "Please make sure you're running this script from the copilot directory." $colors.Error
        exit 1
    }

    Write-ColorOutput "Loading FileBrowser from: $fileBrowserPath" $colors.Info

    # Change to the project root directory so relative paths work correctly
    Push-Location $rootDir

    # Load and run the FileBrowser script
    . $fileBrowserPath

} catch {
    Write-ColorOutput "❌ ERROR: Failed to start server: $($_.Exception.Message)" $colors.Error
    Write-ColorOutput "Stack trace: $($_.ScriptStackTrace)" $colors.Error
} finally {
    Pop-Location
}

Write-ColorOutput "`nServer stopped." $colors.Info
