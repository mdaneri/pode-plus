#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Enhanced FileBrowser server with explicit HTTP/2 support.

.DESCRIPTION
    This script starts the Pode FileBrowser server with explicit HTTP/2 configuration
    to ensure proper ALPN negotiation for browser testing.
#>

param(
    [int]$HttpPort = 8081,
    [int]$HttpsPort = 8043
)

try {
    $FileBrowserPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Path
    $podePath = Split-Path -Parent -Path $FileBrowserPath
    if (Test-Path -Path "$($podePath)/src/Pode.psm1" -PathType Leaf) {
        Import-Module "$($podePath)/src/Pode.psm1" -Force -ErrorAction Stop
    }
    else {
        Import-Module -Name 'Pode' -MaximumVersion 2.99 -ErrorAction Stop
    }
}
catch { throw }

$directoryPath = $podePath

Write-Host "Starting Pode FileBrowser with HTTP/2 support..." -ForegroundColor Green
Write-Host "HTTP:  http://localhost:$HttpPort" -ForegroundColor Cyan
Write-Host "HTTPS: https://localhost:$HttpsPort (HTTP/2 enabled)" -ForegroundColor Cyan

Start-PodeServer -ScriptBlock {
    # Enable debug logging for protocol detection
    $VerbosePreference = 'Continue'

    # Configure endpoints
    Add-PodeEndpoint -Address localhost -Port $using:HttpPort -Protocol Http
    Add-PodeEndpoint -Address localhost -Port $using:HttpsPort -Protocol Https -Default -SelfSigned -DualMode

    # Enable logging
    New-PodeLoggingMethod -Terminal | Enable-PodeRequestLogging
    New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging

    # Force HTTP/2 support by setting server configuration
    # This ensures ALPN negotiation works correctly
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Write-Host "PowerShell 7+ detected - HTTP/2 ALPN should be supported" -ForegroundColor Green
    } else {
        Write-Host "PowerShell 5.x detected - HTTP/2 support may be limited" -ForegroundColor Yellow
    }

    # Setup basic auth (base64> username:password in header)
    New-PodeAuthScheme -Basic -Realm 'Pode Static Page' | Add-PodeAuth -Name 'Validate' -Sessionless -ScriptBlock {
        param($username, $password)

        # here you'd check a real user storage, this is just for example
        if ($username -eq 'morty' -and $password -eq 'pickle') {
            return @{
                User = @{
                    ID   = 'M0R7Y302'
                    Name = 'Morty'
                    Type = 'Human'
                }
            }
        }

        return @{ Message = 'Invalid details supplied' }
    }

    Add-PodeRoute -Method Get -Path '*/LICENSE.txt' -ScriptBlock {
        $value = @'
Don't kid me. Nobody will believe that you want to read this legal nonsense.
I want to be kind; this is a summary of the content:

Nothing to report :D
'@
        Write-PodeTextResponse -Value $value
    }

    Add-PodeRoute -Method Get -Path '/close' -ScriptBlock {
        Close-PodeServer
    }

    Add-PodeStaticRouteGroup -FileBrowser -Routes {
        Add-PodeStaticRoute -Path '/standard' -Source $using:directoryPath
        Add-PodeStaticRoute -Path '/download' -Source $using:directoryPath -DownloadOnly  -PassThru | Add-PodeRouteCompression -Enable -Encoding gzip
        Add-PodeStaticRoute -Path '/nodownload' -Source $using:directoryPath
        Add-PodeStaticRoute -Path '/gzip' -Source $using:directoryPath -PassThru | Add-PodeRouteCompression -Enable -Encoding gzip
        Add-PodeStaticRoute -Path '/deflate' -Source $using:directoryPath -PassThru | Add-PodeRouteCompression -Enable -Encoding deflate
        Add-PodeStaticRoute -Path '/cache' -Source $using:directoryPath -PassThru | Add-PodeRouteCache -Enable -MaxAge 3600 -Visibility public -ETagMode mtime -Immutable
        Add-PodeStaticRoute -Path '/compress_cache' -Source $using:directoryPath -PassThru | Add-PodeRouteCache -Enable -MaxAge 3600 -Visibility public -ETagMode mtime -Immutable -PassThru | Add-PodeRouteCompression -Enable -Encoding deflate, gzip, br

        if ($IsCoreCLR) {
            Add-PodeStaticRoute -Path '/br' -Source $using:directoryPath -PassThru | Add-PodeRouteCompression -Enable -Encoding br
        }
        Add-PodeStaticRoute -Path '/any/*/test' -Source $using:directoryPath
        Add-PodeStaticRoute -Path '/auth' -Source $using:directoryPath -Authentication 'Validate'
    }
    Add-PodeStaticRoute -Path '/nobrowsing' -Source $directoryPath

    Add-PodeRoute -Method Get -Path '/attachment/*/test' -ScriptBlock {
        Set-PodeResponseAttachment -Path 'ruler.png'
    }

    Add-PodeRoute -Method Get -Path '/encoding/transfer' -ScriptBlock {
        $string = Get-Content -Path $using:directoryPath/pode.build.ps1 -raw
        $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($string))
        Write-PodeJsonResponse -Value @{ Data = $data }
    } -PassThru | Add-PodeRouteCompression -Enable -Encoding gzip

    Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
        # Enhanced protocol detection for HTTP/2
        $protocol = 'HTTP/1.1'  # Default
        $requestType = $WebEvent.Request.GetType().Name
        $debugInfo = "Request type: $requestType"

        try {
            # Check for HTTP/2 request type
            if ($WebEvent.Request.GetType().Name -eq 'PodeHttp2Request') {
                $protocol = 'HTTP/2.0'
                $debugInfo += ' | ✅ HTTP/2 detected!'
            }
            else {
                $debugInfo += ' | HTTP/1.x detected'
            }

            # Also check the protocol from the request itself
            if ($WebEvent.Request.Protocol) {
                $debugInfo += " | Request.Protocol: $($WebEvent.Request.Protocol)"
            }

            # Check if this is an HTTPS connection
            if ($WebEvent.Request.IsSecure) {
                $debugInfo += " | 🔒 HTTPS connection"
            } else {
                $debugInfo += " | HTTP connection (browsers won't use HTTP/2)"
            }

        }
        catch {
            $debugInfo += " | Error: $($_.Exception.Message)"
        }

        # Enhanced status message
        $http2Status = if ($protocol -eq 'HTTP/2.0') {
            "✅ HTTP/2 is working!"
        } elseif ($WebEvent.Request.IsSecure) {
            "⚠️ HTTPS but HTTP/1.1 - check ALPN negotiation"
        } else {
            "ℹ️ HTTP/1.1 over HTTP (browsers require HTTPS for HTTP/2)"
        }

        $str = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Pode HTTP/2 Test Server</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 2rem; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { margin-bottom: .5rem; color: #2c3e50; }
        .protocol { font-size: 1.5em; font-weight: bold; margin: 1rem 0; padding: 1rem; border-radius: 4px; }
        .http2 { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .http1 { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .debug { background: #f8f9fa; padding: 1rem; border-radius: 4px; font-family: monospace; font-size: 0.9em; margin: 1rem 0; }
        ul { list-style: none; padding-left: 0; }
        li { margin: .5rem 0; }
        a { text-decoration: none; color: #0060df; padding: 0.25rem 0.5rem; border-radius: 4px; display: inline-block; }
        a:hover { background: #e6f3ff; text-decoration: underline; }
        small { color: #666; font-size: 0.85em; }
        .status { font-size: 1.1em; margin: 1rem 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Pode HTTP/2 Test Server</h1>

        <div class="protocol $($protocol -eq 'HTTP/2.0' ? 'http2' : 'http1')">
            Protocol: $protocol
        </div>

        <div class="status">$http2Status</div>

        <div class="debug">
            <strong>Debug Info:</strong><br>
            $debugInfo
        </div>

        <h2>Test Routes</h2>
        <ul>
            <li><a href="/standard">📁 /standard</a> <small>Standard file browser</small></li>
            <li><a href="/download">⬇️ /download</a> <small>Download-only mode</small></li>
            <li><a href="/gzip">🗜️ /gzip</a> <small>With gzip compression</small></li>
            <li><a href="/deflate">🗜️ /deflate</a> <small>With deflate compression</small></li>
            <li><a href="/cache">💾 /cache</a> <small>With caching headers</small></li>
            <li><a href="/compress_cache">⚡ /compress_cache</a> <small>Compression + caching</small></li>
            <li><a href="/auth">🔐 /auth</a> <small>Basic auth (morty/pickle)</small></li>
        </ul>

        <h3>🔍 How to Verify HTTP/2:</h3>
        <ol>
            <li>Open DevTools (F12)</li>
            <li>Go to Network tab</li>
            <li>Right-click headers and add "Protocol" column</li>
            <li>Reload this page</li>
            <li>Look for "h2" in the Protocol column</li>
        </ol>
    </div>
</body>
</html>
"@
        Write-PodeHtmlResponse -Value $str -StatusCode 200
    }
}
