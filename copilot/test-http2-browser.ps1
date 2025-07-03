param(
    [string]$BrowserPath = "msedge",  # Default to Microsoft Edge
    [string]$Host = "localhost",
    [int]$Port = 8081
)

# Set error action preference
$ErrorActionPreference = 'Stop'

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
    # Using Write-Information with color tags for better compatibility
    $host.UI.WriteLine($Color, $host.UI.RawUI.BackgroundColor, $Message)
}

# Set up a simple Pode server with SSL enabled (required for HTTP/2 in most browsers)
function Start-PodeServer {
    # Check if Pode server is already running on the port
    $portCheck = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($portCheck) {
        Write-ColorOutput "Port $Port is already in use. Please make sure no other server is running on this port." $colors.Error
        return $false
    }

    Write-ColorOutput "Starting FileBrowser server on $Host`:$Port..." $colors.Info

    # Start the server as a background job
    $currentPath = $PWD.Path
    $serverPort = $Port

    $serverJob = Start-Job -ScriptBlock {
        param($Path, $Port)
        Set-Location $Path
        # Dot source the FileBrowser example
        . "$Path\examples\FileBrowser\FileBrowser.ps1" -Port $Port -Verbose
    } -ArgumentList $currentPath, $serverPort

    # Wait for the server to initialize
    Start-Sleep -Seconds 3

    # Check if the job is running
    $jobStatus = Get-Job -Id $serverJob.Id | Select-Object -ExpandProperty State
    if ($jobStatus -ne "Running") {
        Write-ColorOutput "Failed to start the server. Check for errors." $colors.Error
        return $false
    }

    Write-ColorOutput "Server started successfully with job ID: $($serverJob.Id)" $colors.Success
    return $serverJob.Id
}

function Test-Http2WithBrowser {
    param(
        [int]$ServerJobId
    )

    $url = "http://$Host`:$Port"

    Write-ColorOutput "`n=========================================================" $colors.Header
    Write-ColorOutput "  TESTING HTTP/2 WITH BROWSER" $colors.Header
    Write-ColorOutput "=========================================================" $colors.Header

    Write-ColorOutput "`nServer Information:" $colors.Highlight
    Write-ColorOutput "- URL: $url" $colors.Info
    Write-ColorOutput "- Job ID: $ServerJobId" $colors.Info

    Write-ColorOutput "`nBrowser Testing Instructions:" $colors.Highlight
    Write-ColorOutput "1. Opening browser to $url" $colors.Info
    Write-ColorOutput "2. To verify HTTP/2 is working:" $colors.Info
    Write-ColorOutput "   - In Chrome/Edge: Open DevTools (F12) > Network tab" $colors.Info
    Write-ColorOutput "   - Look for 'Protocol' column (add it if not visible)" $colors.Info
    Write-ColorOutput "   - Reload the page and check if requests show 'h2' protocol" $colors.Info
    Write-ColorOutput "   - If 'h2' appears, HTTP/2 is working correctly!" $colors.Success

    # IMPORTANT NOTE: This test uses HTTP (not HTTPS), which means browsers will NOT use HTTP/2
    # Modern browsers require HTTPS for HTTP/2. Use test-http2-browser-https.ps1 for proper browser testing.
    # This script is useful for testing the HTTP/2 protocol implementation with tools, not browsers.

    # Try to open the browser
    try {
        if ($BrowserPath -eq "msedge") {
            Start-Process "msedge" -ArgumentList "$url" -ErrorAction SilentlyContinue
        }
        elseif ($BrowserPath -eq "chrome") {
            Start-Process "chrome" -ArgumentList "$url" -ErrorAction SilentlyContinue
        }
        elseif ($BrowserPath -eq "firefox") {
            Start-Process "firefox" -ArgumentList "$url" -ErrorAction SilentlyContinue
        }
        else {
            # Try to use the provided path
            Start-Process $BrowserPath -ArgumentList "$url" -ErrorAction SilentlyContinue
        }

        Write-ColorOutput "`nBrowser launched. Checking the page in browser..." $colors.Success
    }
    catch {
        Write-ColorOutput "`nCouldn't automatically open browser. Please manually navigate to: $url" $colors.Warning
    }

    # Now run our HTTP/2 verification script
    Write-ColorOutput "`nRunning HTTP/2 verification test..." $colors.Info
    & "$PSScriptRoot\test-http2-verify.ps1" -HostName $Host -Port $Port
}

function Stop-PodeServer {
    param(
        [int]$JobId
    )

    Write-ColorOutput "`n=========================================================" $colors.Header
    Write-ColorOutput "  STOPPING SERVER" $colors.Header
    Write-ColorOutput "=========================================================" $colors.Header

    try {
        Stop-Job -Id $JobId
        Remove-Job -Id $JobId -Force
        Write-ColorOutput "Server stopped successfully." $colors.Success
    }
    catch {
        Write-ColorOutput "Failed to stop server: $_" $colors.Error
    }
}

# Main execution flow
Write-ColorOutput "`n=========================================================" $colors.Header
Write-ColorOutput "  HTTP/2 BROWSER TESTING SCRIPT" $colors.Header
Write-ColorOutput "=========================================================" $colors.Header

# Start the server
$jobId = Start-PodeServer
if ($jobId) {
    try {
        # Test with browser
        Test-Http2WithBrowser -ServerJobId $jobId

        # Wait for user input before stopping
        Write-ColorOutput "`nPress Enter to stop the server and exit..." $colors.Highlight
        Read-Host | Out-Null
    }
    finally {
        # Stop the server
        Stop-PodeServer -JobId $jobId
    }
}

Write-ColorOutput "`nTest script completed. Exiting." $colors.Info
