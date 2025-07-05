param(
    [string]$BrowserPath = "msedge",  # Default to Microsoft Edge
    [string]$HostName = "localhost",  # Changed from Host to avoid conflict
    [int]$HttpsPort = 8043  # Using HTTPS port instead of HTTP
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

# Check if the Pode server is running
function Test-ServerConnection {
    Write-ColorOutput "Checking if server is running on $HostName`:$HttpsPort..." $colors.Info

    try {
        # Try to connect to the server
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        $connectTask = $tcpClient.ConnectAsync($HostName, $HttpsPort)
        $timeout = 3000  # 3 seconds timeout

        if ($connectTask.Wait($timeout)) {
            $tcpClient.Close()
            Write-ColorOutput "✅ Server is running on $HostName`:$HttpsPort" $colors.Success
            return $true
        } else {
            $tcpClient.Close()
            Write-ColorOutput "❌ Server connection timeout" $colors.Error
            return $false
        }
    }
    catch {
        Write-ColorOutput "❌ Server is not running on $HostName`:$HttpsPort" $colors.Error
        Write-ColorOutput "Error: $($_.Exception.Message)" $colors.Error
        return $false
    }
}

function Test-Http2WithBrowser {
    $url = "https://$HostName`:$HttpsPort"

    Write-ColorOutput "`n=========================================================" $colors.Header
    Write-ColorOutput "  TESTING HTTP/2 WITH BROWSER OVER HTTPS" $colors.Header
    Write-ColorOutput "=========================================================" $colors.Header

    Write-ColorOutput "`nServer Information:" $colors.Highlight
    Write-ColorOutput "- URL: $url" $colors.Info
    Write-ColorOutput "- Protocol: HTTPS (required for HTTP/2 in browsers)" $colors.Info

    Write-ColorOutput "`nIMPORTANT NOTES:" $colors.Warning
    Write-ColorOutput "- This uses a self-signed certificate, so you'll get a security warning" $colors.Warning
    Write-ColorOutput "- Click 'Advanced' and 'Proceed to localhost (unsafe)' to continue" $colors.Warning
    Write-ColorOutput "- This is normal for development/testing purposes" $colors.Warning

    Write-ColorOutput "`nBrowser Testing Instructions:" $colors.Highlight
    Write-ColorOutput "1. Opening browser to $url" $colors.Info
    Write-ColorOutput "2. Accept the security warning for the self-signed certificate" $colors.Warning
    Write-ColorOutput "3. To verify HTTP/2 is working:" $colors.Info
    Write-ColorOutput "   - In Chrome/Edge: Open DevTools (F12) > Network tab" $colors.Info
    Write-ColorOutput "   - Look for 'Protocol' column (right-click headers to add it if not visible)" $colors.Info
    Write-ColorOutput "   - Reload the page and check if requests show 'h2' protocol" $colors.Info
    Write-ColorOutput "   - If 'h2' appears, HTTP/2 is working correctly!" $colors.Success
    Write-ColorOutput "`n4. You should see 'Protocol: HTTP/2.0' displayed on the webpage itself" $colors.Info

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

    # Wait a moment for the browser to load, then run verification
    Write-ColorOutput "`nWaiting for browser to load, then running HTTP/2 verification test..." $colors.Info
    Start-Sleep -Seconds 3

    # Run our HTTP/2 verification script against HTTPS port
    & "$PSScriptRoot\test-http2-verify-https.ps1" -HostName $HostName -Port $HttpsPort
}

function Show-ServerStartInstructions {
    Write-ColorOutput "`n=========================================================" $colors.Header
    Write-ColorOutput "  HOW TO START THE SERVER" $colors.Header
    Write-ColorOutput "=========================================================" $colors.Header

    Write-ColorOutput "`nTo start the FileBrowser server with HTTPS support, run:" $colors.Info
    Write-ColorOutput "cd examples\FileBrowser" $colors.Highlight
    Write-ColorOutput ".\FileBrowser.ps1" $colors.Highlight

    Write-ColorOutput "`nThe server will start with both HTTP and HTTPS endpoints:" $colors.Info
    Write-ColorOutput "- HTTP:  http://localhost:8081" $colors.Info
    Write-ColorOutput "- HTTPS: https://localhost:8043 (self-signed certificate)" $colors.Success

    Write-ColorOutput "`nFor HTTP/2 browser testing, use the HTTPS endpoint!" $colors.Warning
}

# Remove the Stop-PodeServer function since we're not managing the server
# function Stop-PodeServer {

# Main execution flow
Write-ColorOutput "`n=========================================================" $colors.Header
Write-ColorOutput "  HTTP/2 BROWSER TESTING SCRIPT (HTTPS)" $colors.Header
Write-ColorOutput "=========================================================" $colors.Header

Write-ColorOutput "`nWhy HTTPS is required:" $colors.Info
Write-ColorOutput "- Modern browsers only support HTTP/2 over HTTPS connections" $colors.Info
Write-ColorOutput "- This is a security requirement implemented by all major browsers" $colors.Info
Write-ColorOutput "- HTTP/2 over plain HTTP works for testing tools but not browsers" $colors.Info

# Check if server is running
if (Test-ServerConnection) {
    # Server is running, proceed with testing
    Test-Http2WithBrowser

    Write-ColorOutput "`nTesting completed! Check your browser for HTTP/2 protocol verification." $colors.Success
} else {
    # Server is not running, show instructions
    Write-ColorOutput "`nServer is not running. Please start the FileBrowser server first." $colors.Warning
    Show-ServerStartInstructions

    Write-ColorOutput "`nAfter starting the server, run this script again to test HTTP/2." $colors.Info
}

Write-ColorOutput "`nTest script completed." $colors.Info
