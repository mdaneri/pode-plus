param(
    [string]$BrowserPath = "msedge",  # Default to Microsoft Edge
    [string]$HostName = "localhost",
    [int]$Port = 8081
)

# Define colors for better output visualization
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'White'
    )
    $host.UI.WriteLine($Color, $host.UI.RawUI.BackgroundColor, $Message)
}

Write-ColorOutput "`n=========================================================" "Magenta"
Write-ColorOutput "  BROWSER WITH HTTP/2 OVER HTTP ENABLED" "Magenta"
Write-ColorOutput "=========================================================" "Magenta"

Write-ColorOutput "`nThis script launches a browser with flags that enable HTTP/2 over HTTP" "Cyan"
Write-ColorOutput "for testing purposes. This bypasses the normal requirement for HTTPS." "Cyan"

$url = "http://$HostName`:$Port"
Write-ColorOutput "`nLaunching browser to $url with HTTP/2 enabled..." "Green"

try {
    if ($BrowserPath -eq "msedge") {
        $browserExe = "msedge"
        $browserName = "Microsoft Edge"
        $flags = "--enable-features=AllowInsecureLocalhostHTTP2"
    } 
    elseif ($BrowserPath -eq "chrome") {
        $browserExe = "chrome"
        $browserName = "Google Chrome"
        $flags = "--enable-features=AllowInsecureLocalhostHTTP2"
    }
    else {
        $browserExe = $BrowserPath
        $browserName = "Custom browser"
        $flags = "--enable-features=AllowInsecureLocalhostHTTP2"
    }
    
    Write-ColorOutput "`nLaunching $browserName with special flags:" "Cyan"
    Write-ColorOutput "  $flags" "Yellow"
    
    Start-Process $browserExe -ArgumentList "$flags", "$url" -ErrorAction Stop
    
    Write-ColorOutput "`nBrowser launched successfully!" "Green"
    Write-ColorOutput "To verify HTTP/2 is working:" "Cyan"
    Write-ColorOutput "1. Open DevTools (F12)" "Cyan"
    Write-ColorOutput "2. Go to Network tab" "Cyan"
    Write-ColorOutput "3. Make sure 'Protocol' column is visible" "Cyan"
    Write-ColorOutput "4. Reload the page" "Cyan"
    Write-ColorOutput "5. Check that requests show 'h2' as protocol" "Cyan"
}
catch {
    Write-ColorOutput "`nFailed to launch browser: $_" "Red"
    Write-ColorOutput "`nTry these alternative methods:" "Yellow"
    Write-ColorOutput "1. For Chrome/Edge, launch from command line:" "Cyan"
    Write-ColorOutput "   chrome --enable-features=AllowInsecureLocalhostHTTP2 $url" "White"
    Write-ColorOutput "   msedge --enable-features=AllowInsecureLocalhostHTTP2 $url" "White"
    Write-ColorOutput "2. Or use HTTPS instead with the test-browser-http2.ps1 -UseHttps parameter" "Cyan"
}

Write-ColorOutput "`n=========================================================" "Magenta"
