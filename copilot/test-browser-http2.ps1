param(
    [string]$BrowserPath = "msedge",  # Default to Microsoft Edge
    [string]$HostName = "localhost",
    [int]$Port = 8081,
    [switch]$UseHttps,
    [string]$CertificatePath = "",
    [string]$CertificatePassword = ""
)

# Set error action preference
$ErrorActionPreference = 'Stop'

# Define colors for better output visualization
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'White'
    )
    # Using Write-Information with color tags for better compatibility
    $host.UI.WriteLine($Color, $host.UI.RawUI.BackgroundColor, $Message)
}

# Print header
Write-ColorOutput "`n=========================================================" "Magenta"
Write-ColorOutput "  HTTP/2 BROWSER TESTING SCRIPT" "Magenta"
Write-ColorOutput "=========================================================" "Magenta"

# Start FileBrowser.ps1 directly to avoid Start-Job linting issues
try {
    # First check if the port is in use
    $portCheck = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($portCheck) {
        Write-ColorOutput "Port $Port is already in use. Please make sure no other server is running on this port." "Red"
        exit 1
    }

    # Determine if we're using HTTPS or HTTP
    $protocol = if ($UseHttps) { "https" } else { "http" }
    
    Write-ColorOutput "`nStarting FileBrowser server on $HostName`:$Port ($protocol)..." "Cyan"
    Write-ColorOutput "Press Ctrl+C to stop the server when you're done testing." "Yellow"
    Write-ColorOutput "`nServer Information:" "White"
    Write-ColorOutput "- URL: $protocol`://$HostName`:$Port" "Cyan"
    
    Write-ColorOutput "`nBrowser Testing Instructions:" "White"
    Write-ColorOutput "1. Open your browser and navigate to: $protocol`://$HostName`:$Port" "Cyan"
    Write-ColorOutput "2. To verify HTTP/2 is working:" "Cyan"
    Write-ColorOutput "   - In Chrome/Edge: Open DevTools (F12) > Network tab" "Cyan"
    Write-ColorOutput "   - Look for 'Protocol' column (add it if not visible)" "Cyan" 
    Write-ColorOutput "   - Reload the page and check if requests show 'h2' protocol" "Cyan"
    Write-ColorOutput "   - If 'h2' appears, HTTP/2 is working correctly!" "Green"
    
    if ($UseHttps) {
        Write-ColorOutput "`nImportant HTTPS Notes:" "Yellow"
        Write-ColorOutput "- Most browsers require HTTPS for HTTP/2 connections" "Cyan"
        Write-ColorOutput "- You may see a certificate warning for self-signed certificates" "Cyan"
        Write-ColorOutput "- Click 'Advanced' and 'Proceed anyway' to continue to the site" "Cyan"
    }
    else {
        Write-ColorOutput "`nImportant HTTP Notes:" "Yellow"
        Write-ColorOutput "- Most browsers only support HTTP/2 over HTTPS connections" "Cyan"
        Write-ColorOutput "- You may need to use the -UseHttps parameter for proper HTTP/2 testing" "Cyan"
        Write-ColorOutput "- Chrome/Edge can be started with --enable-features=AllowInsecureLocalhostHTTP2" "Cyan"
    }
    
    # Try to open the browser
    try {
        $url = "$protocol`://$HostName`:$Port"
        
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
        
        Write-ColorOutput "`nBrowser launched successfully." "Green"
    }
    catch {
        Write-ColorOutput "`nCouldn't automatically open browser. Please manually navigate to: $protocol`://$HostName`:$Port" "Yellow"
    }

    Write-ColorOutput "`nStarting server..." "Green"
    
    # Create a directory for certificates if needed
    if ($UseHttps -and [string]::IsNullOrEmpty($CertificatePath)) {
        Write-ColorOutput "`nGenerating self-signed certificate for HTTPS..." "Yellow"
        
        # Create a certificate directory
        $certDir = Join-Path -Path $PSScriptRoot -ChildPath "certs"
        if (-not (Test-Path $certDir)) {
            New-Item -Path $certDir -ItemType Directory -Force | Out-Null
        }
        
        # Generate a random password
        $certPassword = [System.Guid]::NewGuid().ToString()
        $securePassword = ConvertTo-SecureString -String $certPassword -Force -AsPlainText
        
        # Create certificate path
        $certName = "pode-http2-test"
        $CertificatePath = Join-Path -Path $certDir -ChildPath "$certName.pfx"
        
        # Generate a self-signed certificate
        try {
            $cert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName $HostName -NotAfter (Get-Date).AddYears(1) -KeyAlgorithm RSA -KeyLength 2048
            $certPath = "Cert:\LocalMachine\My\$($cert.Thumbprint)"
            
            # Export the certificate to PFX
            Export-PfxCertificate -Cert $certPath -FilePath $CertificatePath -Password $securePassword -Force | Out-Null
            
            # Clean up the certificate from the store
            Remove-Item -Path $certPath -Force
            
            # Save password for Pode
            $CertificatePassword = $certPassword
            
            Write-ColorOutput "Self-signed certificate created at: $CertificatePath" "Green"
            Write-ColorOutput "Note: You may see browser warnings about this certificate being untrusted." "Yellow"
        }
        catch {
            Write-ColorOutput "Failed to create self-signed certificate: $_" "Red"
            Write-ColorOutput "Will try to continue with HTTP instead of HTTPS." "Yellow"
            $UseHttps = $false
            $protocol = "http"
        }
    }
    
    # Run the FileBrowser example
    $FileBrowserPath = Join-Path -Path $PSScriptRoot -ChildPath "examples\FileBrowser\FileBrowser.ps1"
    if (Test-Path $FileBrowserPath) {
        # Prepare parameters for FileBrowser.ps1
        $scriptParams = @{
            Port = $Port
        }
        
        # Add HTTPS parameters if needed
        if ($UseHttps) {
            $scriptParams['Https'] = $true
            
            if (-not [string]::IsNullOrEmpty($CertificatePath)) {
                $scriptParams['CertificatePath'] = $CertificatePath
            }
            
            if (-not [string]::IsNullOrEmpty($CertificatePassword)) {
                $scriptParams['CertificatePassword'] = $CertificatePassword
            }
        }
        
        # Dot-source the FileBrowser script to run it with the appropriate parameters
        Write-ColorOutput "`nStarting FileBrowser with the following parameters:" "Cyan"
        $scriptParams.GetEnumerator() | ForEach-Object { 
            $value = if ($_.Key -eq 'CertificatePassword') { '********' } else { $_.Value }
            Write-ColorOutput "- $($_.Key): $value" "White" 
        }
        
        # Dot-source the script with parameters
        . $FileBrowserPath @scriptParams
    }
    else {
        Write-ColorOutput "FileBrowser.ps1 not found at expected path: $FileBrowserPath" "Red"
        Write-ColorOutput "Make sure you're running this script from the pode-plus root directory." "Red"
        exit 1
    }
}
catch {
    Write-ColorOutput "Error: $_" "Red"
    exit 1
}
