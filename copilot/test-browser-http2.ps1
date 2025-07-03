# Simple browser test to check HTTP/2 support
try {
    Write-Host "Testing HTTPS connection to localhost:8043..." -ForegroundColor Cyan

    # Make a simple request (skip certificate validation for self-signed cert)
    $response = Invoke-WebRequest -Uri "https://localhost:8043/" -UseBasicParsing -SkipCertificateCheck -TimeoutSec 10

    Write-Host "✅ Response received!" -ForegroundColor Green
    Write-Host "Status Code: $($response.StatusCode)" -ForegroundColor Yellow
    Write-Host "Headers:" -ForegroundColor Yellow
    foreach ($header in $response.Headers.GetEnumerator()) {
        Write-Host "  $($header.Key): $($header.Value)" -ForegroundColor Gray
    }

    if ($response.Headers.ContainsKey("Server")) {
        Write-Host "Server: $($response.Headers.Server)" -ForegroundColor Green
    }

    Write-Host "Content Length: $($response.Content.Length) characters" -ForegroundColor Yellow

} catch {
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Type: $($_.Exception.GetType().Name)" -ForegroundColor Red
}
