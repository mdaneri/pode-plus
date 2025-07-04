#!/usr/bin/env pwsh
# Test HTTP/2 response validation

Write-Host "Testing HTTP/2 server response..." -ForegroundColor Green
Write-Host "Server should be running on https://localhost:8043" -ForegroundColor Cyan

# Test with curl if available
try {
    Write-Host "Testing with curl..." -ForegroundColor Yellow
    $curlResult = curl -k -v --http2-prior-knowledge https://localhost:8043 2>&1

    if ($curlResult -match "HTTP/2 200") {
        Write-Host "✅ curl successfully received HTTP/2 response" -ForegroundColor Green
    } else {
        Write-Host "❌ curl did not receive HTTP/2 response" -ForegroundColor Red
    }

    Write-Host "Full curl output:" -ForegroundColor Cyan
    $curlResult
} catch {
    Write-Host "curl not available or failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`n=== Manual Browser Test ===" -ForegroundColor Magenta
Write-Host "Please open a browser and visit: https://localhost:8043" -ForegroundColor Cyan
Write-Host "Accept the self-signed certificate warning" -ForegroundColor Yellow
Write-Host "If you see the FileBrowser page, HTTP/2 is working correctly!" -ForegroundColor Green

Read-Host "Press Enter to continue..."
