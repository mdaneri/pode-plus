# HTTP/2 Browser Testing Guide

## The Problem

When testing HTTP/2 with browsers, you might notice that your HTTP/2 implementation works perfectly with testing tools but doesn't work in browsers. This is a common issue with a simple explanation.

## Why Browsers Require HTTPS for HTTP/2

**Modern browsers only support HTTP/2 over HTTPS connections.** This is a security requirement implemented by all major browsers (Chrome, Firefox, Safari, Edge, etc.).

- ✅ **HTTP/2 over HTTPS**: Supported by all browsers
- ❌ **HTTP/2 over plain HTTP**: Not supported by browsers (but works with testing tools)

## How to Test HTTP/2 with Browsers

### Method 1: Separate Server and Test (Recommended)

1. **Start the FileBrowser server**:
   ```powershell
   .\start-filebrowser-https.ps1
   ```
   OR manually:
   ```powershell
   cd examples\FileBrowser
   .\FileBrowser.ps1
   ```

2. **Run the browser test** (in a separate terminal):
   ```powershell
   .\test-http2-browser-https.ps1
   ```

### Method 2: Use the Legacy Combined Script

For the old approach that starts/stops the server automatically:
```powershell
.\test-http2-browser-https-combined.ps1  # (if you need this approach)
```

Your Pode server should be configured with HTTPS endpoints for browser testing:

```powershell
Start-PodeServer -ScriptBlock {
    # HTTP endpoint (for tools/testing)
    Add-PodeEndpoint -Address localhost -Port 8081 -Protocol Http

    # HTTPS endpoint (for browsers) - THIS IS REQUIRED FOR HTTP/2 IN BROWSERS
    Add-PodeEndpoint -Address localhost -Port 8043 -Protocol Https -Default -SelfSigned -DualMode

    # Your routes...
}
```

### Testing Scripts

1. **For browsers**: Use `test-http2-browser-https.ps1`
   - Tests HTTP/2 over HTTPS (port 8043)
   - Works with all modern browsers
   - Requires accepting self-signed certificate warning

2. **For protocol testing**: Use `test-http2-browser.ps1`
   - Tests HTTP/2 over HTTP (port 8081)
   - Works with testing tools but NOT browsers
   - Useful for protocol-level verification

## Browser Testing Steps

1. Run the HTTPS test script:
   ```powershell
   .\test-http2-browser-https.ps1
   ```

2. When the browser opens:
   - You'll see a security warning (expected for self-signed certificates)
   - Click "Advanced" > "Proceed to localhost (unsafe)"
   - This is normal for development/testing

3. Verify HTTP/2 is working:
   - Open DevTools (F12)
   - Go to Network tab
   - Add "Protocol" column if not visible (right-click on headers)
   - Reload the page
   - Look for "h2" in the Protocol column ✅

4. The webpage should also display "Protocol: HTTP/2.0"

## Summary

- **For browser testing**: Always use HTTPS (port 8043)
- **For protocol testing**: HTTP is fine (port 8081)
- **Security warning**: Expected with self-signed certificates
- **Protocol indicator**: Look for "h2" in browser DevTools

Your HTTP/2 implementation is likely working correctly - the issue is just that browsers require HTTPS!
