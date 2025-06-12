$prefix = 'http://localhost:8081/receive/callback/'
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "Listening on $prefix ..."
$ctx = $listener.GetContext()             # ← blocks
Write-Host ">>> got $($ctx.Request.HttpMethod) $($ctx.Request.Url)"

$body = [IO.StreamReader]::new($ctx.Request.InputStream).ReadToEnd()
Write-Host ">>> body = $body"

$ctx.Response.StatusCode = 200
$ctx.Response.Close()
$listener.Stop()
