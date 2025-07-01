$uri = 'http://localhost:8081/bigfile.txt'
$rangeSize = 1GB
$tempDir = "$env:TEMP\pode-range-test"
$fullPath = "$tempDir\full.ova"
$joinedPath = "$tempDir\joined.ova"

# Ensure temp folder
Remove-Item $tempDir -Recurse -Force -ErrorAction Ignore
New-Item $tempDir -ItemType Directory | Out-Null

# Step 1: Download full file for reference
Invoke-WebRequest -Uri $uri -OutFile $fullPath

# Step 2: Get full size
$resp = Invoke-WebRequest -Uri $uri -Method Head
$length = [Int64]::Parse($resp.Headers['Content-Length'])
Write-Host "Total file size: $length bytes"


Write-Host "Failed Range"
Invoke-WebRequest -Uri $uri -OutFile $partFile -Headers @{ Range ="bytes=0-$($length+200)"}


# Step 3: Download in ranges
$parts = @()
$i = 0
for ($start = 0; $start -lt $length; $start += $rangeSize) {
    $end = ($start + $rangeSize - 1)
    if ($end -ge $length) { $end = $length - 1 }
    $rangeHeader = "bytes=$start-$end"
    $partFile = "$tempDir\part$i.bin"
    $i++

    Write-Host "Downloading range $rangeHeader to $partFile"
    Invoke-WebRequest -Uri $uri -OutFile $partFile -Headers @{ Range = $rangeHeader }

    $parts += $partFile
}

# Step 4: Join parts
Write-Host "Joining $($parts.Count) parts into $joinedPath"
$out = [System.IO.File]::Create($joinedPath)
foreach ($f in $parts) {
    $bytes = [System.IO.File]::ReadAllBytes($f)
    $out.Write($bytes, 0, $bytes.Length)
}
$out.Dispose()

# Step 5: Compare hashes
$hash1 = (Get-FileHash $fullPath -Algorithm SHA256).Hash
$hash2 = (Get-FileHash $joinedPath -Algorithm SHA256).Hash

Write-Host "Original SHA-256: $hash1"
Write-Host "Joined   SHA-256: $hash2"

if ($hash1 -eq $hash2) {
    Write-Host '✅ Match! Range support works correctly.' -ForegroundColor Green
}
else {
    Write-Host "❌ Mismatch. There's a problem." -ForegroundColor Red
}

