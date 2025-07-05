try {
    $podePath = $PWD
    
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Host "PowerShell Edition: $($PSVersionTable.PSEdition)"
    
    if (Test-Path -Path "$($podePath)/src/Pode.psm1" -PathType Leaf) {
        Write-Host "Loading Pode from source: $($podePath)/src/Pode.psm1"
        Import-Module "$($podePath)/src/Pode.psm1" -Force -ErrorAction Stop
    }
    else {
        Write-Host "Loading Pode from gallery"
        Import-Module -Name 'Pode' -MaximumVersion 2.99 -ErrorAction Stop
    }
    
    # Check which assemblies are loaded
    $podeModule = Get-Module Pode
    Write-Host "Pode Module Path: $($podeModule.Path)"
    Write-Host "Pode Version: $($podeModule.Version)"
    
    # Check loaded assemblies
    $loadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -like "*Pode*" }
    foreach ($assembly in $loadedAssemblies) {
        Write-Host "Loaded Assembly: $($assembly.FullName)"
        Write-Host "Assembly Location: $($assembly.Location)"
    }
    
    # Check if HTTP/2 types are available
    try {
        $http2RequestType = [Pode.PodeHttp2Request]
        Write-Host "PodeHttp2Request type is available: $($http2RequestType -ne $null)"
    } catch {
        Write-Host "PodeHttp2Request type is NOT available: $($_.Exception.Message)"
    }
    
    try {
        $http2ResponseType = [Pode.PodeHttp2Response]
        Write-Host "PodeHttp2Response type is available: $($http2ResponseType -ne $null)"
    } catch {
        Write-Host "PodeHttp2Response type is NOT available: $($_.Exception.Message)"
    }
    
} catch {
    Write-Host "Error: $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace
}
