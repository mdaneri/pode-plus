<#
.SYNOPSIS
    A PowerShell script to set up a Pode server with API key authentication and various route configurations.

.DESCRIPTION
    This script sets up a Pode server that listens on a specified port, enables request and error logging,
    and configures API key authentication. It also defines a route to fetch a list of users, requiring authentication.

.PARAMETER Location
    The location where the API key is expected. Valid values are 'Header', 'Query', and 'Cookie'. Default is 'Header'.

.EXAMPLE
    To run the sample: ./Web-AuthApiKey.ps1

    Invoke-RestMethod -Uri http://localhost:8081/users -Method Get

.LINK
    https://github.com/Badgerati/Pode/blob/develop/examples/Authentication/Web-AuthApiKey.ps1

.NOTES
    Use:
    Invoke-RestMethod -Method Get -Uri 'http://localhost:8081/users' -Headers @{ 'X-API-KEY' = 'test-api-key' }

.NOTES
    Author: Pode Team
    License: MIT License
#>
param(
    [Parameter()]
    [ValidateSet('Header', 'Query', 'Cookie')]
    [string]
    $Location = 'Header'
)

try {
    # Determine the script path and Pode module path
    $ScriptPath = (Split-Path -Parent -Path (Split-Path -Parent -Path $MyInvocation.MyCommand.Path))
    $podePath = Split-Path -Parent -Path $ScriptPath

    # Import the Pode module from the source path if it exists, otherwise from installed modules
    if (Test-Path -Path "$($podePath)/src/Pode.psm1" -PathType Leaf) {
        Import-Module "$($podePath)/src/Pode.psm1" -Force -ErrorAction Stop
    }
    else {
        Import-Module -Name 'Pode' -MaximumVersion 2.99 -ErrorAction Stop
    }
}
catch { throw }

# or just:
# Import-Module Pode

# create a server, and start listening on port 8081
Start-PodeServer -Threads 2 {

    # listen on localhost:8081
    Add-PodeEndpoint -Address localhost -Port 8081 -Protocol Http

    New-PodeLoggingMethod -File -Name 'requests' | Enable-PodeRequestLogging
    New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging

    # setup bearer auth
    New-PodeAuthScheme -ApiKey -Location $Location | Add-PodeAuth -Name 'Validate' -Sessionless -ScriptBlock {
        param($key)

        # here you'd check a real user storage, this is just for example
        if ($key -ieq 'test-api-key') {
            return @{
                User = @{
                    ID   = 'M0R7Y302'
                    Name = 'Morty'
                    Type = 'Human'
                }
            }
        }

        return $null
    }

    # GET request to get list of users (since there's no session, authentication will always happen)
    Add-PodeRoute -Method Get -Path '/users' -Authentication 'Validate' -ScriptBlock {
        Write-PodeJsonResponse -Value @{
            Users = @(
                @{
                    Name = 'Deep Thought'
                    Age  = 42
                },
                @{
                    Name = 'Leeroy Jenkins'
                    Age  = 1337
                }
            )
        }
    }

}