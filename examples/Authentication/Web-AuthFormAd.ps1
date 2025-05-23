<#
.SYNOPSIS
    PowerShell script to set up a Pode server with Form authentication using Windows Active Directory.

.DESCRIPTION
    This script sets up a Pode server that listens on a specified port and uses Form authentication
    with Windows Active Directory for securing access to different pages. The home page view counter
    is stored in the session data, which is persisted across user sessions.

.EXAMPLE
    To run the sample: ./Web-AuthFormAd.ps1

    This examples shows how to use session persistent authentication using Windows Active Directory.
    The example used here is Form authentication, sent from the <form> in HTML.

    Navigating to the 'http://localhost:8081' endpoint in your browser will auto-rediect you to the '/login'
    page. Here, you can type the details for a domain user. Clicking 'Login' will take you back to the home
    page with a greeting and a view counter. Clicking 'Logout' will purge the session and take you back to
    the login page.

.LINK
    https://github.com/Badgerati/Pode/blob/develop/examples/Authentication/Web-AuthFormAd.ps1

.NOTES
    Author: Pode Team
    License: MIT License
#>
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
    New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging

    # set the view engine
    Set-PodeViewEngine -Type Pode

    # setup session details
    Enable-PodeSessionMiddleware -Duration 120 -Extend

    # setup form auth against windows AD (<form> in HTML)
    New-PodeAuthScheme -Form | Add-PodeAuthWindowsAd -Name 'Login' -Groups @() -Users @() -FailureUrl '/login' -SuccessUrl '/'


    # home page:
    # redirects to login page if not authenticated
    Add-PodeRoute -Method Get -Path '/' -Authentication Login -ScriptBlock {
        $WebEvent.Session.Data.Views++

        Write-PodeViewResponse -Path 'auth-home' -Data @{
            Username = $WebEvent.Auth.User.Name
            Views    = $WebEvent.Session.Data.Views
        }
    }


    # login page:
    # the login flag set below checks if there is already an authenticated session cookie. If there is, then
    # the user is redirected to the home page. If there is no session then the login page will load without
    # checking user authetication (to prevent a 401 status)
    Add-PodeRoute -Method Get -Path '/login' -Authentication Login -Login -ScriptBlock {
        Write-PodeViewResponse -Path 'auth-login' -FlashMessages
    }


    # login check:
    # this is the endpoint the <form>'s action will invoke. If the user validates then they are set against
    # the session as authenticated, and redirect to the home page. If they fail, then the login page reloads
    Add-PodeRoute -Method Post -Path '/login' -Authentication Login -Login


    # logout check:
    # when the logout button is click, this endpoint is invoked. The logout flag set below informs this call
    # to purge the currently authenticated session, and then redirect back to the login page
    Add-PodeRoute -Method Post -Path '/logout' -Authentication Login -Logout
}