function Start-PodeAzFuncServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    param(
        [Parameter(Mandatory = $true)]
        $Data
    )

    # setup any inbuilt middleware that works for azure functions
    $inbuilt_middleware = @(
        (Get-PodeSecurityMiddleware),
        (Get-PodeFaviconMiddleware),
        (Get-PodePublicMiddleware),
        (Get-PodeRouteValidateMiddleware),
        (Get-PodeBodyMiddleware),
        (Get-PodeCookieMiddleware)
    )

    $PodeContext.Server.Middleware = ($inbuilt_middleware + $PodeContext.Server.Middleware)

    try {
        try {
            # get the request
            $request = $Data.Request

            # setup the response
            $response = New-PodeAzFuncResponse
            $response.StatusCode = 200
            $response.Headers = @{}

            # reset event data
            $global:WebEvent = @{
                OnEnd            = @()
                Auth             = @{}
                Response         = $response
                Request          = $request
                Lockable         = $PodeContext.Threading.Lockables.Global
                Path             = [string]::Empty
                Method           = $request.Method.ToLowerInvariant()
                Query            = $request.Query
                Endpoint         = @{
                    Protocol = ($request.Url -split '://')[0]
                    Address  = $null
                    Name     = $null
                }
                ContentType      = $null
                ErrorType        = $null
                Cookies          = @{}
                PendingCookies   = @{}
                Parameters       = $null
                Data             = $null
                Files            = $null
                Streamed         = $false
                Route            = $null
                StaticContent    = $null
                Timestamp        = [datetime]::UtcNow
                TransferEncoding = $null
                AcceptEncoding   = $null
                Ranges           = $null
                Metadata         = @{}
            }

            $WebEvent.Endpoint.Address = ((Get-PodeHeader -Name 'host') -split ':')[0]
            $WebEvent.ContentType = (Get-PodeHeader -Name 'content-type')

            # set the path, using static content query parameter if passed
            if (![string]::IsNullOrWhiteSpace($request.Query['static-file'])) {
                $WebEvent.Path = $request.Query['static-file']
            }
            else {
                $funcName = $Data.sys.MethodName
                if ([string]::IsNullOrWhiteSpace($funcName)) {
                    $funcName = $Data.FunctionName
                }

                $WebEvent.Path = "/api/$($funcName)"
            }

            $WebEvent.Path = [System.Web.HttpUtility]::UrlDecode($WebEvent.Path)

            # set pode in server response header
            Set-PodeServerHeader -Type 'Kestrel'

            # invoke global and route middleware
            if ((Invoke-PodeMiddleware -Middleware $PodeContext.Server.Middleware -Route $WebEvent.Path)) {
                if ((Invoke-PodeMiddleware -Middleware $WebEvent.Route.Middleware)) {
                    # invoke the route
                    if ($null -ne $WebEvent.StaticContent) {
                        $fileBrowser = $WebEvent.Route.FileBrowser
                        if ($WebEvent.StaticContent.RedirectToDefault) {
                            $file = [System.IO.Path]::GetFileName($WebEvent.StaticContent.Source)
                            Move-PodeResponseUrl -Url "$($WebEvent.Path)/$($file)"
                        }
                        else {
                            Write-PodeFileResponseInternal -FileInfo $WebEvent.StaticContent.FileInfo `
                                -FileBrowser:$fileBrowser -Download:$WebEvent.StaticContent.IsDownload
                        }
                    }
                    else {
                        $null = Invoke-PodeScriptBlock -ScriptBlock $WebEvent.Route.Logic -Arguments $WebEvent.Route.Arguments -UsingVariables $WebEvent.Route.UsingVariables -Scoped -Splat
                    }
                }
            }
        }
        catch {
            $_ | Write-PodeErrorLog
            $_.Exception | Write-PodeErrorLog -CheckInnerException
            Set-PodeResponseStatus -Code 500 -Exception $_
        }
        finally {
            Update-PodeServerRequestMetric -WebEvent $WebEvent
        }

        # invoke endware specifc to the current web event
        $_endware = ($WebEvent.OnEnd + @($PodeContext.Server.Endware))
        Invoke-PodeEndware -Endware $_endware

        # close and send the response
        Push-OutputBinding -Name Response -Value $response
    }
    catch {
        $_ | Write-PodeErrorLog
        throw $_.Exception
    }
}

function New-PodeAzFuncResponse {
    return [HttpResponseContext]::new()
}

function Start-PodeAwsLambdaServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    param(
        [Parameter(Mandatory = $true)]
        $Data
    )

    # setup any inbuilt middleware that works for aws lambda
    $inbuilt_middleware = @(
        (Get-PodeSecurityMiddleware),
        (Get-PodeFaviconMiddleware),
        (Get-PodePublicMiddleware),
        (Get-PodeRouteValidateMiddleware),
        (Get-PodeBodyMiddleware),
        (Get-PodeCookieMiddleware)
    )

    $PodeContext.Server.Middleware = ($inbuilt_middleware + $PodeContext.Server.Middleware)

    try {
        try {
            # get the request
            $request = $Data

            # setup the response
            $response = @{
                StatusCode = 200
                Headers    = @{}
                Body       = [string]::Empty
            }

            # reset event data
            $global:WebEvent = @{
                OnEnd            = @()
                Auth             = @{}
                Response         = $response
                Request          = $request
                Lockable         = $PodeContext.Threading.Lockables.Global
                Path             = [System.Web.HttpUtility]::UrlDecode($request.path)
                Method           = $request.httpMethod.ToLowerInvariant()
                Query            = $request.queryStringParameters
                Endpoint         = @{
                    Protocol = $null
                    Address  = $null
                    Name     = $null
                }
                ContentType      = $null
                ErrorType        = $null
                Cookies          = @{}
                PendingCookies   = @{}
                Parameters       = $null
                Data             = $null
                Files            = $null
                Streamed         = $false
                Route            = $null
                StaticContent    = $null
                Timestamp        = [datetime]::UtcNow
                TransferEncoding = $null
                AcceptEncoding   = $null
                Ranges           = $null
                Metadata         = @{}
            }

            $WebEvent.Endpoint.Protocol = (Get-PodeHeader -Name 'X-Forwarded-Proto')
            $WebEvent.Endpoint.Address = ((Get-PodeHeader -Name 'Host') -split ':')[0]
            $WebEvent.ContentType = (Get-PodeHeader -Name 'Content-Type')

            # set pode in server response header
            Set-PodeServerHeader -Type 'Lambda'

            # invoke global and route middleware
            if ((Invoke-PodeMiddleware -Middleware $PodeContext.Server.Middleware -Route $WebEvent.Path)) {
                if ((Invoke-PodeMiddleware -Middleware $WebEvent.Route.Middleware)) {
                    # invoke the route
                    if ($null -ne $WebEvent.StaticContent) {
                        $fileBrowser = $WebEvent.Route.FileBrowser
                        if ($WebEvent.StaticContent.RedirectToDefault) {
                            $file = [System.IO.Path]::GetFileName($WebEvent.StaticContent.Source)
                            Move-PodeResponseUrl -Url "$($WebEvent.Path)/$($file)"
                        }
                        else {
                            Write-PodeFileResponseInternal -FileInfo $WebEvent.StaticContent.FileInfo `
                                -FileBrowser:$fileBrowser -Download:$WebEvent.StaticContent.IsDownload
                        }
                    }
                    else {
                        $null = Invoke-PodeScriptBlock -ScriptBlock $WebEvent.Route.Logic -Arguments $WebEvent.Route.Arguments -UsingVariables $WebEvent.Route.UsingVariables -Scoped -Splat
                    }
                }
            }
        }
        catch {
            $_ | Write-PodeErrorLog
            $_.Exception | Write-PodeErrorLog -CheckInnerException
            Set-PodeResponseStatus -Code 500 -Exception $_
        }
        finally {
            Update-PodeServerRequestMetric -WebEvent $WebEvent
        }

        # invoke endware specifc to the current web event
        $_endware = ($WebEvent.OnEnd + @($PodeContext.Server.Endware))
        Invoke-PodeEndware -Endware $_endware

        # close and send the response
        if (![string]::IsNullOrWhiteSpace($response.ContentType)) {
            Set-PodeHeader -Name 'Content-Type' -Value $response.ContentType
        }

        return (@{
                'statusCode' = $response.StatusCode
                'headers'    = $response.Headers
                'body'       = $response.Body
            } | ConvertTo-Json -Depth 10 -Compress)
    }
    catch {
        $_ | Write-PodeErrorLog
        throw $_.Exception
    }
}