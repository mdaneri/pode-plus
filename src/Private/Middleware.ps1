using namespace System.Security.Cryptography

function Invoke-PodeMiddleware {
    param(
        [Parameter()]
        $Middleware,

        [Parameter()]
        [string]
        $Route
    )

    # if there's no middleware, do nothing
    if (($null -eq $Middleware) -or ($Middleware.Length -eq 0)) {
        return $true
    }

    # filter the middleware down by route (retaining order)
    if (![string]::IsNullOrWhiteSpace($Route)) {
        $Middleware = @(foreach ($mware in $Middleware) {
                if ($null -eq $mware) {
                    continue
                }

                if ([string]::IsNullOrWhiteSpace($mware.Route) -or ($mware.Route -ieq '/') -or ($mware.Route -ieq $Route) -or ($Route -imatch "^$($mware.Route)$")) {
                    $mware
                }
            })
    }

    # continue or halt?
    $continue = $true

    # loop through each of the middleware, invoking the next if it returns true
    foreach ($midware in @($Middleware)) {
        if (($null -eq $midware) -or ($null -eq $midware.Logic)) {
            continue
        }

        try {
            $continue = Invoke-PodeScriptBlock -ScriptBlock $midware.Logic -Arguments $midware.Arguments -UsingVariables $midware.UsingVariables -Return -Scoped -Splat
            if ($null -eq $continue) {
                $continue = $true
            }
        }
        catch {
            Set-PodeResponseStatus -Code 500 -Exception $_
            $continue = $false
            $_ | Write-PodeErrorLog
        }

        if (!$continue) {
            break
        }
    }

    return $continue
}

function New-PodeMiddlewareInternal {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock,

        [Parameter()]
        [string]
        $Route,

        [Parameter()]
        [object[]]
        $ArgumentList,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.SessionState]
        $PSSession
    )

    if (Test-PodeIsEmpty $ScriptBlock) {
        # No ScriptBlock supplied
        throw ($PodeLocale.noScriptBlockSuppliedExceptionMessage)
    }

    # if route is empty, set it to root
    $Route = ConvertTo-PodeRouteRegex -Path $Route

    # check for scoped vars
    $ScriptBlock, $usingVars = Convert-PodeScopedVariables -ScriptBlock $ScriptBlock -PSSession $PSSession

    # create the middleware hashtable from a scriptblock
    $HashTable = @{
        Route          = $Route
        Logic          = $ScriptBlock
        Arguments      = $ArgumentList
        UsingVariables = $usingVars
    }

    # return the middleware, so it can be cached/added at a later date
    return $HashTable
}

function Get-PodeInbuiltMiddleware {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [scriptblock]
        $ScriptBlock
    )

    # check if middleware contains an override
    $override = ($PodeContext.Server.Middleware | Where-Object { $_.Name -ieq $Name })

    # if override there, remove it from middleware
    if ($override) {
        $PodeContext.Server.Middleware = @($PodeContext.Server.Middleware | Where-Object { $_.Name -ine $Name })
        $ScriptBlock = $override.Logic
    }

    # return the script
    return @{
        Name  = $Name
        Logic = $ScriptBlock
    }
}

function Get-PodeAccessMiddleware {
    return (Get-PodeInbuiltMiddleware -Name '__pode_mw_access__' -ScriptBlock {
            $result = Invoke-PodeLimitAccessRuleRequest
            if ($null -eq $result) {
                return $true
            }

            Set-PodeResponseStatus -Code $result.StatusCode
            return $false
        })
}

<#
.SYNOPSIS
Retrieves the rate limit middleware for Pode.

.DESCRIPTION
This function returns the inbuilt rate limit middleware for Pode.
It checks if the request IP address, route, and endpoint have hit their respective rate limits.
If any of these checks fail, a 429 status code is set, and the request is denied.

.EXAMPLE
Get-PodeLimitMiddleware
Retrieves the rate limit middleware and adds it to the middleware pipeline.

.RETURNS
[ScriptBlock] - Returns a script block that represents the rate limit middleware.

.NOTES
This is an internal function and may change in future releases of Pode.
#>
function Get-PodeLimitMiddleware {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return (Get-PodeInbuiltMiddleware -Name '__pode_mw_rate_limit__' -ScriptBlock {
            $result = Invoke-PodeLimitRateRuleRequest
            if ($null -eq $result) {
                return $true
            }

            Set-PodeHeader -Name 'Retry-After' -Value $result.RetryAfter
            Set-PodeResponseStatus -Code $result.StatusCode
            return $false
        })
}

<#
.SYNOPSIS
    Retrieves middleware for serving public static content in a Pode web server.
.DESCRIPTION
    This function retrieves middleware for serving public static content in a Pode web server.
    It searches for static content based on the requested path and serves it if found.
.PARAMETER WebEvent
    The PodeWebEvent object representing the incoming web request.
.PARAMETER PodeContext
    The PodeContext object representing the current Pode server context.
.EXAMPLE
    Get-PodePublicMiddleware
    Retrieves middleware for serving public static content.
#>
function Get-PodePublicMiddleware {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return (Get-PodeInbuiltMiddleware -Name '__pode_mw_static_content__' -ScriptBlock {
            # only find public static content here
            $pubRoute = Find-PodePublicRoute -Path $WebEvent.Path
            if ($null -eq $pubRoute) {
                return $true
            }

            # write the file to the response
            Write-PodeFileResponseInternal -FileInfo $pubRoute.FileInfo
            # public static content found, stop
            return $false
        })
}

<#
.SYNOPSIS
    Middleware function to validate the route for an incoming web request.

.DESCRIPTION
    This function is used as middleware to validate the route for an incoming web request. It checks if the route exists for the requested method and path. If the route does not exist, it sets the appropriate response status code (404 for not found, 405 for method not allowed) and returns false to halt further processing. If the route exists, it sets various properties on the WebEvent object, such as parameters, content type, and transfer encoding, and returns true to continue processing.

.PARAMETER None

.EXAMPLE
    $middleware = Get-PodeRouteValidateMiddleware
    Add-PodeMiddleware -Middleware $middleware

.NOTES
    This function is part of the internal Pode server logic and is typically not called directly by users.

#>
function Get-PodeRouteValidateMiddleware {
    return @{
        Name  = '__pode_mw_route_validation__'
        Logic = {
            if ($PodeContext.Server.Web.Static.ValidateLast) {
                #  check the main routes and check the static routes
                $route = Find-PodeRoute -Method $WebEvent.Method -Path $WebEvent.Path -EndpointName $WebEvent.Endpoint.Name -CheckWildMethod
                if ($null -eq $route) {
                    $route = Find-PodeStaticRoute -Path $WebEvent.Path -EndpointName $WebEvent.Endpoint.Name
                }
            }
            else {
                # check if the path is static route first, then check the main routes
                $route = Find-PodeStaticRoute -Path $WebEvent.Path -EndpointName $WebEvent.Endpoint.Name
                if ($null -eq $route) {
                    $route = Find-PodeRoute -Method $WebEvent.Method -Path $WebEvent.Path -EndpointName $WebEvent.Endpoint.Name -CheckWildMethod
                }
            }

            # if there's no route defined, it's a 404 - or a 405 if a route exists for any other method
            if ($null -eq $route) {
                # check if a route exists for another method
                $methods = @('CONNECT', 'DELETE', 'GET', 'HEAD', 'MERGE', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE')
                $diff_route = @(foreach ($method in $methods) {
                        $r = Find-PodeRoute -Method $method -Path $WebEvent.Path -EndpointName $WebEvent.Endpoint.Name
                        if ($null -ne $r) {
                            $r
                            break
                        }
                    })[0]

                if ($null -ne $diff_route) {
                    Set-PodeResponseStatus -Code 405
                    return $false
                }

                # otherwise, it's a 404
                Set-PodeResponseStatus -Code 404
                return $false
            }

            # check if static and split
            if ($null -ne $route.Content) {
                $WebEvent.StaticContent = $route.Content
                $route = $route.Route
            }

            # set the route parameters
            $WebEvent.Parameters = @{}
            if ($WebEvent.Path -imatch "$($route.Path)$") {
                $WebEvent.Parameters = $Matches
            }

            # set the route on the WebEvent
            $WebEvent.Route = $route

            # override the content type from the route if it's not empty
            if (![string]::IsNullOrEmpty($route.ContentType)) {
                $WebEvent.ContentType = $route.ContentType
            }

            # override the transfer encoding from the route if it's not empty
            if (![string]::IsNullOrEmpty($route.TransferEncoding)) {
                $WebEvent.TransferEncoding = $route.TransferEncoding
            }

            $WebEvent.AcceptEncoding = (Resolve-PodeCompressionEncoding -AcceptEncoding (Get-PodeHeader -Name 'Accept-Encoding') -Route $WebEvent.Route -ThrowError)
            $WebEvent.ContentEncoding = (Resolve-PodeCompressionEncoding -ContentEncoding (Get-PodeHeader -Name 'Content-Encoding') -Route $WebEvent.Route -ThrowError)
            $WebEvent.Ranges = (Get-PodeRange -Range (Get-PodeHeader -Name 'Range') -ThrowError)
            # set the content type for any pages for the route if it's not empty
            $WebEvent.ErrorType = $route.ErrorType

            # route exists
            return $true
        }
    }
}

function Get-PodeBodyMiddleware {
    return (Get-PodeInbuiltMiddleware -Name '__pode_mw_body_parsing__' -ScriptBlock {
            try {
                # attempt to parse that data
                $result = ConvertFrom-PodeRequestContent -Request $WebEvent.Request -ContentType $WebEvent.ContentType -TransferEncoding $WebEvent.TransferEncoding -ContentEncoding $WebEvent.ContentEncoding

                # set session data
                $WebEvent.Data = $result.Data
                $WebEvent.Files = $result.Files
                # if the body is compressed, replace it with the decompressed body
                if ($null -ne $Result.decompressedBody) {
                    $WebEvent.Raw.Body = $result.decompressedBody
                }
                # payload parsed
                return $true
            }
            catch {
                $_ | write-PodeErrorLog -Level Verbose
                Set-PodeResponseStatus -Code 400 -Exception $_
                return $false
            }
        })
}

function Get-PodeQueryMiddleware {
    return (Get-PodeInbuiltMiddleware -Name '__pode_mw_query_parsing__' -ScriptBlock {
            try {
                # set the query string from the request
                $WebEvent.Query = (ConvertFrom-PodeNameValueToHashTable -Collection $WebEvent.Request.QueryString)
                return $true
            }
            catch {
                Set-PodeResponseStatus -Code 400 -Exception $_
                return $false
            }
        })
}

function Get-PodeCookieMiddleware {
    return (Get-PodeInbuiltMiddleware -Name '__pode_mw_cookie_parsing__' -ScriptBlock {
            # if cookies already set, return
            if ($WebEvent.Cookies.Count -gt 0) {
                return $true
            }

            # if the request's header has no cookies, return
            $h_cookie = (Get-PodeHeader -Name 'Cookie')
            if ([string]::IsNullOrWhiteSpace($h_cookie)) {
                return $true
            }

            # parse the cookies from the header
            $cookies = @($h_cookie -split '; ')
            $WebEvent.Cookies = @{}

            foreach ($cookie in $cookies) {
                $atoms = $cookie.Split('=', 2)

                $value = [string]::Empty
                if ($atoms.Length -gt 1) {
                    foreach ($atom in $atoms[1..($atoms.Length - 1)]) {
                        $value += $atom
                    }
                }

                $WebEvent.Cookies[$atoms[0]] = [System.Net.Cookie]::new($atoms[0], $value)
            }

            return $true
        })
}

function Get-PodeSecurityMiddleware {
    return (Get-PodeInbuiltMiddleware -Name '__pode_mw_security__' -ScriptBlock {
            # are there any security headers setup?
            if ($PodeContext.Server.Security.Headers.Count -eq 0) {
                return $true
            }

            # add security headers
            Set-PodeHeaderBulk -Value $PodeContext.Server.Security.Headers

            # continue to next middleware/route
            return $true
        })
}

function Initialize-PodeIISMiddleware {
    # do nothing if not iis
    if (!$PodeContext.Server.IsIIS) {
        return
    }

    # fail if no iis token - because there should be!
    if ([string]::IsNullOrEmpty($PodeContext.Server.IIS.Token)) {
        # IIS ASPNETCORE_TOKEN is missing
        throw ($PodeLocale.iisAspnetcoreTokenMissingExceptionMessage)
    }

    # add middleware to check every request has the token
    Add-PodeMiddleware -Name '__pode_iis_token_check__' -ScriptBlock {
        $token = Get-PodeHeader -Name 'MS-ASPNETCORE-TOKEN'
        if ($token -ne $PodeContext.Server.IIS.Token) {
            Set-PodeResponseStatus -Code 400 -Description 'MS-ASPNETCORE-TOKEN header missing'
            return $false
        }

        return $true
    }

    # add middleware to check if there's a client cert
    Add-PodeMiddleware -Name '__pode_iis_clientcert_check__' -ScriptBlock {
        if (!$WebEvent.Request.AllowClientCertificate -or ($null -ne $WebEvent.Request.ClientCertificate)) {
            return $true
        }

        $headers = @('MS-ASPNETCORE-CLIENTCERT', 'X-ARR-ClientCert')
        foreach ($header in $headers) {
            if (!(Test-PodeHeader -Name $header)) {
                continue
            }

            try {
                $value = Get-PodeHeader -Name $header
                $WebEvent.Request.ClientCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($value))
            }
            catch {
                $WebEvent.Request.ClientCertificateErrors = [System.Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable
            }
        }

        return $true
    }

    # add route to gracefully shutdown server for iis
    Add-PodeRoute -Method Post -Path '/iisintegration' -ScriptBlock {
        $eventType = Get-PodeHeader -Name 'MS-ASPNETCORE-EVENT'

        # no x-forward
        if (Test-PodeHeader -Name 'X-Forwarded-For') {
            Set-PodeResponseStatus -Code 400
            return
        }

        # no user-agent
        if (Test-PodeHeader -Name 'User-Agent') {
            Set-PodeResponseStatus -Code 400
            return
        }

        # valid local Host
        $hostValue = Get-PodeHeader -Name 'Host'
        if ($hostValue -ine "127.0.0.1:$($PodeContext.Server.IIS.Port)") {
            Set-PodeResponseStatus -Code 400
            return
        }

        # no content-length
        if ($WebEvent.Request.ContentLength -gt 0) {
            Set-PodeResponseStatus -Code 400
            return
        }

        # valid event type
        if ($eventType -ine 'shutdown') {
            Set-PodeResponseStatus -Code 400
            return
        }

        # shutdown
        $PodeContext.Server.IIS.Shutdown = $true
        Close-PodeServer
        Set-PodeResponseStatus -Code 202
    }
}


<#
.SYNOPSIS
	Returns a Pode middleware scriptblock for handling requests to the /favicon.ico path.

.DESCRIPTION
	This function returns a middleware delegate that intercepts GET requests to `/favicon.ico`.
	If a favicon is defined for the current endpoint, it returns the favicon file directly in the response
	with the appropriate content type and a 200 OK status.

	If the request is not for a favicon, the request is passed to the next middleware.

.PARAMETER None
	This function takes no parameters.

.OUTPUTS
	ScriptBlock
	Returns a Pode-compatible middleware scriptblock.

.EXAMPLE
	$middleware = Get-PodeFaviconMiddleware
	Add-PodeMiddleware -Middleware $middleware

.NOTES
	This is an internal Pode middleware function and may be subject to change.
#>
function Get-PodeFaviconMiddleware {
    return (Get-PodeInbuiltMiddleware -Name '__pode_mw_favicon__' -ScriptBlock {
            if (($WebEvent.Path -eq '/favicon.ico') -and ($WebEvent.Method -eq 'GET') -and ($null -ne $PodeContext.Server.Endpoints[$context.EndpointName].Favicon)) {
                # Write the file content as the HTTP response
                Write-PodeTextResponse -Bytes $PodeContext.Server.Endpoints[$context.EndpointName].Favicon.Bytes -ContentType $PodeContext.Server.Endpoints[$context.EndpointName].Favicon.ContentType -StatusCode 200
                return $false
            }

            return $true
        })
}