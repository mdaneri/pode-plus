using namespace Pode

function Start-PodeWebServer {
    param(
        [switch]
        $Browse
    )

    # setup any inbuilt middleware
    $inbuilt_middleware = @(
        (Get-PodeLimitMiddleware),
        (Get-PodeSecurityMiddleware),
        (Get-PodeFaviconMiddleware),
        (Get-PodeAccessMiddleware),
        (Get-PodePublicMiddleware),
        (Get-PodeRouteValidateMiddleware),
        (Get-PodeBodyMiddleware),
        (Get-PodeQueryMiddleware),
        (Get-PodeCookieMiddleware)
    )

    $PodeContext.Server.Middleware = ($inbuilt_middleware + $PodeContext.Server.Middleware)

    # work out which endpoints to listen on
    $endpoints = @()
    $endpointsMap = @{}

    # Variable to track if a default endpoint is already defined for the current type.
    # This ensures that only one default endpoint can be assigned per protocol type (e.g., HTTP, HTTPS).
    # If multiple default endpoints are detected, an error will be thrown to prevent configuration issues.
    $defaultEndpoint = $false

    @(Get-PodeEndpointByProtocolType -Type Http, Ws) | ForEach-Object {

        # Enforce unicity: only one default endpoint is allowed per type.
        if ($defaultEndpoint -and $_.Default) {
            # A default endpoint for the type '{0}' is already set. Only one default endpoint is allowed per type. Please check your configuration.
            throw ($Podelocale.defaultEndpointAlreadySetExceptionMessage -f $($_.Type))
        }
        else {
            # Assign the current endpoint's Default value for tracking.
            $defaultEndpoint = $_.Default
        }

        # get the ip address
        $_ip = [string]($_.Address)
        $_ip = Get-PodeIPAddressesForHostname -Hostname $_ip -Type All | Select-Object -First 1
        $_ip = Get-PodeIPAddress -IP $_ip -DualMode:($_.DualMode)

        # dual mode?
        $addrs = $_ip
        if ($_.DualMode) {
            $addrs = Resolve-PodeIPDualMode -IP $_ip
        }

        # the endpoint
        $_endpoint = @{
            Name                   = $_.Name
            Key                    = "$($_ip):$($_.Port)"
            Address                = $addrs
            Hostname               = $_.HostName
            IsIPAddress            = $_.IsIPAddress
            Port                   = $_.Port
            Certificate            = $_.Certificate.Raw
            AllowClientCertificate = $_.Certificate.AllowClientCertificate
            Url                    = $_.Url
            Protocol               = $_.Protocol
            Type                   = $_.Type
            Pool                   = $_.Runspace.PoolName
            SslProtocols           = $_.Ssl.Protocols
            DualMode               = $_.DualMode
            Default                = $_.Default
        }

        # add endpoint to list
        $endpoints += $_endpoint

        # add to map
        if (!$endpointsMap.ContainsKey($_endpoint.Key)) {
            $endpointsMap[$_endpoint.Key] = @{ Type = $_.Type }
        }
        else {
            if ($endpointsMap[$_endpoint.Key].Type -ine $_.Type) {
                $endpointsMap[$_endpoint.Key].Type = 'HttpAndWs'
            }
        }
    }

    # Create the listener
    $listener = & $("New-Pode$($PodeContext.Server.ListenerType)Listener") -CancellationToken $PodeContext.Tokens.Cancellation.Token
    $listener.ErrorLoggingEnabled = (Test-PodeErrorLoggingEnabled)
    $listener.ErrorLoggingLevels = @(Get-PodeErrorLoggingLevel)
    $listener.RequestTimeout = $PodeContext.Server.Request.Timeout
    $listener.RequestBodySize = $PodeContext.Server.Request.BodySize
    $listener.ShowServerDetails = [bool]$PodeContext.Server.Security.ServerDetails

    try {
        # register endpoints on the listener
        $endpoints | ForEach-Object {
            # Create a hashtable of parameters for splatting
            $socketParams = @{
                Name                   = $_.Name
                Address                = $_.Address
                Port                   = $_.Port
                SslProtocols           = $_.SslProtocols
                Type                   = $endpointsMap[$_.Key].Type
                Certificate            = $_.Certificate
                AllowClientCertificate = $_.AllowClientCertificate
                DualMode               = $_.DualMode
            }

            # Initialize a new listener socket with splatting
            $socket = & $("New-Pode$($PodeContext.Server.ListenerType)ListenerSocket") @socketParams
            $socket.ReceiveTimeout = $PodeContext.Server.Sockets.ReceiveTimeout

            if (!$_.IsIPAddress) {
                $socket.Hostnames.Add($_.HostName)
            }

            $listener.Add($socket)
        }

        $listener.Start()
        $PodeContext.Listeners += $listener
        $PodeContext.Server.Signals.Enabled = $true
        $PodeContext.Server.Signals.Listener = $listener
        $PodeContext.Server.Http.Listener = $listener
    }
    catch {
        $_ | Write-PodeErrorLog
        $_.Exception | Write-PodeErrorLog -CheckInnerException
        Close-PodeDisposable -Disposable $listener
        throw $_.Exception
    }

    # only if HTTP endpoint
    if (Test-PodeEndpointByProtocolType -Type Http) {
        # script for listening out for incoming requests
        $listenScript = {
            param(
                [Parameter(Mandatory = $true)]
                $Listener,

                [Parameter(Mandatory = $true)]
                [int]
                $ThreadId
            )
            # Waits for the Pode server to fully start before proceeding with further operations.
            Wait-PodeCancellationTokenRequest -Type Start
            do {
                try {
                    while ($Listener.IsConnected -and !(Test-PodeCancellationTokenRequest -Type Terminate)) {
                        # get request and response
                        $context = (Wait-PodeTask -Task $Listener.GetContextAsync($PodeContext.Tokens.Cancellation.Token))

                        try {
                            try {
                                $Request = $context.Request
                                $Response = $context.Response

                                # reset with basic event data
                                $WebEvent = @{
                                    OnEnd            = @()
                                    Auth             = @{}
                                    Response         = $Response
                                    Request          = $Request
                                    Lockable         = $PodeContext.Threading.Lockables.Global
                                    Path             = [System.Web.HttpUtility]::UrlDecode($Request.Url.AbsolutePath)
                                    Method           = $Request.HttpMethod.ToLowerInvariant()
                                    Query            = $null
                                    Raw              = @{
                                        Query   = $Request.Url.Query
                                        Headers = $Request.Headers
                                        Body    = $Request.Body
                                    }
                                    Endpoint         = @{
                                        Protocol = $Request.Url.Scheme
                                        Address  = $Request.Host
                                        Name     = $context.EndpointName
                                    }
                                    ContentType      = $Request.ContentType
                                    ErrorType        = $null
                                    Cookies          = @{}
                                    PendingCookies   = @{}
                                    Parameters       = $null
                                    Data             = $null
                                    Files            = $null
                                    Streamed         = $true
                                    Route            = $null
                                    StaticContent    = $null
                                    Timestamp        = [datetime]::UtcNow
                                    TransferEncoding = $null
                                    AcceptEncoding   = $null
                                    ContentEncoding  = $null
                                    Ranges           = $null
                                    Sse              = $null
                                    Metadata         = @{}
                                    Async            = $false
                                    Cache            = $null
                                }

                                # if iis, and we have an app path, alter it
                                if ($PodeContext.Server.IsIIS -and $PodeContext.Server.IIS.Path.IsNonRoot) {
                                    $WebEvent.Path = ($WebEvent.Path -ireplace $PodeContext.Server.IIS.Path.Pattern, '')
                                    if ([string]::IsNullOrEmpty($WebEvent.Path)) {
                                        $WebEvent.Path = '/'
                                    }
                                }

                                $WebEvent.TransferEncoding = (Get-PodeTransferEncoding -TransferEncoding (Get-PodeHeader -Name 'Transfer-Encoding') -ThrowError)

                                # add logging endware for post-request
                                Add-PodeRequestLogEndware -WebEvent $WebEvent

                                # stop now if the request has an error
                                if ($Request.IsAborted) {
                                    throw $Request.Error
                                }

                                # if we have an sse clientId, verify it and then set details in WebEvent
                                if ($WebEvent.Request.HasSseClientId) {
                                    if (!(Test-PodeSseClientIdValid)) {
                                        throw [Pode.PodeRequestException]::new("The X-PODE-SSE-CLIENT-ID value is not valid: $($WebEvent.Request.SseClientId)")
                                    }

                                    if (![string]::IsNullOrEmpty($WebEvent.Request.SseClientName) -and !(Test-PodeSseClientId -Name $WebEvent.Request.SseClientName -ClientId $WebEvent.Request.SseClientId)) {
                                        throw [Pode.PodeRequestException]::new("The SSE Connection being referenced via the X-PODE-SSE-NAME and X-PODE-SSE-CLIENT-ID headers does not exist: [$($WebEvent.Request.SseClientName)] $($WebEvent.Request.SseClientId)", 404)
                                    }

                                    $WebEvent.Sse = @{
                                        Name        = $WebEvent.Request.SseClientName
                                        Group       = $WebEvent.Request.SseClientGroup
                                        ClientId    = $WebEvent.Request.SseClientId
                                        LastEventId = $null
                                        IsLocal     = $false
                                    }
                                }

                                # invoke global and route middleware
                                if ((Invoke-PodeMiddleware -Middleware $PodeContext.Server.Middleware -Route $WebEvent.Path)) {
                                    # has the request been aborted
                                    if ($Request.IsAborted) {
                                        throw $Request.Error
                                    }

                                  if ($null -ne $WebEvent.Route) {
                                        # set the cache settings for the web event
                                        $WebEvent.Cache = $WebEvent.Route.Cache
                                    }

                                    if ((Invoke-PodeMiddleware -Middleware $WebEvent.Route.Middleware)) {
                                        # has the request been aborted
                                        if ($Request.IsAborted) {
                                            throw $Request.Error
                                        }

                                        # invoke the route
                                        if ($null -ne $WebEvent.StaticContent) {
                                            if ( ('Get', 'Head') -contains $WebEvent.Method) {
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
                                                Set-PodeResponseStatus -Code 404
                                            }
                                        }
                                        elseif ($null -ne $WebEvent.Route.Logic) {
                                            $null = Invoke-PodeScriptBlock -ScriptBlock $WebEvent.Route.Logic -Arguments $WebEvent.Route.Arguments -UsingVariables $WebEvent.Route.UsingVariables -Scoped -Splat
                                        }
                                    }
                                }
                            }
                            catch [System.OperationCanceledException] {
                                $_ | Write-PodeErrorLog -Level Debug
                            }
                            catch [Pode.PodeRequestException] {
                                if ($Response.StatusCode -ge 500) {
                                    $_.Exception | Write-PodeErrorLog -CheckInnerException
                                }

                                $code = $_.Exception.StatusCode
                                if ($code -le 0) {
                                    $code = 400
                                }

                                Set-PodeResponseStatus -Code $code -Exception $_
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
                        }
                        finally {
                            $WebEvent = $null
                            Close-PodeDisposable -Disposable $context
                        }
                    }
                }
                catch [System.OperationCanceledException] {
                    $_ | Write-PodeErrorLog -Level Debug
                }
                catch {
                    $_ | Write-PodeErrorLog
                    $_.Exception | Write-PodeErrorLog -CheckInnerException
                    throw $_.Exception
                }

                # end do-while
            } while (Test-PodeSuspensionToken) # Check for suspension token and wait for the debugger to reset if active

        }

        # start the runspace for listening on x-number of threads
        1..$PodeContext.Threads.General | ForEach-Object {
            Add-PodeRunspace -Type Web -Name 'Listener' -ScriptBlock $listenScript -Parameters @{ 'Listener' = $listener; 'ThreadId' = $_ }
        }
    }

    # only if WS endpoint
    if (Test-PodeEndpointByProtocolType -Type Ws) {
        # script to write messages back to the client(s)
        $signalScript = {
            param(
                [Parameter(Mandatory = $true)]
                $Listener
            )
            # Waits for the Pode server to fully start before proceeding with further operations.
            Wait-PodeCancellationTokenRequest -Type Start

            do {
                try {
                    while ($Listener.IsConnected -and !(Test-PodeCancellationTokenRequest -Type Terminate)) {
                        $message = (Wait-PodeTask -Task $Listener.GetServerSignalAsync($PodeContext.Tokens.Cancellation.Token))

                        try {
                            # get the sockets for the message
                            $sockets = @()

                            # by clientId
                            if (![string]::IsNullOrWhiteSpace($message.ClientId)) {
                                $sockets = @($Listener.Signals[$message.ClientId])
                            }
                            else {
                                $sockets = @($Listener.Signals.Values)

                                # by path
                                if (![string]::IsNullOrWhiteSpace($message.Path)) {
                                    $sockets = @(foreach ($socket in $sockets) {
                                            if ($socket.Path -ieq $message.Path) {
                                                $socket
                                            }
                                        })
                                }
                            }

                            # do nothing if no socket found
                            if (($null -eq $sockets) -or ($sockets.Length -eq 0)) {
                                continue
                            }

                            # send the message to all found sockets
                            foreach ($socket in $sockets) {
                                try {
                                    $null = Wait-PodeTask -Task $socket.Context.Response.SendSignal($message)
                                }
                                catch {
                                    $null = $Listener.Signals.Remove($socket.ClientId)
                                }
                            }
                        }
                        catch [System.OperationCanceledException] {
                            $_ | Write-PodeErrorLog -Level Debug
                        }
                        catch {
                            $_ | Write-PodeErrorLog
                            $_.Exception | Write-PodeErrorLog -CheckInnerException
                        }
                        finally {
                            Close-PodeDisposable -Disposable $message
                        }
                    }
                }
                catch [System.OperationCanceledException] {
                    $_ | Write-PodeErrorLog -Level Debug
                }
                catch {
                    $_ | Write-PodeErrorLog
                    $_.Exception | Write-PodeErrorLog -CheckInnerException
                    throw $_.Exception
                }

                # end do-while
            } while (Test-PodeSuspensionToken) # Check for suspension token and wait for the debugger to reset if active

        }

        Add-PodeRunspace -Type Signals -Name 'Listener' -ScriptBlock $signalScript -Parameters @{ 'Listener' = $listener }
    }

    # only if WS endpoint
    if (Test-PodeEndpointByProtocolType -Type Ws) {
        # script to queue messages from clients to send back to other clients from the server
        $clientScript = {
            param(
                [Parameter(Mandatory = $true)]
                $Listener,

                [Parameter(Mandatory = $true)]
                [int]
                $ThreadId
            )

            # Waits for the Pode server to fully start before proceeding with further operations.
            Wait-PodeCancellationTokenRequest -Type Start

            do {
                try {
                    while ($Listener.IsConnected -and !(Test-PodeCancellationTokenRequest -Type Terminate)) {
                        $context = (Wait-PodeTask -Task $Listener.GetClientSignalAsync($PodeContext.Tokens.Cancellation.Token))

                        try {
                            $payload = ($context.Message | ConvertFrom-Json)
                            $Request = $context.Signal.Context.Request
                            $Response = $context.Signal.Context.Response

                            $SignalEvent = @{
                                Response  = $Response
                                Request   = $Request
                                Lockable  = $PodeContext.Threading.Lockables.Global
                                Path      = [System.Web.HttpUtility]::UrlDecode($Request.Url.AbsolutePath)
                                Data      = @{
                                    Path     = [System.Web.HttpUtility]::UrlDecode($payload.path)
                                    Message  = $payload.message
                                    ClientId = $payload.clientId
                                    Direct   = [bool]$payload.direct
                                }
                                Endpoint  = @{
                                    Protocol = $Request.Url.Scheme
                                    Address  = $Request.Host
                                    Name     = $context.Signal.Context.EndpointName
                                }
                                Route     = $null
                                ClientId  = $context.Signal.ClientId
                                Timestamp = $context.Timestamp
                                Streamed  = $true
                                Metadata  = @{}
                            }

                            # see if we have a route and invoke it, otherwise auto-send
                            $SignalEvent.Route = Find-PodeSignalRoute -Path $SignalEvent.Path -EndpointName $SignalEvent.Endpoint.Name

                            if ($null -ne $SignalEvent.Route) {
                                $null = Invoke-PodeScriptBlock -ScriptBlock $SignalEvent.Route.Logic -Arguments $SignalEvent.Route.Arguments -UsingVariables $SignalEvent.Route.UsingVariables -Scoped -Splat
                            }
                            else {
                                Send-PodeSignal -Value $SignalEvent.Data.Message -Path $SignalEvent.Data.Path -ClientId $SignalEvent.Data.ClientId
                            }
                        }
                        catch [System.OperationCanceledException] {
                            $_ | Write-PodeErrorLog -Level Debug
                        }
                        catch {
                            $_ | Write-PodeErrorLog
                            $_.Exception | Write-PodeErrorLog -CheckInnerException
                        }
                        finally {
                            Update-PodeServerSignalMetric -SignalEvent $SignalEvent
                            Close-PodeDisposable -Disposable $context
                        }
                    }
                }
                catch [System.OperationCanceledException] {
                    $_ | Write-PodeErrorLog -Level Debug
                }
                catch {
                    $_ | Write-PodeErrorLog
                    $_.Exception | Write-PodeErrorLog -CheckInnerException
                    throw $_.Exception
                }

                # end do-while
            } while (Test-PodeSuspensionToken) # Check for suspension token and wait for the debugger to reset if active

        }

        # start the runspace for listening on x-number of threads
        1..$PodeContext.Threads.General | ForEach-Object {
            Add-PodeRunspace -Type Signals -Name 'Broadcaster' -ScriptBlock $clientScript -Parameters @{ 'Listener' = $listener; 'ThreadId' = $_ }
        }
    }

    # script to keep web server listening until cancelled
    $waitScript = {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNull()]
            $Listener
        )

        try {
            while ($Listener.IsConnected -and !(Test-PodeCancellationTokenRequest -Type Terminate)) {
                Start-Sleep -Seconds 1
            }
        }
        catch [System.OperationCanceledException] {
            $_ | Write-PodeErrorLog -Level Debug
        }
        catch {
            $_ | Write-PodeErrorLog
            $_.Exception | Write-PodeErrorLog -CheckInnerException
            throw $_.Exception
        }
        finally {
            Close-PodeDisposable -Disposable $Listener
        }
    }


    if (Test-PodeEndpointByProtocolType -Type Http) {
        Add-PodeRunspace -Type 'Web' -Name 'KeepAlive' -ScriptBlock $waitScript -Parameters @{ 'Listener' = $listener } -NoProfile
    }
    else {
        Add-PodeRunspace -Type 'Signals' -Name 'KeepAlive' -ScriptBlock $waitScript -Parameters @{ 'Listener' = $listener } -NoProfile
    }

    # browse to the first endpoint, if flagged
    if ($Browse) {
        Start-Process $endpoints[0].Url
    }

    return @(foreach ($endpoint in $endpoints) {
            @{
                Url      = $endpoint.Url
                Pool     = $endpoint.Pool
                DualMode = $endpoint.DualMode
                Name     = $endpoint.Name
                Default  = $endpoint.Default
            }
        })
}

function New-PodeListener {
    [CmdletBinding()]
    [OutputType([Pode.PodeListener])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Threading.CancellationToken]
        $CancellationToken
    )

    return [PodeListener]::new($CancellationToken)
}

function New-PodeListenerSocket {
    [CmdletBinding()]
    [OutputType([Pode.PodeSocket])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [ipaddress[]]
        $Address,

        [Parameter(Mandatory = $true)]
        [int]
        $Port,

        [Parameter()]
        [System.Security.Authentication.SslProtocols]
        $SslProtocols,

        [Parameter(Mandatory = $true)]
        [PodeProtocolType]
        $Type,

        [Parameter()]
        [X509Certificate]
        $Certificate,

        [Parameter()]
        [bool]
        $AllowClientCertificate,

        [switch]
        $DualMode
    )

    return [PodeSocket]::new($Name, $Address, $Port, $SslProtocols, $Type, $Certificate, $AllowClientCertificate, 'Implicit', $DualMode.IsPresent)
}