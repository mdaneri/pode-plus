function Get-PodeLoggingTerminalMethod {
    return {
        param($item, $options)

        if ($PodeContext.Server.Quiet) {
            return
        }

        # check if it's an array from batching
        if ($item -is [array]) {
            $item = ($item -join [System.Environment]::NewLine)
        }

        # protect then write
        $item = ($item | Protect-PodeLogItem)
        $item.ToString() | Out-PodeHost
    }
}

function Get-PodeLoggingFileMethod {
    return {
        param($item, $options)

        # check if it's an array from batching
        if ($item -is [array]) {
            $item = ($item -join [System.Environment]::NewLine)
        }

        # mask values
        $item = ($item | Protect-PodeLogItem)

        # variables
        $date = [DateTime]::Now.ToString('yyyy-MM-dd')

        # do we need to reset the fileId?
        if ($options.Date -ine $date) {
            $options.Date = $date
            $options.FileId = 0
        }

        # get the fileId
        if ($options.FileId -eq 0) {
            $path = [System.IO.Path]::Combine($options.Path, "$($options.Name)_$($date)_*.log")
            $options.FileId = (@(Get-ChildItem -Path $path)).Length
            if ($options.FileId -eq 0) {
                $options.FileId = 1
            }
        }

        $id = "$($options.FileId)".PadLeft(3, '0')
        if ($options.MaxSize -gt 0) {
            $path = [System.IO.Path]::Combine($options.Path, "$($options.Name)_$($date)_$($id).log")
            if ((Get-Item -Path $path -Force).Length -ge $options.MaxSize) {
                $options.FileId++
                $id = "$($options.FileId)".PadLeft(3, '0')
            }
        }

        # get the file to write to
        $path = [System.IO.Path]::Combine($options.Path, "$($options.Name)_$($date)_$($id).log")

        # write the item to the file
        $item.ToString() | Out-File -FilePath $path -Encoding utf8 -Append -Force

        # if set, remove log files beyond days set (ensure this is only run once a day)
        if (($options.MaxDays -gt 0) -and ($options.NextClearDown -le [DateTime]::Now.Date)) {
            $date = [DateTime]::Now.Date.AddDays(-$options.MaxDays)

            $null = Get-ChildItem -Path $options.Path -Filter "$($options.Name)_*.log" -Force |
                Where-Object { $_.CreationTime -lt $date } |
                Remove-Item -Force

            $options.NextClearDown = [DateTime]::Now.Date.AddDays(1)
        }
    }
}

function Get-PodeLoggingEventViewerMethod {
    return {
        param($item, $options, $rawItem)

        if ($item -isnot [array]) {
            $item = @($item)
        }

        if ($rawItem -isnot [array]) {
            $rawItem = @($rawItem)
        }

        for ($i = 0; $i -lt $item.Length; $i++) {
            # convert log level - info if no level present
            $entryType = ConvertTo-PodeEventViewerLevel -Level $rawItem[$i].Level

            # create log instance
            $entryInstance = [System.Diagnostics.EventInstance]::new($options.ID, 0, $entryType)

            # create event log
            $entryLog = [System.Diagnostics.EventLog]::new()
            $entryLog.Log = $options.LogName
            $entryLog.Source = $options.Source

            try {
                $message = ($item[$i] | Protect-PodeLogItem)
                $entryLog.WriteEvent($entryInstance, $message)
            }
            catch {
                $_ | Write-PodeErrorLog -Level Debug
            }
        }
    }
}

function ConvertTo-PodeEventViewerLevel {
    param(
        [Parameter()]
        [string]
        $Level
    )

    if ([string]::IsNullOrWhiteSpace($Level)) {
        return [System.Diagnostics.EventLogEntryType]::Information
    }

    if ($Level -ieq 'error') {
        return [System.Diagnostics.EventLogEntryType]::Error
    }

    if ($Level -ieq 'warning') {
        return [System.Diagnostics.EventLogEntryType]::Warning
    }

    return [System.Diagnostics.EventLogEntryType]::Information
}

function Get-PodeLoggingInbuiltType {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Errors', 'Requests','service')]
        [string]
        $Type
    )

    switch ($Type.ToLowerInvariant()) {
        'requests' {
            $script = {
                param($item, $options)

                # just return the item if Raw is set
                if ($options.Raw) {
                    return $item
                }

                function sg($value) {
                    if ([string]::IsNullOrWhiteSpace($value)) {
                        return '-'
                    }

                    return $value
                }

                # build the url with http method
                $url = "$(sg $item.Request.Method) $(sg $item.Request.Resource) $(sg $item.Request.Protocol)"

                # build and return the request row
                return "$(sg $item.Host) $(sg $item.RfcUserIdentity) $(sg $item.User) [$(sg $item.Date)] `"$($url)`" $(sg $item.Response.StatusCode) $(sg $item.Response.Size) `"$(sg $item.Request.Referrer)`" `"$(sg $item.Request.Agent)`""
            }
        }

        'errors' {
            $script = {
                param($item, $options)

                # do nothing if the error level isn't present
                if (@($options.Levels) -inotcontains $item.Level) {
                    return
                }

                # just return the item if Raw is set
                if ($options.Raw) {
                    return $item
                }

                # build the exception details
                $row = @(
                    "Date: $($item.Date.ToString('yyyy-MM-dd HH:mm:ss'))",
                    "Level: $($item.Level)",
                    "ThreadId: $($item.ThreadId)",
                    "Server: $($item.Server)",
                    "Category: $($item.Category)",
                    "Message: $($item.Message)",
                    "StackTrace: $($item.StackTrace)"
                )

                # join the details and return
                return "$($row -join "`n")`n"
            }
        }
        'service' {
            $script = {
                param($item, $options)

                # do nothing if the error level isn't present
                if (@($options.Levels) -inotcontains $item.Level) {
                    return
                }

                # just return the item if Raw is set
                if ($options.Raw) {
                    return $item
                }

                # build the exception details
                $row = @(
                    "Date: $($item.Date.ToString('yyyy-MM-dd HH:mm:ss'))",
                    "Level: $($item.Level)",
                    "ThreadId: $($item.ThreadId)",
                    "Server: $($item.Server)",
                    "Category: $($item.Category)",
                    "Message: $($item.Message)"
                )

                # join the details and return
                return "$($row -join "`n")`n"
            }
        }
    }

    return $script
}

function Get-PodeRequestLoggingName {
    return '__pode_log_requests__'
}

function Get-PodeErrorLoggingName {
    return '__pode_log_errors__'
}

<#
.SYNOPSIS
    Retrieves a Pode logger by name.

.DESCRIPTION
    This function allows you to retrieve a Pode logger by specifying its name. It returns the logger object associated with the given name.

.PARAMETER Name
    The name of the Pode logger to retrieve.

.OUTPUTS
    A Pode logger object.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Get-PodeLogger {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    return $PodeContext.Server.Logging.Types[$Name]
}

function Test-PodeLoggerEnabled {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    return ($PodeContext.Server.Logging.Enabled -and $PodeContext.Server.Logging.Types.ContainsKey($Name))
}

<#
.SYNOPSIS
    Gets the error logging levels for Pode.

.DESCRIPTION
    This function retrieves the error logging levels configured for Pode. It returns an array of available error levels.

.PARAMETER Name
    The name of the Pode logger to retrieve.

.OUTPUTS
    An array of error logging levels.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Get-PodeErrorLoggingLevel {
    return (Get-PodeLogger -Name (Get-PodeErrorLoggingName)).Arguments.Levels
}

function Test-PodeErrorLoggingEnabled {
    return (Test-PodeLoggerEnabled -Name (Get-PodeErrorLoggingName))
}

function Test-PodeRequestLoggingEnabled {
    return (Test-PodeLoggerEnabled -Name (Get-PodeRequestLoggingName))
}

function Write-PodeRequestLog {
    param(
        [Parameter(Mandatory = $true)]
        $Request,

        [Parameter(Mandatory = $true)]
        $Response,

        [Parameter()]
        [string]
        $Path
    )

    # do nothing if logging is disabled, or request logging isn't setup
    $name = Get-PodeRequestLoggingName
    if (!(Test-PodeLoggerEnabled -Name $name)) {
        return
    }

    # build a request object
    $item = @{
        Host            = $Request.RemoteEndPoint.Address.IPAddressToString
        RfcUserIdentity = '-'
        User            = '-'
        Date            = [DateTime]::Now.ToString('dd/MMM/yyyy:HH:mm:ss zzz')
        UtcDate         = [DateTime]::UtcNow
        Request         = @{
            Method   = $Request.HttpMethod.ToUpperInvariant()
            Hostname = $Request.Host.ToLowerInvariant()
            Scheme   = $Request.Scheme.ToLowerInvariant()
            Resource = $Path
            Query = (Protect-PodeValue -Value $Request.Url.Query -Default '-').TrimStart('?')
            Protocol = "HTTP/$($Request.ProtocolVersion)"
            Referrer = $Request.UrlReferrer
            Agent    = $Request.UserAgent
        }
        Response        = @{
            StatusCode        = $Response.StatusCode
            StatusDescription = $Response.StatusDescription
            Size              = '-'
        }
    }
    
    # set size if >0
    if ($Response.ContentLength64 -gt 0) {
        $item.Response.Size = $Response.ContentLength64
    }

    # set username - dot spaces
    if (Test-PodeAuthUser -IgnoreSession) {
        $userProps = (Get-PodeLogger -Name $name).Properties.Username.Split('.')

        $user = $WebEvent.Auth.User
        foreach ($atom in $userProps) {
            $user = $user.($atom)
        }

        if (![string]::IsNullOrWhiteSpace($user)) {
            $item.User = $user -ireplace '\s+', '.'
        }
    }

    # add the item to be processed
    $null = $PodeContext.LogsToProcess.Add(@{
            Name = $name
            Item = $item
        })
}

function Add-PodeRequestLogEndware {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $WebEvent
    )

    # do nothing if logging is disabled, or request logging isn't setup
    $name = Get-PodeRequestLoggingName
    if (!(Test-PodeLoggerEnabled -Name $name)) {
        return
    }

    # add the request logging endware
    $WebEvent.OnEnd += @{
        Logic = {
            Write-PodeRequestLog -Request $WebEvent.Request -Response $WebEvent.Response -Path $WebEvent.Path
        }
    }
}

function Test-PodeLoggersExist {
    if (($null -eq $PodeContext.Server.Logging) -or ($null -eq $PodeContext.Server.Logging.Types)) {
        return $false
    }

    return (($PodeContext.Server.Logging.Types.Count -gt 0) -or ($PodeContext.Server.Logging.Enabled))
}

function Start-PodeLoggingRunspace {
    # skip if there are no loggers configured, or logging is disabled
    if (!(Test-PodeLoggersExist)) {
        return
    }

    $script = {
        try {
            while (!(Test-PodeCancellationTokenRequest -Type Terminate)) {

                # Check for suspension token and wait for the debugger to reset if active
                Test-PodeSuspensionToken

                try {
                    # if there are no logs to process, just sleep for a few seconds - but after checking the batch
                    if ($PodeContext.LogsToProcess.Count -eq 0) {
                        Test-PodeLoggerBatch
                        Start-Sleep -Seconds 5
                        continue
                    }

                    # safely pop off the first log from the array
                    $log = (Lock-PodeObject -Return -Object $PodeContext.LogsToProcess -ScriptBlock {
                            $log = $PodeContext.LogsToProcess[0]
                            $null = $PodeContext.LogsToProcess.RemoveAt(0)
                            return $log
                        })

                    # run the log item through the appropriate method
                    $logger = Get-PodeLogger -Name $log.Name
                    $now = [datetime]::Now

                    # if the log is null, check batch then sleep and skip
                    if ($null -eq $log) {
                        Start-Sleep -Milliseconds 100
                        continue
                    }

                    # convert to log item into a writable format
                    $rawItems = $log.Item
                    $_args = @($log.Item) + @($logger.Arguments)
                    $result = @(Invoke-PodeScriptBlock -ScriptBlock $logger.ScriptBlock -Arguments $_args -UsingVariables $logger.UsingVariables -Return -Splat)

                    # check batching
                    $batch = $logger.Method.Batch
                    if ($batch.Size -gt 1) {
                        # add current item to batch
                        $batch.Items += $result
                        $batch.RawItems += $log.Item
                        $batch.LastUpdate = $now

                        # if the current amount of items matches the batch, write
                        $result = $null
                        if ($batch.Items.Length -ge $batch.Size) {
                            $result = $batch.Items
                            $rawItems = $batch.RawItems
                        }

                        # if we're writing, reset the items
                        if ($null -ne $result) {
                            $batch.Items = @()
                            $batch.RawItems = @()
                        }
                    }

                    # send the writable log item off to the log writer
                    if ($null -ne $result) {
                        $_args = @(, $result) + @($logger.Method.Arguments) + @(, $rawItems)
                        $null = Invoke-PodeScriptBlock -ScriptBlock $logger.Method.ScriptBlock -Arguments $_args -UsingVariables $logger.Method.UsingVariables -Splat
                    }

                    # small sleep to lower cpu usage
                    Start-Sleep -Milliseconds 100
                }
                catch {
                    $_ | Write-PodeErrorLog
                }
            }
        }
        catch [System.OperationCanceledException] {
            $_ | Write-PodeErrorLog -Level Debug
        }
        catch {
            $_ | Write-PodeErrorLog
            throw $_.Exception
        }
    }

    Add-PodeRunspace -Type Main -Name 'Logging' -ScriptBlock $script
}

<#
.SYNOPSIS
    Tests whether Pode logger batches need to be written.

.DESCRIPTION
    This function checks each Pode logger and determines if its batch needs to be written. It evaluates the batch size, timeout, and last update timestamp to decide whether to process the batch and write the log entries.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Test-PodeLoggerBatch {
    $now = [datetime]::Now

    # check each logger, and see if its batch needs to be written
    foreach ($logger in $PodeContext.Server.Logging.Types.Values) {
        $batch = $logger.Method.Batch
        if (($batch.Size -gt 1) -and ($batch.Items.Length -gt 0) -and ($batch.Timeout -gt 0) `
                -and ($null -ne $batch.LastUpdate) -and ($batch.LastUpdate.AddSeconds($batch.Timeout) -le $now)
        ) {
            $result = $batch.Items
            $rawItems = $batch.RawItems

            $batch.Items = @()
            $batch.RawItems = @()

            $_args = @(, $result) + @($logger.Method.Arguments) + @(, $rawItems)
            $null = Invoke-PodeScriptBlock -ScriptBlock $logger.Method.ScriptBlock -Arguments $_args -UsingVariables $logger.Method.UsingVariables -Splat
        }
    }
}
