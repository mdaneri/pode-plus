<#
.SYNOPSIS
    Tests if the Pode service is enabled.

.DESCRIPTION
    This function checks if the Pode service is enabled by verifying if the `Service` key exists in the `$PodeContext.Server` hashtable.

.OUTPUTS
    [Bool] - `$true` if the 'Service' key exists, `$false` if it does not.

.EXAMPLE
    Test-PodeServiceEnabled

    Returns `$true` if the Pode service is enabled, otherwise returns `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Test-PodeServiceEnabled {

    # Check if the 'Service' key exists in the $PodeContext.Server hashtable
    return $PodeContext.Server.ContainsKey('Service')
}

<#
.SYNOPSIS
    Starts the Pode Service Heartbeat using a named pipe for communication with a C# service.

.DESCRIPTION
    This function starts a named pipe server in PowerShell that listens for commands from a C# application. It supports two commands:
    - 'shutdown': to gracefully stop the Pode server.
    - 'restart': to restart the Pode server.

.PARAMETER None
    The function takes no parameters. It retrieves the pipe name from the Pode service context.

.EXAMPLE
    Start-PodeServiceHeartbeat

    This command starts the Pode service monitoring and waits for 'shutdown' or 'restart' commands from the named pipe.

.NOTES
    This is an internal function and may change in future releases of Pode.

    The function uses Pode's context for the service to manage the pipe server. The pipe listens for messages sent from a C# client
    and performs actions based on the received message.

    If the pipe receives a 'stop' message, the Pode server is stopped.
    If the pipe receives a 'restart' message, the Pode server is restarted.

    Global variable example:  $global:PodeService=@{DisableTermination=$true;Quiet=$false;Pipename='ssss'}
#>
function Start-PodeServiceHeartbeat {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param()
    # Check if the Pode service is enabled
    if (Test-PodeServiceEnabled) {

        # Define the script block for the client receiver, listens for commands via the named pipe
        $scriptBlock = {
            while (!(Test-PodeCancellationTokenRequest -Type Terminate)) {

                do {
                    Start-Sleep -Seconds 1
                    $serviceState = Get-PodeServerState
                }until(( [Pode.PodeServerState]::Running, [Pode.PodeServerState]::Suspended, [Pode.PodeServerState]::Terminating) -contains ( $serviceState) )

                [System.Console]::WriteLine("Initialize Listener Pipe $($PodeContext.Server.Service.PipeName)")
                [System.Console]::WriteLine("Service State: $serviceState")
                [System.Console]::WriteLine("Total Uptime: $(Get-PodeServerUptime -Total -Format verbose -ExcludeMilliseconds)")
                if ((Get-PodeServerUptime) -gt 1000) {
                    [System.Console]::WriteLine("Uptime Since Last Restart: $(Get-PodeServerUptime -Readable -OutputType Verbose -ExcludeMilliseconds)")
                }
                [System.Console]::WriteLine("Total Number of Restart: $(Get-PodeServerRestartCount)")
                try {
                    Start-Sleep -Milliseconds 100
                    # Create a named pipe server stream
                    $pipeStream = [System.IO.Pipes.NamedPipeServerStream]::new(
                        $PodeContext.Server.Service.PipeName,
                        [System.IO.Pipes.PipeDirection]::InOut,
                        1, # Max number of allowed concurrent connections
                        [System.IO.Pipes.PipeTransmissionMode]::Byte,
                        [System.IO.Pipes.PipeOptions]::None
                    )

                    [System.Console]::WriteLine("Waiting for connection to the $($PodeContext.Server.Service.PipeName) pipe.")
                    $pipeStream.WaitForConnection()  # Wait until a client connects
                    [System.Console]::WriteLine("Connected to the $($PodeContext.Server.Service.PipeName) pipe.")

                    # Create a StreamReader to read incoming messages from the pipe
                    $reader = [System.IO.StreamReader]::new($pipeStream)

                    # Process incoming messages in a loop as long as the pipe is connected
                    if ($pipeStream.IsConnected) {
                        $message = $reader.ReadLine()  # Read message from the pipe
                        if ( Test-PodeCancellationTokenRequest -Type Terminate) {
                            return
                        }

                        if ($message) {
                            [System.Console]::WriteLine("Received message: $message")

                            switch ($message) {
                                'stop' {
                                    # Process 'shutdown' message
                                    [System.Console]::WriteLine("Server request: 'Stop'. Closing Pode ...")
                                    Close-PodeServer  # Gracefully stop Pode server
                                    Start-Sleep 1
                                    [System.Console]::WriteLine("Service State: $(Get-PodeServerState)")

                                    [System.Console]::WriteLine('Closing Service Monitoring Heartbeat')
                                    return  # Exit the loop
                                }

                                'restart' {
                                    # Process 'restart' message
                                    [System.Console]::WriteLine("Server request: 'Restart'. Restarting Pode ...")
                                    Restart-PodeServer  # Restart Pode server
                                    Start-Sleep 1
                                    [System.Console]::WriteLine("Service State: $(Get-PodeServerState)")

                                    [System.Console]::WriteLine('Closing Service Monitoring Heartbeat')
                                    return # Exit the loop
                                }

                                'suspend' {
                                    # Process 'suspend' message
                                    [System.Console]::WriteLine("Server request: 'Suspend'. Suspending Pode ...")
                                    Suspend-PodeServer
                                    Start-Sleep 1
                                    [System.Console]::WriteLine("Service State: $(Get-PodeServerState)")
                                    break
                                }

                                'resume' {
                                    # Process 'resume' message
                                    [System.Console]::WriteLine("Server request: 'Resume'. Resuming Pode ...")
                                    Resume-PodeServer
                                    Start-Sleep 1
                                    [System.Console]::WriteLine("Service State: $(Get-PodeServerState)")
                                    break
                                }
                            }

                        }
                    }
                }
                catch {
                    $_ | Write-PodeErrorLog  # Log any errors that occur during pipe operation
                }
                finally {
                    if ($reader) {
                        $reader.Dispose()
                    }
                    if ($pipeStream) {
                        $pipeStream.Flush()
                        $pipeStream.Close()
                        $pipeStream.Dispose()  # Always dispose of the pipe stream when done
                        [System.Console]::WriteLine("Disposing Listener Pipe $($PodeContext.Server.Service.PipeName)")
                    }
                }

            }
            [System.Console]::WriteLine('Closing Service Monitoring Heartbeat')
        }

        # Assign a name to the Pode service
        $PodeContext.Server.Service['Name'] = 'Service'
        Write-Verbose -Message 'Starting service monitoring'

        # Start the runspace that runs the client receiver script block
        $PodeContext.Server.Service['Runspace'] = Add-PodeRunspace -Type 'Service' -ScriptBlock ($scriptBlock) -PassThru
    }
}

<#
.SYNOPSIS
    Registers a Pode service as a macOS LaunchAgent/Daemon.

.DESCRIPTION
    The `Register-PodeMacService` function creates a macOS plist file for the Pode service. It sets up the service
    to run using `launchctl`, specifying options such as autostart, logging, and the executable path.

.PARAMETER Name
    The name of the Pode service. This is used to identify the service in macOS.

.PARAMETER Description
    A brief description of the service. This is not included in the plist file but can be useful for logging.

.PARAMETER BinPath
    The path to the directory where the PodeMonitor executable is located.

.PARAMETER SettingsFile
    The path to the configuration file (e.g., `srvsettings.json`) that the Pode service will use.

.PARAMETER User
    The user under which the Pode service will run.

.PARAMETER Start
    If specified, the service will be started after registration.

.PARAMETER Autostart
    If specified, the service will automatically start when the system boots.

.PARAMETER OsArchitecture
    Specifies the architecture of the operating system (e.g., `osx-x64` or `osx-arm64`).

.PARAMETER Agent
    A switch to create an Agent instead of a Daemon in MacOS.

.OUTPUTS
    Returns $true if successful.

.EXAMPLE
    Register-PodeMacService -Name 'MyPodeService' -Description 'My Pode service' -BinPath '/path/to/bin' `
        -SettingsFile '/path/to/srvsettings.json' -User 'podeuser' -Start -Autostart -OsArchitecture 'osx-arm64'

    Registers a Pode service on macOS and starts it immediately with autostart enabled.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Register-PodeMacService {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [string]
        $Description,

        [string]
        $BinPath,

        [string]
        $SettingsFile,

        [string]
        $User,

        [string]
        $OsArchitecture,

        [string]
        $LogPath,

        [switch]
        $Agent
    )

    $nameService = Get-PodeRealServiceName -Name $Name

    # Check if the service is already registered
    if ((Test-PodeMacOsServiceIsRegistered $nameService -Agent:$Agent)) {
        # Service is already registered.
        throw ($PodeLocale.serviceAlreadyRegisteredException -f $nameService)
    }

    # Determine whether the service should run at load
    $runAtLoad = if ($Autostart.IsPresent) { '<true/>' } else { '<false/>' }


    # Create a temporary file
    $tempFile = [System.IO.Path]::GetTempFileName()

    # Create the plist content
    @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$nameService</string>

    <key>ProgramArguments</key>
    <array>
        <string>$BinPath/$OsArchitecture/PodeMonitor</string> <!-- Path to your published executable -->
        <string>$SettingsFile</string> <!-- Path to your configuration file -->
    </array>

    <key>WorkingDirectory</key>
    <string>$BinPath</string>

    <key>RunAtLoad</key>
    $runAtLoad

    <key>StandardOutPath</key>
    <string>$LogPath/$nameService.stdout.log</string>

    <key>StandardErrorPath</key>
    <string>$LogPath/$nameService.stderr.log</string>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <!-- Enable advanced restart and recovery options
    <key>EnableTransactions</key>
    <true/>
    -->
</dict>
</plist>
"@ | Set-Content -Path $tempFile -Encoding UTF8

    Write-Verbose  -Message "Service '$nameService' WorkingDirectory : $($BinPath)."
    try {
        if ($Agent) {
            $plistPath = "$($HOME)/Library/LaunchAgents/$($nameService).plist"
            Copy-Item -Path $tempFile -Destination $plistPath
            #set rw r r permissions
            chmod 644 $plistPath
            # Load the plist with launchctl
            launchctl load $plistPath
        }
        else {
            $plistPath = "/Library/LaunchDaemons/$($nameService).plist"
            & sudo cp $tempFile  $plistPath
            #set rw r r permissions
            & sudo chmod 644 $plistPath

            & sudo chown root:wheel $plistPath

            # Load the plist with launchctl
            & sudo launchctl load $plistPath

        }

        # Verify the service is now registered
        if (! (Test-PodeMacOsServiceIsRegistered $nameService -Agent:$Agent)) {
            # Service registration failed.
            throw ($PodeLocale.serviceRegistrationException -f $nameService)
        }
    }
    catch {
        $_ | Write-PodeErrorLog
        throw $_  # Rethrow the error after logging
    }

    return $true
}


<#
.SYNOPSIS
    Registers a new systemd service on a Linux system to run a Pode-based PowerShell worker.

.DESCRIPTION
    The `Register-PodeLinuxService` function configures and registers a new systemd service on a Linux system.
    It sets up the service with the specified parameters, generates the service definition file, enables the service,
    and optionally starts it. It can also create the necessary user if it does not exist.

.PARAMETER Name
    The name of the systemd service to be registered.

.PARAMETER Description
    A brief description of the service. Defaults to an empty string.

.PARAMETER BinPath
    The path to the directory containing the `PodeMonitor` executable.

.PARAMETER SettingsFile
    The path to the settings file for the Pode worker.

.PARAMETER User
    The name of the user under which the service will run. If the user does not exist, it will be created unless the `SkipUserCreation` switch is used.

.PARAMETER Group
    The group under which the service will run. Defaults to the same as the `User` parameter.

.PARAMETER OsArchitecture
    The architecture of the operating system (e.g., `x64`, `arm64`). Used to locate the appropriate binary.

.OUTPUTS
    Returns $true if successful.

.EXAMPLE
    Register-PodeLinuxService -Name "PodeExampleService" -Description "An example Pode service" `
        -BinPath "/usr/local/bin" -SettingsFile "/etc/pode/example-settings.json" `
        -User "podeuser" -Group "podegroup" -Start -OsArchitecture "x64"

    Registers a new systemd service named "PodeExampleService", creates the necessary user and group,
    generates the service file, enables the service, and starts it.

.EXAMPLE
    Register-PodeLinuxService -Name "PodeExampleService" -BinPath "/usr/local/bin" `
        -SettingsFile "/etc/pode/example-settings.json" -User "podeuser" -SkipUserCreation `
        -OsArchitecture "arm64"

    Registers a new systemd service without creating the user, and does not start the service immediately.

.NOTES
    - This function assumes systemd is the init system on the Linux machine.
    - The function will check if the service is already registered and will throw an error if it is.
    - If the user specified by the `User` parameter does not exist, the function will create it unless the `SkipUserCreation` switch is used.
    - This is an internal function and may change in future releases of Pode.
#>
function Register-PodeLinuxService {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [string]
        $Description,

        [string]
        $BinPath,

        [string]
        $SettingsFile,

        [string]
        $User,

        [string]
        $Group,

        [switch]
        $Start,

        [string]
        $OsArchitecture
    )
    $nameService = Get-PodeRealServiceName -Name $Name
    $null = systemctl status $nameService 2>&1

    # Check if the service is already registered
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3) {
        # Service is already registered.
        throw ($PodeLocale.serviceAlreadyRegisteredException -f $nameService )
    }
    # Create a temporary file
    $tempFile = [System.IO.Path]::GetTempFileName()

    $execStart = "$BinPath/$OsArchitecture/PodeMonitor `"$SettingsFile`""
    # Create the service file
    @"
[Unit]
Description=$Description
After=network.target

[Service]
ExecStart=$execStart
WorkingDirectory=$BinPath
Restart=always
User=$User
KillMode=process
Environment=NOTIFY_SOCKET=/run/systemd/notify
Environment=DOTNET_CLI_TELEMETRY_OPTOUT=1
# Uncomment and adjust if needed
# Group=$Group
# Environment=ASPNETCORE_ENVIRONMENT=Production

[Install]
WantedBy=multi-user.target
"@ | Set-Content -Path $tempFile  -Encoding UTF8

    Write-Verbose  -Message "Service '$nameService' ExecStart : $execStart)."

    & sudo cp $tempFile "/etc/systemd/system/$nameService"

    Remove-Item -path $tempFile -ErrorAction SilentlyContinue

    # Enable the service and check if it fails
    try {
        if (!(Enable-PodeLinuxService -Name $nameService)) {
            # Service registration failed.
            throw ($PodeLocale.serviceRegistrationException -f $nameService)
        }
    }
    catch {
        $_ | Write-PodeErrorLog
        throw $_  # Rethrow the error after logging
        return $false
    }

    return $true
}

<#
.SYNOPSIS
    Registers a new Windows service to run a Pode-based PowerShell worker.

.DESCRIPTION
    The `Register-PodeMonitorWindowsService` function configures and registers a new Windows service to run a Pode-based PowerShell worker.
    It sets up the service with the specified parameters, including paths to the Pode monitor executable, configuration file,
    credentials, and security descriptor. The service can be optionally started immediately after registration.

.PARAMETER Name
    The name of the Windows service to be registered.

.PARAMETER Description
    A brief description of the service. Defaults to an empty string.

.PARAMETER DisplayName
    The display name of the service, as it will appear in the Windows Services Manager.

.PARAMETER StartupType
    Specifies how the service is started. Options are: 'Automatic', 'Manual', or 'Disabled'. Defaults to 'Automatic'.

.PARAMETER BinPath
    The path to the directory containing the `PodeMonitor` executable.

.PARAMETER SettingsFile
    The path to the configuration file for the Pode worker.

.PARAMETER Credential
    A `PSCredential` object specifying the credentials for the account under which the service will run.

.PARAMETER SecurityDescriptorSddl
    An SDDL string (Security Descriptor Definition Language) used to define the security of the service.

.PARAMETER OsArchitecture
    The architecture of the operating system (e.g., `x64`, `arm64`). Used to locate the appropriate binary.

.OUTPUTS
    Returns $true if successful.

.EXAMPLE
    Register-PodeMonitorWindowsService -Name "PodeExampleService" -DisplayName "Pode Example Service" `
        -BinPath "C:\Pode" -SettingsFile "C:\Pode\settings.json" `
        -StartupType "Automatic" -Credential (Get-Credential) -Start -OsArchitecture "x64"

    Registers a new Windows service named "PodeExampleService", creates the service with credentials,
    generates the service, and starts it.

.EXAMPLE
    Register-PodeMonitorWindowsService -Name "PodeExampleService" -BinPath "C:\Pode" `
        -SettingsFile "C:\Pode\settings.json" -OsArchitecture "x64"

    Registers a new Windows service without credentials or immediate startup.

.NOTES
    - This function assumes the service binary exists at the specified `BinPath`.
    - It checks if the service already exists and throws an error if it does.
    - This is an internal function and may change in future releases of Pode.
#>

function Register-PodeMonitorWindowsService {
    param(
        [string]
        $Name,

        [string]
        $Description,

        [string]
        $DisplayName,

        [string]
        $StartupType,

        [string]
        $BinPath,

        [string]
        $SettingsFile,

        [pscredential]
        $Credential,

        [string]
        $SecurityDescriptorSddl,

        [string]
        $OsArchitecture
    )


    # Check if service already exists
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        # Service is already registered.
        throw ($PodeLocale.serviceAlreadyRegisteredException -f "$Name")

    }

    # Parameters for New-Service
    $params = @{
        Name           = $Name
        BinaryPathName = "`"$BinPath\$OsArchitecture\PodeMonitor.exe`" `"$SettingsFile`""
        DisplayName    = $DisplayName
        StartupType    = $StartupType
        Description    = $Description
        #DependsOn      = 'NetLogon'
    }
    if ($SecurityDescriptorSddl) {
        $params['SecurityDescriptorSddl'] = $SecurityDescriptorSddl
    }
    Write-Verbose -Message "Service '$Name' BinaryPathName : $($params['BinaryPathName'])."

    try {
        $paramsString = $params.GetEnumerator() | ForEach-Object { "-$($_.Key) '$($_.Value)'" }

        $sv = Invoke-PodeWinElevatedCommand -Command 'New-Service' -Arguments ($paramsString -join ' ') -Credential $Credential

        if (!$sv) {
            # Service registration failed.
            throw ($PodeLocale.serviceRegistrationException -f "$Name")
        }
    }
    catch {
        $_ | Write-PodeErrorLog
        throw $_  # Rethrow the error after logging
    }

    return $true
}





function Test-PodeUserServiceCreationPrivilege {
    # Get the list of user privileges
    $privileges = whoami /priv | Where-Object { $_ -match 'SeCreateServicePrivilege' }

    if ($privileges) {
        return $true
    }
    else {
        return $false
    }
}

<#
.SYNOPSIS
    Confirms if the current user has the necessary privileges to run the script.

.DESCRIPTION
    This function checks if the user has administrative privileges on Windows or root/sudo privileges on Linux/macOS.
    If the user does not have the required privileges, the script will output an appropriate message and exit.

.PARAMETER None
    This function does not accept any parameters.

.EXAMPLE
    Confirm-PodeAdminPrivilege

    This will check if the user has the necessary privileges to run the script. If not, it will output an error message and exit.

.OUTPUTS
    Exits the script if the necessary privileges are not available.

.NOTES
    This function works across Windows, Linux, and macOS, and checks for either administrative/root/sudo privileges or specific service-related permissions.
#>

function Confirm-PodeAdminPrivilege {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    # Check for administrative privileges
    if (! (Test-PodeAdminPrivilege -Elevate)) {
        if ((Test-PodeIsWindows) -and (Test-PodeUserServiceCreationPrivilege)) {
            Write-Error "Insufficient privileges. This script requires Administrator access or the 'SERVICE_CHANGE_CONFIG' (SeCreateServicePrivilege) permission to continue."
            return $false
        }

        # Message for non-Windows (Linux/macOS)
        Write-Error "Insufficient privileges. This script must be run as root or with 'sudo' permissions to continue."
        return $false
    }
    return $true
}

<#
.SYNOPSIS
    Verifies that the current Linux system is using systemd.

.DESCRIPTION
    Checks whether the process with PID 1 is 'systemd'.
    On non-Linux systems, or if PID 1 is not systemd, it writes an error and returns $false.
    Otherwise returns $true.

.PARAMETER (none)
    This function does not take any parameters.

.OUTPUTS
    System.Boolean
    Returns $true if running under systemd on Linux; otherwise $false.

.EXAMPLE
    # On a Linux host:
    PS> Test-PodeSystemd
    True

.EXAMPLE
    # On a non-systemd system:
    PS> Test-PodeSystemd
    Test-PodeSystemd : Systemd was not detected on this Linux system. Service management commands require systemd and cannot be executed.
    False

.NOTES
    - Requires that the automatic variable $IsLinux be correctly set.
    - Relies on Get-Process to inspect PID 1.
#>
function Test-PodeSystemd {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($IsLinux) {
        if ((Get-Process -Id 1).ProcessName -ne 'systemd') {
            Write-Error -Message 'Systemd was not detected on this Linux system. Service management commands require systemd and cannot be executed.' -Category InvalidOperation
            return $false
        }
    }
    return $true
}
 
<#
.SYNOPSIS
    Tests if a Linux service is registered.

.DESCRIPTION
    Checks if a specified Linux service is registered by using the `systemctl status` command.
    It returns `$true` if the service is found or its status code matches either `0` or `3`.

.PARAMETER Name
    The name of the Linux service to test.

.OUTPUTS
    [bool]
    Returns `$true` if the service is registered; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Test-PodeLinuxServiceIsRegistered {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    $nameService = Get-PodeRealServiceName -Name $Name
    $systemctlStatus = systemctl status $nameService 2>&1
    $isRegistered = ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3)
    Write-Verbose -Message ($systemctlStatus -join '`n')
    return $isRegistered
}

<#
.SYNOPSIS
    Tests if a Linux service is active.

.DESCRIPTION
    Checks if a specified Linux service is currently active by using the `systemctl is-active` command.
    It returns `$true` if the service is active.

.PARAMETER Name
    The name of the Linux service to check.

.OUTPUTS
    [bool]
    Returns `$true` if the service is active; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Test-PodeLinuxServiceIsActive {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    $nameService = Get-PodeRealServiceName -Name $Name
    $systemctlIsActive = systemctl is-active $nameService 2>&1
    $isActive = $systemctlIsActive -eq 'active'
    Write-Verbose -Message ($systemctlIsActive -join '`n')
    return $isActive
}

<#
.SYNOPSIS
    Disables a Linux service.

.DESCRIPTION
    Disables a specified Linux service by using the `sudo systemctl disable` command.
    It returns `$true` if the service is successfully disabled.

.PARAMETER Name
    The name of the Linux service to disable.

.OUTPUTS
    [bool]
    Returns `$true` if the service is successfully disabled; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Disable-PodeLinuxService {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    $nameService = Get-PodeRealServiceName -Name $Name
    $systemctlDisable = & sudo systemctl disable $nameService 2>&1
    $success = $LASTEXITCODE -eq 0
    Write-Verbose -Message ($systemctlDisable -join '`n')
    return $success
}

<#
.SYNOPSIS
    Enables a Linux service.

.DESCRIPTION
    Enables a specified Linux service by using the `sudo systemctl enable` command.
    It returns `$true` if the service is successfully enabled.

.PARAMETER Name
    The name of the Linux service to enable.

.OUTPUTS
    [bool]
    Returns `$true` if the service is successfully enabled; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Enable-PodeLinuxService {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    $systemctlEnable = & sudo systemctl enable $Name 2>&1
    $success = $LASTEXITCODE -eq 0
    Write-Verbose -Message ($systemctlEnable -join '`n')
    return $success
}

<#
.SYNOPSIS
    Stops a Linux service.

.DESCRIPTION
    Stops a specified Linux service by using the `systemctl stop` command.
    It returns `$true` if the service is successfully stopped.

.PARAMETER Name
    The name of the Linux service to stop.

.OUTPUTS
    [bool]
    Returns `$true` if the service is successfully stopped; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Stop-PodeLinuxService {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    $nameService = Get-PodeRealServiceName -Name $Name
    #return (Send-PodeServiceSignal -Name $Name -Signal SIGTERM)
    $serviceStopInfo = & sudo systemctl stop  $nameService 2>&1
    $success = $LASTEXITCODE -eq 0
    Write-Verbose -Message ($serviceStopInfo -join "`n")
    return $success
}

<#
.SYNOPSIS
    Starts a Linux service.

.DESCRIPTION
    Starts a specified Linux service by using the `systemctl start` command.
    It returns `$true` if the service is successfully started.

.PARAMETER Name
    The name of the Linux service to start.

.OUTPUTS
    [bool]
    Returns `$true` if the service is successfully started; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Start-PodeLinuxService {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    $nameService = Get-PodeRealServiceName -Name $Name
    $serviceStartInfo = & sudo systemctl start $nameService 2>&1
    $success = $LASTEXITCODE -eq 0
    Write-Verbose -Message ($serviceStartInfo -join "`n")
    return $success
}

<#
.SYNOPSIS
    Tests if a macOS service is registered.

.DESCRIPTION
    Checks if a specified macOS service is registered by using the `launchctl list` command.
    It returns `$true` if the service is registered.

.PARAMETER Name
    The name of the macOS service to test.

.PARAMETER Agent
    Return only Agent type services.

.OUTPUTS
    [bool]
    Returns `$true` if the service is registered; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Test-PodeMacOsServiceIsRegistered {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [switch]
        $Agent
    )
    $nameService = Get-PodeRealServiceName -Name $Name
    if ($Agent) {
        $sudo = $false
    }
    else {
        $sudo = !(Test-Path -Path "$($HOME)/Library/LaunchAgents/$nameService.plist" -PathType Leaf)
    }

    if ($sudo) {
        $systemctlStatus = & sudo launchctl list $nameService 2>&1
    }
    else {
        $systemctlStatus = & launchctl list $nameService 2>&1
    }
    $isRegistered = ($LASTEXITCODE -eq 0)
    Write-Verbose -Message ($systemctlStatus -join '`n')
    return $isRegistered
}

<#
.SYNOPSIS
    Checks if a Pode service is registered on the current operating system.

.DESCRIPTION
    This function determines if a Pode service with the specified name is registered,
    based on the operating system. It delegates the check to the appropriate
    platform-specific function or logic.

.PARAMETER Name
    The name of the Pode service to check.

.EXAMPLE
    Test-PodeServiceIsRegistered -Name 'MyService'

    Checks if the Pode service named 'MyService' is registered.

.NOTES
   This is an internal function and may change in future releases of Pode.
#>
function Test-PodeServiceIsRegistered {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    if (Test-PodeIsWindows) {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"
        return $null -eq $service
    }
    if ($IsLinux) {
        return Test-PodeLinuxServiceIsRegistered -Name $Name
    }
    if ($IsMacOS) {
        return Test-PodeMacOsServiceIsRegistered -Name $Name
    }
}

<#
.SYNOPSIS
    Checks if a Pode service is active and running on the current operating system.

.DESCRIPTION
    This function determines if a Pode service with the specified name is active (running),
    based on the operating system. It delegates the check to the appropriate platform-specific
    function or logic.

.PARAMETER Name
    The name of the Pode service to check.

.EXAMPLE
    Test-PodeServiceIsActive -Name 'MyService'

    Checks if the Pode service named 'MyService' is active and running.

.NOTES
   This is an internal function and may change in future releases of Pode.
#>
function Test-PodeServiceIsActive {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    if (Test-PodeIsWindows) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service) {
            # Check if the service is already running
            return ($service.Status -ne 'Running')
        }
        return $false
    }
    if ($IsLinux) {
        return Test-PodeLinuxServiceIsActive -Name $Name
    }
    if ($IsMacOS) {
        return Test-PodeMacOsServiceIsActive -Name $Name
    }

}


<#
.SYNOPSIS
    Tests if a macOS service is active.

.DESCRIPTION
    Checks if a specified macOS service is currently active by looking for the "PID" value in the output of `launchctl list`.
    It returns `$true` if the service is active (i.e., if a PID is found).

.PARAMETER Name
    The name of the macOS service to check.

.OUTPUTS
    [bool]
    Returns `$true` if the service is active; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Test-PodeMacOsServiceIsActive {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    $nameService = Get-PodeRealServiceName -Name $Name
    $sudo = !(Test-Path -Path "$($HOME)/Library/LaunchAgents/$nameService.plist" -PathType Leaf)
    if ($sudo) {
        $serviceInfo = & sudo launchctl list $nameService
    }
    else {
        $serviceInfo = & launchctl list $nameService
    }
    $isActive = $serviceInfo -match '"PID" = (\d+);'
    Write-Verbose -Message ($serviceInfo -join "`n")
    return $isActive.Count -eq 1
}

<#
.SYNOPSIS
    Retrieves the PID of a macOS service.

.DESCRIPTION
    Retrieves the process ID (PID) of a specified macOS service by using `launchctl list`.
    If the service is not active or a PID cannot be found, the function returns `0`.

PARAMETER Name
    The name of the macOS service whose PID you want to retrieve.

.OUTPUTS
    [int]
    Returns the PID of the service if it is active; otherwise, returns `0`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Get-PodeMacOsServicePid {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    $nameService = Get-PodeRealServiceName -Name $Name
    $sudo = !(Test-Path -Path "$($HOME)/Library/LaunchAgents/$nameService.plist" -PathType Leaf)
    if ($sudo) {
        $serviceInfo = & sudo launchctl list $nameService
    }
    else {
        $serviceInfo = & launchctl list $nameService
    }
    $pidString = $serviceInfo -match '"PID" = (\d+);'
    Write-Verbose -Message ($serviceInfo -join "`n")
    return $(if ($pidString.Count -eq 1) { ($pidString[0].split('= '))[1].trim(';') } else { 0 })
}

<#
.SYNOPSIS
    Disables a macOS service.

.DESCRIPTION
    Disables a specified macOS service by using `launchctl unload` to unload the service's plist file.
    It returns `$true` if the service is successfully disabled.

.PARAMETER Name
    The name of the macOS service to disable.

.PARAMETER Agent
    Specifies that only agent-type services should be returned. This parameter is applicable to macOS only.

.OUTPUTS
    [bool]
    Returns `$true` if the service is successfully disabled; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Disable-PodeMacOsService {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [switch]
        $Agent
    )
    # Standardize service naming for Linux/macOS
    $nameService = Get-PodeRealServiceName -Name $Name

    if ($Agent) {
        $sudo = $false
    }
    else {
        $sudo = !(Test-Path -Path "$($HOME)/Library/LaunchAgents/$nameService.plist" -PathType Leaf)
    }

    if ($sudo) {
        $systemctlDisable = & sudo launchctl unload "/Library/LaunchDaemons/$nameService.plist" 2>&1
    }
    else {
        $systemctlDisable = & launchctl unload "$HOME/Library/LaunchAgents/$nameService.plist" 2>&1
    }
    $success = $LASTEXITCODE -eq 0
    Write-Verbose -Message ($systemctlDisable -join '`n')
    return $success
}

<#
.SYNOPSIS
    Stops a macOS service.

.DESCRIPTION
    Stops a specified macOS service by using the `launchctl stop` command.
    It returns `$true` if the service is successfully stopped.

.PARAMETER Name
    The name of the macOS service to stop.

.PARAMETER Agent
    Specifies that only agent-type services should be returned. This parameter is applicable to macOS only.

.OUTPUTS
    [bool]
    Returns `$true` if the service is successfully stopped; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Stop-PodeMacOsService {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [switch]
        $Agent
    )

    return (Send-PodeServiceSignal -Name $Name -Signal SIGTERM -Agent:$Agent)
}

<#
.SYNOPSIS
    Starts a macOS service.

.DESCRIPTION
    Starts a specified macOS service by using the `launchctl start` command.
    It returns `$true` if the service is successfully started.

.PARAMETER Name
    The name of the macOS service to start.

.PARAMETER Agent
    Specifies that only agent-type services should be returned.

.OUTPUTS
    [bool]
    Returns `$true` if the service is successfully started; otherwise, `$false`.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Start-PodeMacOsService {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [switch]
        $Agent
    )
    $nameService = Get-PodeRealServiceName -Name $Name

    if ($Agent) {
        $sudo = $false
    }
    else {
        $sudo = !(Test-Path -Path "$($HOME)/Library/LaunchAgents/$nameService.plist" -PathType Leaf)
    }

    if ($sudo) {
        $serviceStartInfo = & sudo launchctl start $nameService 2>&1
    }
    else {
        $serviceStartInfo = & launchctl start $nameService 2>&1
    }
    $success = $LASTEXITCODE -eq 0
    Write-Verbose -Message ($serviceStartInfo -join "`n")
    return $success
}

<#
.SYNOPSIS
	Sends a specified signal to a Pode service on Linux or macOS.

.DESCRIPTION
	The `Send-PodeServiceSignal` function sends a Unix signal (`SIGTSTP`, `SIGCONT`, `SIGHUP`, or `SIGTERM`) to a specified Pode service. It checks if the service is registered and active before sending the signal. The function supports both standard and elevated privilege operations based on the service's configuration.

.PARAMETER Name
	The name of the Pode service to signal.

.PARAMETER Signal
	The Unix signal to send to the service. Supported signals are:
	- `SIGTSTP`: Stop the service temporarily (20).
	- `SIGCONT`: Continue the service (18).
	- `SIGHUP`: Restart the service (1).
	- `SIGTERM`: Terminate the service gracefully (15).

.PARAMETER Agent
    Specifies that only agent-type services should be returned. This parameter is applicable to macOS only.

.OUTPUTS
	[bool] Returns `$true` if the signal was successfully sent, otherwise `$false`.

.EXAMPLE
	Send-PodeServiceSignal -Name "MyPodeService" -Signal "SIGHUP"

	Sends the `SIGHUP` signal to the Pode service named "MyPodeService", instructing it to restart.

.EXAMPLE
	Send-PodeServiceSignal -Name "AnotherService" -Signal "SIGTERM"

	Sends the `SIGTERM` signal to gracefully stop the Pode service named "AnotherService".

.NOTES
	- This function is intended for use on Linux and macOS only.
	- Requires administrative/root privileges to send signals to services running with elevated privileges.
	- Logs verbose output for troubleshooting.
    - This is an internal function and may change in future releases of Pode.
#>
function Send-PodeServiceSignal {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The name of the Pode service to signal
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        # The Unix signal to send to the service
        [Parameter(Mandatory = $true)]
        [ValidateSet('SIGTSTP', 'SIGCONT', 'SIGHUP', 'SIGTERM')]
        [string]
        $Signal,

        [switch]
        $Agent
    )

    # Standardize service naming for Linux/macOS
    $nameService = Get-PodeRealServiceName -Name $Name

    # Map signal names to their corresponding Unix signal numbers
    $signalMap = @{
        'SIGTSTP' = 20  # Stop the process
        'SIGCONT' = 18  # Resume the process
        'SIGHUP'  = 1   # Restart the process
        'SIGTERM' = 15  # Gracefully terminate the process
    }

    # Retrieve the signal number from the map
    $level = $signalMap[$Signal]

    # Check if the service is registered
    if ((Test-PodeServiceIsRegistered -Name $nameService)) {
        # Check if the service is currently active
        if ((Test-PodeServiceIsActive -Name $nameService)) {
            Write-Verbose -Message "Service '$Name' is active. Sending $Signal signal."

            # Retrieve service details, including the PID and privilege requirement
            $svc = Get-PodeService -Name $Name -Agent:$Agent

            # Send the signal based on the privilege level
            if ($svc.Sudo) {
                & sudo /bin/kill -$($level) $svc.Pid
            }
            else {
                & /bin/kill -$($level) $svc.Pid
            }

            # Check the exit code to determine if the signal was sent successfully
            $success = $LASTEXITCODE -eq 0
            if ($success) {
                Write-Verbose -Message "$Signal signal sent to service '$Name'."
            }
            return $success
        }
        else {
            Write-Verbose -Message "Service '$Name' is not running."
        }
    }
    else {
        # Throw an exception if the service is not registered
        throw ($PodeLocale.serviceIsNotRegisteredException -f $Name)
    }

    # Return false if the signal could not be sent
    return $false
}

<#
.SYNOPSIS
	Waits for a Pode service to reach a specified status within a defined timeout period.

.DESCRIPTION
	The `Wait-PodeServiceStatus` function continuously checks the status of a specified Pode service and waits for it to reach the desired status (`Running`, `Stopped`, or `Suspended`). If the service does not reach the desired status within the timeout period, the function returns `$false`.

.PARAMETER Name
	The name of the Pode service to monitor.

.PARAMETER Status
	The desired status to wait for. Valid values are:
	- `Running`
	- `Stopped`
	- `Suspended`

.PARAMETER Timeout
	The maximum time, in seconds, to wait for the service to reach the desired status. Defaults to 10 seconds.

.EXAMPLE
	Wait-PodeServiceStatus -Name "MyPodeService" -Status "Running" -Timeout 15

	Waits up to 15 seconds for the Pode service named "MyPodeService" to reach the `Running` status.

.EXAMPLE
	Wait-PodeServiceStatus -Name "AnotherService" -Status "Stopped"

	Waits up to 10 seconds (default timeout) for the Pode service named "AnotherService" to reach the `Stopped` status.

.OUTPUTS
	[bool] Returns `$true` if the service reaches the desired status within the timeout period, otherwise `$false`.

.NOTES
	- The function checks the service status every second until the desired status is reached or the timeout period expires.
	- If the service does not reach the desired status within the timeout period, the function returns `$false`.
    - This is an internal function and may change in future releases of Pode.
#>
function Wait-PodeServiceStatus {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Running', 'Stopped', 'Suspended')]
        [string]
        $Status,

        [Parameter(Mandatory = $false)]
        [int]
        $Timeout = 10
    )

    # Record the start time for timeout tracking
    $startTime = Get-Date
    Write-Verbose "Waiting for service '$Name' to reach status '$Status' with a timeout of $Timeout seconds."

    # Begin an infinite loop to monitor the service status
    while ($true) {
        # Retrieve the current status of the specified Pode service
        $currentStatus = Get-PodeServiceStatus -Name $Name

        # Check if the service has reached the desired status
        if ($currentStatus.Status -eq $Status) {
            Write-Verbose "Service '$Name' has reached the desired status '$Status'."
            return $true
        }

        # Check if the timeout period has been exceeded
        if ((Get-Date) -gt $startTime.AddSeconds($Timeout)) {
            Write-Verbose "Timeout reached. Service '$Name' did not reach the desired status '$Status'."
            return $false
        }

        # Pause execution for 1 second before checking again
        Start-Sleep -Seconds 1
    }
}

<#
.SYNOPSIS
    Retrieves the status of a Pode service on Windows, Linux, and macOS.

.DESCRIPTION
    The `Get-PodeServiceStatus` function provides detailed information about the status of a Pode service.
    It queries the service's current state, process ID (PID), and whether elevated privileges (Sudo) are required,
    adapting its behavior to the platform it runs on:

    - **Windows**: Retrieves service information using the `Win32_Service` class and maps common states to Pode-specific ones.
    - **Linux**: Uses `systemctl` to determine the service status and reads additional state information from custom Pode state files if available.
    - **macOS**: Checks service status via `launchctl` and processes custom Pode state files when applicable.

.PARAMETER Name
    Specifies the name of the Pode service to query.

.PARAMETER Agent
    Specifies that only agent-type services should be returned. This parameter is applicable to macOS only.

.EXAMPLE
    Get-PodeServiceStatus -Name "MyPodeService"
    Retrieves the status of the Pode service named "MyPodeService".

.EXAMPLE
    Get-PodeServiceStatus -Name "MyPodeService" -Agent
    Retrieves the status of the agent-type Pode service named "MyPodeService" (macOS only).

.OUTPUTS
    [PSCustomObject] The function returns a custom object with the following properties:
        - **Name**: The name of the service.
        - **Status**: The current status of the service (e.g., Running, Stopped, Suspended).
        - **Pid**: The process ID of the service.
        - **Sudo**: A boolean indicating whether elevated privileges are required.
        - **PathName**: The path to the service's configuration or executable.
        - **Type**: The type of the service (e.g., Service, Daemon, Agent).

.NOTES
    - **Supported Status States**: Running, Stopped, Suspended, Starting, Stopping, Pausing, Resuming, Unknown.
    - Requires administrative/root privileges for accessing service information on Linux and macOS.
    - **Platform-specific Behaviors**:
        - **Windows**: Leverages CIM to query service information and map states.
        - **Linux**: Relies on `systemctl` and custom Pode state files for service details.
        - **macOS**: Uses `launchctl` and Pode state files to assess service status.
    - If the specified service is not found, the function returns `$null`.
    - Logs errors and warnings to assist in troubleshooting.
    - This function is internal to Pode and subject to changes in future releases.
#>
function Get-PodeServiceStatus {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [switch]
        $Agent
    )


    if (Test-PodeIsWindows) {
        # Check if the service exists on Windows
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"

        if ($service) {
            switch ($service.State) {
                'Running' { $status = 'Running' }
                'Stopped' { $status = 'Stopped' }
                'Paused' { $status = 'Suspended' }
                'StartPending' { $status = 'Starting' }
                'StopPending' { $status = 'Stopping' }
                'PausePending' { $status = 'Pausing' }
                'ContinuePending' { $status = 'Resuming' }
                default { $status = 'Unknown' }
            }
            return [PSCustomObject]@{
                PsTypeName = 'PodeService'
                Name       = $Name
                Status     = $status
                Pid        = $service.ProcessId
                Sudo       = $true
                PathName   = $service.PathName
                Type       = 'Service'
            }

        }
        else {
            Write-Verbose -Message "Service '$Name' not found."
            return $null
        }
    }

    elseif ($IsLinux) {
        try {
            $nameService = Get-PodeRealServiceName -Name $Name
            # Check if the service exists on Linux (systemd)
            if ((Test-PodeLinuxServiceIsRegistered -Name $nameService)) {
                $servicePid = 0
                $status = $(systemctl show -p ActiveState $nameService | awk -F'=' '{print $2}')

                switch ($status) {
                    'active' {
                        $servicePid = $(systemctl show -p MainPID $nameService | awk -F'=' '{print $2}')
                        $stateFilePath = "/var/run/podemonitor/$servicePid.state"
                        if (Test-Path -Path $stateFilePath) {
                            $status = Get-Content -Path $stateFilePath -Raw
                            $status = $status.Substring(0, 1).ToUpper() + $status.Substring(1)
                        }
                    }
                    'reloading' {
                        $servicePid = $(systemctl show -p MainPID $nameService | awk -F'=' '{print $2}')
                        $status = 'Running'
                    }
                    'maintenance' {
                        $servicePid = $(systemctl show -p MainPID $nameService | awk -F'=' '{print $2}')
                        $status = 'Suspended'
                    }
                    'inactive' {
                        $status = 'Stopped'
                    }
                    'failed' {
                        $status = 'Stopped'
                    }
                    'activating' {
                        $servicePid = $(systemctl show -p MainPID $nameService | awk -F'=' '{print $2}')
                        $status = 'Starting'
                    }
                    'deactivating' {
                        $status = 'Stopping'
                    }
                    default {
                        $status = 'Stopped'
                    }
                }
                return [PSCustomObject]@{
                    PsTypeName = 'PodeService'
                    Name       = $Name
                    Status     = $status
                    Pid        = $servicePid
                    Sudo       = $true
                    PathName   = "/etc/systemd/system/$nameService"
                    Type       = 'Service'
                }
            }
            else {
                Write-Verbose -Message "Service '$nameService' not found."
            }
        }
        catch {
            $_ | Write-PodeErrorLog
            Write-Error -Exception $_.Exception
            return $null
        }
    }

    elseif ($IsMacOS) {
        try {
            $nameService = Get-PodeRealServiceName -Name $Name
            # Check if the service exists on macOS (launchctl)
            if ((Test-PodeMacOsServiceIsRegistered $nameService -Agent:$Agent)) {
                $servicePid = Get-PodeMacOsServicePid -Name $nameService # Extract the PID from the match

                if ($Agent) {
                    $sudo = $false
                }
                else {
                    $sudo = !(Test-Path -Path "$($HOME)/Library/LaunchAgents/$nameService.plist" -PathType Leaf)
                }

                if ($sudo) {
                    $stateFilePath = "/Library/LaunchDaemons/PodeMonitor/$servicePid.state"
                    $plistPath = "/Library/LaunchDaemons/$($nameService).plist"
                    $serviceType = 'Daemon'
                }
                else {
                    $stateFilePath = "$($HOME)/Library/LaunchAgents/PodeMonitor/$servicePid.state"
                    $plistPath = "$($HOME)/Library/LaunchAgents/$($nameService).plist"
                    $serviceType = 'Agent'
                }

                if (Test-Path -Path $stateFilePath) {
                    $status = Get-Content -Path $stateFilePath -Raw
                    $status = $status.Substring(0, 1).ToUpper() + $status.Substring(1)
                }
                else {
                    $status = 'Stopped'
                }

                return [PSCustomObject]@{
                    PsTypeName = 'PodeService'
                    Name       = $Name
                    Status     = $status
                    Pid        = $servicePid
                    Sudo       = $sudo
                    PathName   = $plistPath
                    Type       = $serviceType
                }
            }
            else {
                Write-Verbose -Message "Service '$Name' not found."
                return $null
            }
        }
        catch {
            $_ | Write-PodeErrorLog
            Write-Error -Exception $_.Exception
            return $null
        }
    }

}

<#
.SYNOPSIS
	Returns the standardized service name for a Pode service based on the current platform.

.DESCRIPTION
	The `Get-PodeRealServiceName` function formats a Pode service name to match platform-specific conventions:
	- On macOS, the service name is prefixed with `pode.` and suffixed with `.service`, with spaces replaced by underscores.
	- On Linux, the service name is suffixed with `.service`, with spaces replaced by underscores.
	- On Windows, the service name is returned as provided.

.PARAMETER Name
	The name of the Pode service to standardize.

.EXAMPLE
	Get-PodeRealServiceName -Name "My Pode Service"

	For macOS, returns: `pode.My_Pode_Service.service`.
	For Linux, returns: `My_Pode_Service.service`.
	For Windows, returns: `My Pode Service`.

.NOTES
	This is an internal function and may change in future releases of Pode.
#>
function Get-PodeRealServiceName {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    # If the name already ends with '.service', return it directly
    if ($Name -like '*.service') {
        return $Name
    }

    # Standardize service naming based on platform
    if ($IsMacOS) {
        return "pode.$Name.service".Replace(' ', '_')
    }
    elseif ($IsLinux) {
        return "$Name.service".Replace(' ', '_')
    }
    else {
        # Assume Windows or unknown platform
        return $Name
    }
}
