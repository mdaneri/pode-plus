using namespace Pode

<#
.SYNOPSIS
    Dynamically executes content as a Pode file, optionally passing data to it.

.DESCRIPTION
    This function takes a string of content, which is expected to be PowerShell code, and optionally a hashtable of data. It constructs a script block that optionally includes a parameter declaration,
    and then executes this script block using the provided data. This is useful for dynamically generating content based on a template or script contained in a file or a string.

.PARAMETER Content
    The PowerShell code as a string. This content is dynamically executed as a script block. It can include placeholders or logic that utilizes the passed data.

.PARAMETER Data
    Optional hashtable of data that can be referenced within the content/script. This data is passed to the script block as parameters.

.EXAMPLE
    $scriptContent = '"Hello, world! Today is $(Get-Date)"'
    ConvertFrom-PodeFile -Content $scriptContent

    This example will execute the content of the script and output "Hello, world! Today is [current date]".

.EXAMPLE
    $template = '"Hello, $(Name)! Your balance is $$(Amount)"'
    $data = @{ Name = 'John Doe'; Amount = '100.50' }
    ConvertFrom-PodeFile -Content $template -Data $data

    This example demonstrates using the function with a data parameter to replace placeholders within the content.
#>
function ConvertFrom-PodeFile {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Content,

        [Parameter()]
        $Data = @{}
    )

    # if we have data, then setup the data param
    if ($null -ne $Data -and $Data.Count -gt 0) {
        $Content = "param(`$data)`nreturn `"$($Content -replace '"', '``"')`""
    }
    else {
        $Content = "return `"$($Content -replace '"', '``"')`""
    }

    # invoke the content as a script to generate the dynamic content
    return (Invoke-PodeScriptBlock -ScriptBlock ([scriptblock]::Create($Content)) -Arguments $Data -Return -NoNewClosure)
}

function Get-PodeViewEngineType {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    # work out the engine to use when parsing the file
    $type = $PodeContext.Server.ViewEngine.Type

    $ext = Get-PodeFileExtension -Path $Path -TrimPeriod
    if (![string]::IsNullOrEmpty($ext) -and ($ext -ine $PodeContext.Server.ViewEngine.Extension)) {
        $type = $ext
    }

    return $type
}

function Get-PodeFileContentUsingViewEngine {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [string]
        $Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'FileInfo')]
        [System.IO.FileSystemInfo]
        $FileInfo,

        [Parameter()]
        [hashtable]
        $Data
    )

    # if we have no file info, get the file info from the path
    if ($null -eq $FileInfo) {
        $FileInfo = Get-Item -Path $Path -Force -ErrorAction Stop
    }

    # work out the engine to use when parsing the file
    $engine = Get-PodeViewEngineType -Path $FileInfo.FullName

    # setup the content
    $content = [string]::Empty

    # run the relevant engine logic
    switch ($engine.ToLowerInvariant()) {
        'html' {
            $content = [System.IO.File]::ReadAllText($FileInfo.FullName, [System.Text.Encoding]::UTF8)
        }

        'md' {
            $content = [System.IO.File]::ReadAllText($FileInfo.FullName, [System.Text.Encoding]::UTF8)
        }

        'pode' {
            $content = [System.IO.File]::ReadAllText($FileInfo.FullName, [System.Text.Encoding]::UTF8)
            $content = ConvertFrom-PodeFile -Content $content -Data $Data
        }

        default {
            if ($null -ne $PodeContext.Server.ViewEngine.ScriptBlock) {
                $_args = @($FileInfo.FullName)
                if (($null -ne $Data) -and ($Data.Count -gt 0)) {
                    $_args = @($FileInfo.FullName, $Data)
                }

                $content = (Invoke-PodeScriptBlock -ScriptBlock $PodeContext.Server.ViewEngine.ScriptBlock -Arguments $_args -UsingVariables $PodeContext.Server.ViewEngine.UsingVariables -Return -Splat)
            }
        }
    }

    return $content
}

function Get-PodeFileContent {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [switch]
        $NoEscape
    )

    $Path = Protect-PodePath -Path $Path -NoEscape:$NoEscape
    return (Get-Content -Path $Path -Raw -Encoding utf8)
}

function Protect-PodePath {
    param(
        [Parameter()]
        [string]
        $Path,

        [switch]
        $NoEscape
    )

    if ($NoEscape -or [string]::IsNullOrEmpty($Path)) {
        return $Path
    }

    return [WildcardPattern]::Escape($Path)
}

function Get-PodeType {
    param(
        [Parameter()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $type = $Value.GetType()
    return @{
        Name     = $type.Name.ToLowerInvariant()
        BaseName = $type.BaseType.Name.ToLowerInvariant()
    }
}

function Get-PodePSVersionTable {
    return $PSVersionTable
}

function Get-PodeHostIPRegex {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Both', 'Hostname', 'IP')]
        [string]
        $Type
    )

    $ip_rgx = '\[?([a-f0-9]*\:){1,}[a-f0-9]*((\d+\.){3}\d+)?\]?|(((\d{1,2}|1\d{1,2}|2[0-5][0-5])\.){3}(\d{1,2}|1\d{1,2}|2[0-5][0-5]))(\/(\d|[1-2][0-9]|3[0-2]))?|\*|all'
    $host_rgx = '([a-z]|\*\.)(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])+'

    switch ($Type.ToLowerInvariant()) {
        'both' {
            return "(?<host>($($ip_rgx)|$($host_rgx)))"
        }

        'hostname' {
            return "(?<host>($($host_rgx)))"
        }

        'ip' {
            return "(?<host>($($ip_rgx)))"
        }
    }
}

function Get-PodePortRegex {
    return '(?<port>\d+)'
}

function Get-PodeEndpointInfo {
    param(
        [Parameter()]
        [string]
        $Address,

        [switch]
        $AnyPortOnZero
    )

    if ([string]::IsNullOrWhiteSpace($Address)) {
        return $null
    }

    $hostRgx = Get-PodeHostIPRegex -Type Both
    $portRgx = Get-PodePortRegex
    $cmbdRgx = "$($hostRgx)\:$($portRgx)"

    # validate that we have a valid ip/host:port address
    if (!(
        ($Address -imatch "^$($cmbdRgx)$") -or
        ($Address -imatch "^$($hostRgx)[\:]{0,1}") -or
        (!$Address.Contains('.') -and $Address -imatch "[\:]{0,1}$($portRgx)$")
        )) {
        throw ($PodeLocale.failedToParseAddressExceptionMessage -f $Address)#"Failed to parse '$($Address)' as a valid IP/Host:Port address"
    }

    # grab the ip address/hostname
    $_host = $Matches['host']
    if ([string]::IsNullOrWhiteSpace($_host)) {
        $_host = '*'
    }

    # ensure we have a valid ip address/hostname
    if (!(Test-PodeIPAddress -IP $_host)) {
        throw ($PodeLocale.invalidIpAddressExceptionMessage -f $_host) #"The IP address supplied is invalid: $($_host)"
    }

    # grab the port
    $_port = $Matches['port']
    if ([string]::IsNullOrWhiteSpace($_port)) {
        $_port = 0
    }

    # ensure the port is valid
    if ($_port -lt 0) {
        throw ($PodeLocale.invalidPortExceptionMessage -f $_port)#"The port cannot be negative: $($_port)"
    }

    # return the info
    return @{
        Host = $_host
        Port = (Resolve-PodeValue -Check ($AnyPortOnZero -and ($_port -eq 0)) -TrueValue '*' -FalseValue $_port)
    }
}

function Test-PodeIPAddress {
    param(
        [Parameter()]
        [string]
        $IP,

        [switch]
        $IPOnly,

        [switch]
        $FailOnEmpty
    )

    # fail on empty
    if ([string]::IsNullOrWhiteSpace($IP)) {
        return !$FailOnEmpty.IsPresent
    }

    # all empty, or */all
    if ($IP -iin @('*', 'all')) {
        return $true
    }

    # are we allowing hostnames?
    if ($IP -imatch "^$(Get-PodeHostIPRegex -Type Hostname)$") {
        return !$IPOnly.IsPresent
    }

    # check if the IP matches regex
    if ($IP -imatch "^$(Get-PodeHostIPRegex -Type IP)$") {
        return $true
    }

    # if we get here, try parsing with [IPAddress] as a last resort
    try {
        $null = [System.Net.IPAddress]::Parse($IP)
        return $true
    }
    catch [exception] {
        return $false
    }
}

function Test-PodeHostname {
    param(
        [Parameter()]
        [string]
        $Hostname
    )

    return ($Hostname -imatch "^$(Get-PodeHostIPRegex -Type Hostname)$")
}

function ConvertTo-PodeIPAddress {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Address
    )

    return [System.Net.IPAddress]::Parse(([System.Net.IPEndPoint]$Address).Address.ToString())
}

function Get-PodeIPAddressesForHostname {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Hostname,

        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'IPv4', 'IPv6')]
        [string]
        $Type
    )

    if (!(Test-PodeHostname -Hostname $Hostname)) {
        return $Hostname
    }

    # get the ip addresses for the hostname
    try {
        $ips = @([System.Net.Dns]::GetHostAddresses($Hostname))
    }
    catch {
        return '127.0.0.1'
    }

    # return ips based on type
    switch ($Type.ToLowerInvariant()) {
        'ipv4' {
            $ips = @(foreach ($ip in $ips) {
                    if ($ip.AddressFamily -ieq 'InterNetwork') {
                        $ip
                    }
                })
        }

        'ipv6' {
            $ips = @(foreach ($ip in $ips) {
                    if ($ip.AddressFamily -ieq 'InterNetworkV6') {
                        $ip
                    }
                })
        }
    }

    return (@($ips)).IPAddressToString
}

function Test-PodeIPAddressLocal {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $IP
    )

    return (@('127.0.0.1', '::1', '[::1]', '::ffff:127.0.0.1', 'localhost') -icontains $IP)
}

function Test-PodeIPAddressAny {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $IP
    )

    return (@('0.0.0.0', '*', 'all', '::', '[::]') -icontains $IP)
}

function Test-PodeIPAddressLocalOrAny {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $IP
    )

    return ((Test-PodeIPAddressLocal -IP $IP) -or (Test-PodeIPAddressAny -IP $IP))
}

function Resolve-PodeIPDualMode {
    param(
        [Parameter()]
        [ipaddress]
        $IP
    )

    # do nothing if IPv6Any
    if ($IP -eq [ipaddress]::IPv6Any) {
        return $IP
    }

    # check loopbacks
    if (($IP -eq [ipaddress]::Loopback) -and [System.Net.Sockets.Socket]::OSSupportsIPv6) {
        return @($IP, [ipaddress]::IPv6Loopback)
    }

    if ($IP -eq [ipaddress]::IPv6Loopback) {
        return @($IP, [ipaddress]::Loopback)
    }

    # if iIPv4, convert and return both
    if (($IP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) -and [System.Net.Sockets.Socket]::OSSupportsIPv6) {
        return @($IP, $IP.MapToIPv6())
    }

    # if IPv6, only convert if valid IPv4
    if (($IP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) -and $IP.IsIPv4MappedToIPv6) {
        return @($IP, $IP.MapToIPv4())
    }

    # just return the IP
    return $IP
}

function Get-PodeIPAddress {
    param(
        [Parameter()]
        [string]
        $IP,

        [switch]
        $DualMode,

        [switch]
        $ContainsPort
    )

    # if we have a port, remove it
    if ($ContainsPort) {
        $ipRegex = Get-PodeHostIPRegex -Type IP
        $portRegex = Get-PodePortRegex
        $regex = "^$($ipRegex)(\:$($portRegex))?$"

        if ($IP -imatch $regex) {
            $IP = $Matches['host']
        }
        else {
            $IP = ($IP -split ':')[0]
        }
    }

    # any address for IPv4 (or IPv6 for DualMode)
    if ([string]::IsNullOrEmpty($IP) -or ($IP -iin @('*', 'all'))) {
        if ($DualMode) {
            return [System.Net.IPAddress]::IPv6Any
        }

        return [System.Net.IPAddress]::Any
    }

    # any address for IPv6 explicitly
    if ($IP -iin @('::', '[::]')) {
        return [System.Net.IPAddress]::IPv6Any
    }

    # localhost
    if ($IP -ieq 'localhost') {
        return [System.Net.IPAddress]::Loopback
    }

    # localhost IPv6 explicitly
    if ($IP -iin @('[::1]', '::1')) {
        return [System.Net.IPAddress]::IPv6Loopback
    }

    # hostname
    if ($IP -imatch "^$(Get-PodeHostIPRegex -Type Hostname)$") {
        return $IP
    }

    # raw ip
    return [System.Net.IPAddress]::Parse($IP)
}

function Test-PodeIPAddressInSubnet {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]
        $IP,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $Lower,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $Upper
    )

    $valid = $true

    foreach ($i in 0..3) {
        if (($IP[$i] -lt $Lower[$i]) -or ($IP[$i] -gt $Upper[$i])) {
            $valid = $false
            break
        }
    }

    return $valid
}

function Test-PodeIPAddressIsSubnetMask {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $IP
    )

    return (($IP -split '/').Length -gt 1)
}

function Get-PodeSubnetRange {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubnetMask
    )

    # split for ip and number of 1 bits
    $split = $SubnetMask -split '/'
    if ($split.Length -le 1) {
        return $null
    }

    $ip_parts = $split[0] -isplit '\.'
    $bits = [int]$split[1]

    # generate the netmask
    $network = @('', '', '', '')
    $count = 0

    foreach ($i in 0..3) {
        foreach ($b in 1..8) {
            $count++

            if ($count -le $bits) {
                $network[$i] += '1'
            }
            else {
                $network[$i] += '0'
            }
        }
    }

    # covert netmask to bytes
    foreach ($i in 0..3) {
        $network[$i] = [Convert]::ToByte($network[$i], 2)
    }

    # calculate the bottom range
    $bottom = @(foreach ($i in 0..3) {
            [byte]([byte]$network[$i] -band [byte]$ip_parts[$i])
        })

    # calculate the range
    $range = @(foreach ($i in 0..3) {
            256 + (-bnot [byte]$network[$i])
        })

    # calculate the top range
    $top = @(foreach ($i in 0..3) {
            [byte]([byte]$ip_parts[$i] + [byte]$range[$i])
        })

    return @{
        Lower   = ($bottom -join '.')
        Upper   = ($top -join '.')
        Range   = ($range -join '.')
        Netmask = ($network -join '.')
        IP      = ($ip_parts -join '.')
    }
}


function New-PodePSDrive {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Name
    )

    # if the path is a share, do nothing
    if ($Path.StartsWith('\\')) {
        return $Path
    }

    # if no name is passed, used a randomly generated one
    if ([string]::IsNullOrWhiteSpace($Name)) {
        $Name = "PodeDir$(New-PodeGuid)"
    }

    # if the path supplied doesn't exist, error
    if (!(Test-Path $Path)) {
        throw ($PodeLocale.pathNotExistExceptionMessage -f $Path)#"Path does not exist: $($Path)"
    }

    # resolve the path
    $Path = Get-PodeRelativePath -Path $Path -JoinRoot -Resolve

    # create the temp drive
    if (!(Test-PodePSDrive -Name $Name -Path $Path)) {
        $drive = (New-PSDrive -Name $Name -PSProvider FileSystem -Root $Path -Scope Global -ErrorAction Stop)
    }
    else {
        $drive = Get-PodePSDrive -Name $Name
    }

    # store internally, and return the drive's name
    if (!$PodeContext.Server.Drives.ContainsKey($drive.Name)) {
        $PodeContext.Server.Drives[$drive.Name] = $Path
    }

    return "$($drive.Name):$([System.IO.Path]::DirectorySeparatorChar)"
}

function Get-PodePSDrive {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    return (Get-PSDrive -Name $Name -PSProvider FileSystem -Scope Global -ErrorAction Ignore)
}

function Test-PodePSDrive {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $Path
    )

    $drive = Get-PodePSDrive -Name $Name
    if ($null -eq $drive) {
        return $false
    }

    if (![string]::IsNullOrWhiteSpace($Path)) {
        return ($drive.Root -ieq $Path)
    }

    return $true
}

<#
.SYNOPSIS
    Adds Pode PS drives to the session.

.DESCRIPTION
    This function iterates through the keys of Pode drives stored in the `$PodeContext.Server.Drives` collection and creates corresponding PS drives using `New-PodePSDrive`. The drive paths are specified by the values associated with each key.

.EXAMPLE
    Add-PodePSDrivesInternal
    # Creates Pode PS drives in the session based on the configured drive paths.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Add-PodePSDrivesInternal {
    foreach ($key in $PodeContext.Server.Drives.Keys) {
        $null = New-PodePSDrive -Path $PodeContext.Server.Drives[$key] -Name $key
    }
}

<#
.SYNOPSIS
    Imports other Pode modules into the session.

.DESCRIPTION
    This function iterates through the paths of other Pode modules stored in the `$PodeContext.Server.Modules.Values` collection and imports them into the session.
    It uses the `-DisableNameChecking` switch to suppress name checking during module import.

.EXAMPLE
    Import-PodeModulesInternal
    # Imports other Pode modules into the session.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Import-PodeModulesInternal {
    # import other modules in the session
    foreach ($path in $PodeContext.Server.Modules.Values) {
        if (Test-Path $path) {
            $null = Import-Module $path -DisableNameChecking -Scope Global -ErrorAction Stop
        }
    }
}

<#
.SYNOPSIS
Creates and registers inbuilt PowerShell drives for the Pode server's default folders.

.DESCRIPTION
This function sets up inbuilt PowerShell drives for the Pode web server's default directories: views, public content, and error pages. For each of these directories, if the physical path exists on the server, a new PowerShell drive is created and mapped to this path. These drives provide an easy and consistent way to access server resources like views, static files, and custom error pages within the Pode application.

The function leverages `$PodeContext` to access the server's configuration and to determine the paths for these default folders. If a folder's path exists, the function uses `New-PodePSDrive` to create a PowerShell drive for it and stores this drive in the server's `InbuiltDrives` dictionary, keyed by the folder type.

.PARAMETER None

.EXAMPLE
Add-PodePSInbuiltDrive

This example is typically called within the Pode server setup script or internally by the Pode framework to initialize the PowerShell drives for the server's default folders.

.NOTES
This is an internal function and may change in future releases of Pode.
#>
function Add-PodePSInbuiltDrive {

    # create drive for views, if path exists
    $path = (Join-PodeServerRoot -Folder $PodeContext.Server.DefaultFolders.Views)
    if (Test-Path $path) {
        $PodeContext.Server.InbuiltDrives[$PodeContext.Server.DefaultFolders.Views] = (New-PodePSDrive -Path $path)
    }

    # create drive for public content, if path exists
    $path = (Join-PodeServerRoot $PodeContext.Server.DefaultFolders.Public)
    if (Test-Path $path) {
        $PodeContext.Server.InbuiltDrives[$PodeContext.Server.DefaultFolders.Public] = (New-PodePSDrive -Path $path)
    }

    # create drive for errors, if path exists
    $path = (Join-PodeServerRoot $PodeContext.Server.DefaultFolders.Errors)
    if (Test-Path $path) {
        $PodeContext.Server.InbuiltDrives[$PodeContext.Server.DefaultFolders.Errors] = (New-PodePSDrive -Path $path)
    }
}

<#
.SYNOPSIS
    Removes Pode PS drives from the session.

.DESCRIPTION
    This function removes Pode PS drives from the session based on the specified drive name or pattern.
    If no specific name or pattern is provided, it removes all Pode PS drives by default.
    It uses `Get-PSDrive` to retrieve the drives and `Remove-PSDrive` to remove them.

.PARAMETER Name
    The name or pattern of the Pode PS drives to remove. Defaults to 'PodeDir*'.

.EXAMPLE
    Remove-PodePSDrive -Name 'myDir*'
    # Removes all PS drives with names matching the pattern 'myDir*'.

.EXAMPLE
    Remove-PodePSDrive
    # Removes all Pode PS drives.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Remove-PodePSDrive {
    [CmdletBinding()]
    param(
        $Name = 'PodeDir*'
    )
    $null = Get-PSDrive -Name $Name | Remove-PSDrive
}

<#
.SYNOPSIS
    Joins a folder and file path to the root path of the server.

.DESCRIPTION
    This function combines a folder path, file path (optional), and the root path of the server to create a complete path. If the root path is not explicitly provided, it uses the default root path from the Pode context.

.PARAMETER Folder
    The folder path to join.

.PARAMETER FilePath
    The file path (optional) to join. If not provided, only the folder path is used.

.PARAMETER Root
    The root path of the server. If not provided, the default root path from the Pode context is used.

.OUTPUTS
    Returns the combined path as a string.

.EXAMPLE
    Join-PodeServerRoot -Folder "uploads" -FilePath "document.txt"
    # Output: "/uploads/document.txt"

    This example combines the folder path "uploads" and the file path "document.txt" with the default root path from the Pode context.

#>
function Join-PodeServerRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Folder,

        [Parameter()]
        [string]
        $FilePath,

        [Parameter()]
        [string]
        $Root
    )

    # use the root path of the server
    if ([string]::IsNullOrWhiteSpace($Root)) {
        $Root = $PodeContext.Server.Root
    }

    # join the folder/file to the root path
    return [System.IO.Path]::Combine($Root, $Folder, $FilePath)
}

<#
.SYNOPSIS
    Removes empty items (empty strings) from an array.

.DESCRIPTION
    This function filters out empty items (empty strings) from an array. It returns a new array containing only non-empty items.

.PARAMETER Array
    The array from which to remove empty items.

.OUTPUTS
    Returns an array containing non-empty items.

.EXAMPLE
    $myArray = "apple", "", "banana", "", "cherry"
    $filteredArray = Remove-PodeEmptyItemsFromArray -Array $myArray
    Write-PodeHost "Filtered array: $filteredArray"

    This example removes empty items from the array and displays the filtered array.
#>
function Remove-PodeEmptyItemsFromArray {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectComparisonWithNull', '')]
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        $Array
    )
    if ($null -eq $Array) {
        return @()
    }

    return @( @($Array -ne ([string]::Empty)) -ne $null )

}

<#
.SYNOPSIS
    Retrieves the file extension from a given path.

.DESCRIPTION
    This function extracts the file extension (including the period) from a specified path. Optionally, it can trim the period from the extension.

.PARAMETER Path
    The path from which to extract the file extension.

.PARAMETER TrimPeriod
    Switch parameter. If specified, trims the period from the file extension.

.OUTPUTS
    Returns the file extension (with or without the period) as a string.

.EXAMPLE
    Get-PodeFileExtension -Path "C:\MyFiles\document.txt"
    # Output: ".txt"

    Get-PodeFileExtension -Path "C:\MyFiles\document.txt" -TrimPeriod
    # Output: "txt"

    This example demonstrates how to retrieve the file extension with and without the period from a given path.
#>
function Get-PodeFileExtension {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [string]
        $Path,

        [switch]
        $TrimPeriod
    )

    # Get the file extension
    $ext = [System.IO.Path]::GetExtension($Path)

    # Trim the period if requested
    if ($TrimPeriod) {
        $ext = $ext.Trim('.')
    }

    return $ext
}


<#
.SYNOPSIS
    Retrieves the file name from a given path.

.DESCRIPTION
    This function extracts the file name (including the extension) or the file name without the extension from a specified path.

.PARAMETER Path
    The path from which to extract the file name.

.PARAMETER WithoutExtension
    Switch parameter. If specified, returns the file name without the extension.

.OUTPUTS
    Returns the file name (with or without extension) as a string.

.EXAMPLE
    Get-PodeFileName -Path "C:\MyFiles\document.txt"
    # Output: "document.txt"

    Get-PodeFileName -Path "C:\MyFiles\document.txt" -WithoutExtension
    # Output: "document"

    This example demonstrates how to retrieve the file name with and without the extension from a given path.

.NOTES
    - If the path is a directory, the function returns the directory name.
    - Use this function to extract file names for further processing or display.
#>
function Get-PodeFileName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [string]
        $Path,

        [switch]
        $WithoutExtension
    )

    if ($WithoutExtension) {
        return [System.IO.Path]::GetFileNameWithoutExtension($Path)
    }

    return [System.IO.Path]::GetFileName($Path)
}

<#
.SYNOPSIS
    Tests whether an exception message indicates a valid network failure.

.DESCRIPTION
    This function checks if an exception message contains specific phrases that commonly indicate network-related failures. It returns a boolean value indicating whether the exception message matches any of these network failure patterns.

.PARAMETER Exception
    The exception object whose message needs to be tested.

.OUTPUTS
    Returns $true if the exception message indicates a valid network failure, otherwise returns $false.

.EXAMPLE
    $exception = [System.Exception]::new("The network name is no longer available.")
    $isNetworkFailure = Test-PodeValidNetworkFailure -Exception $exception
    Write-PodeHost "Is network failure: $isNetworkFailure"

    This example tests whether the exception message "The network name is no longer available." indicates a network failure.
#>
function Test-PodeValidNetworkFailure {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        $Exception
    )

    $msgs = @(
        '*network name is no longer available*',
        '*nonexistent network connection*',
        '*the response has completed*',
        '*broken pipe*'
    )

    $match = @(foreach ($msg in $msgs) {
            if ($Exception.Message -ilike $msg) {
                $msg
            }
        })[0]

    return ($null -ne $match)
}



function New-PodeRequestException {
    param(
        [Parameter(Mandatory = $true)]
        [int]
        $StatusCode
    )

    return [PodeRequestException]::new($StatusCode)
}

function ConvertTo-PodeResponseContent {
    param(
        [Parameter()]
        $InputObject,

        [Parameter()]
        [string]
        $ContentType,

        [Parameter()]
        [int]
        $Depth = 10,

        [Parameter()]
        [string]
        $Delimiter = ',',

        [switch]
        $AsHtml
    )
    # split for the main content type
    $ContentType = Split-PodeContentType -ContentType $ContentType

    # if there is no content-type then convert straight to string
    if ([string]::IsNullOrWhiteSpace($ContentType)) {
        return ([string]$InputObject)
    }

    # run action for the content type
    switch ($ContentType) {
        { $_ -match '^(.*\/)?(.*\+)?json$' } {
            if ($InputObject -isnot [string]) {
                if ($Depth -le 0) {
                    return (ConvertTo-Json -InputObject $InputObject -Compress)
                }
                else {
                    return (ConvertTo-Json -InputObject $InputObject -Depth $Depth -Compress)
                }
            }

            if ([string]::IsNullOrWhiteSpace($InputObject)) {
                return '{}'
            }
        }

        { $_ -match '^(.*\/)?(.*\+)?yaml$' } {
            if ($InputObject -isnot [string]) {
                if ($Depth -le 0) {
                    return (ConvertTo-PodeYamlInternal -InputObject $InputObject )
                }
                else {
                    return (ConvertTo-PodeYamlInternal -InputObject $InputObject -Depth $Depth  )
                }
            }

            if ([string]::IsNullOrWhiteSpace($InputObject)) {
                return '[]'
            }
        }

        { $_ -match '^(.*\/)?(.*\+)?xml$' } {
            if ($InputObject -isnot [string]) {
                $temp = @(foreach ($item in $InputObject) {
                        [pscustomobject]$item
                    })

                return ($temp | ConvertTo-Xml -Depth $Depth -As String -NoTypeInformation)
            }

            if ([string]::IsNullOrWhiteSpace($InputObject)) {
                return [string]::Empty
            }
        }

        { $_ -ilike '*/csv' } {
            if ($InputObject -isnot [string]) {
                $temp = @(foreach ($item in $InputObject) {
                        [pscustomobject]$item
                    })

                if (Test-PodeIsPSCore) {
                    $temp = ($temp | ConvertTo-Csv -Delimiter $Delimiter -IncludeTypeInformation:$false)
                }
                else {
                    $temp = ($temp | ConvertTo-Csv -Delimiter $Delimiter -NoTypeInformation)
                }

                return ($temp -join ([environment]::NewLine))
            }

            if ([string]::IsNullOrWhiteSpace($InputObject)) {
                return [string]::Empty
            }
        }

        { $_ -ilike '*/html' } {
            if ($InputObject -isnot [string]) {
                return (($InputObject | ConvertTo-Html) -join ([environment]::NewLine))
            }

            if ([string]::IsNullOrWhiteSpace($InputObject)) {
                return [string]::Empty
            }
        }

        { $_ -ilike '*/markdown' } {
            if ($AsHtml -and ($PSVersionTable.PSVersion.Major -ge 7)) {
                return ($InputObject | ConvertFrom-Markdown).Html
            }
        }
    }

    return ([string]$InputObject)
}

function ConvertFrom-PodeRequestContent {
    param(
        [Parameter()]
        $Request,

        [Parameter()]
        [string]
        $ContentType,

        [Parameter()]
        [string]
        $TransferEncoding,

        [Parameter()]
        [ValidateSet('', 'gzip', 'deflate', 'br')]
        [string]
        $ContentEncoding
    )

    # get the requests content type
    $ContentType = Split-PodeContentType -ContentType $ContentType

    # result object for data/files
    $Result = @{
        Data  = @{}
        Files = @{}
    }
    # if there is no content-type then do nothing
    if ([string]::IsNullOrWhiteSpace($ContentType)) {
        return $Result
    }

    # if the content-type is not multipart/form-data, get the string data
    if ($ContentType -ine 'multipart/form-data') {
        # get the content based on server type
        if ($PodeContext.Server.IsServerless) {
            switch ($PodeContext.Server.ServerlessType.ToLowerInvariant()) {
                'awslambda' {
                    $Content = $Request.body
                }

                'azurefunctions' {
                    $Content = $Request.RawBody
                }
            }
        }
        else {
            # if the request is compressed, attempt to uncompress it
            if (![string]::IsNullOrWhiteSpace($TransferEncoding)) {
                $Content = [PodeHelpers]::DecompressBytes($Request.RawBody, $TransferEncoding, $Request.ContentEncoding)
                $Result.decompressedBody = $content
            }elseif (![string]::IsNullOrWhiteSpace($ContentEncoding)) {
                $Content = [PodeHelpers]::DecompressBytes($Request.RawBody, $ContentEncoding, $Request.ContentEncoding)
                $Result.decompressedBody = $content
            }
            else {
                $Content = $Request.Body
            }
        }

        # if there is no content then do nothing
        if ([string]::IsNullOrWhiteSpace($Content)) {
            return $Result
        }

        # check if there is a defined custom body parser
        if ($PodeContext.Server.BodyParsers.ContainsKey($ContentType)) {
            $parser = $PodeContext.Server.BodyParsers[$ContentType]
            $Result.Data = (Invoke-PodeScriptBlock -ScriptBlock $parser.ScriptBlock -Arguments $Content -UsingVariables $parser.UsingVariables -Return)
            $Content = $null
            return $Result
        }
    }
    # run action for the content type
    switch ($ContentType) {
        { $_ -ilike '*/json' } {
            if (Test-PodeIsPSCore) {
                $Result.Data = ($Content | ConvertFrom-Json -AsHashtable)
            }
            else {
                $Result.Data = ConvertTo-PodeHashtable -InputObject ($Content | ConvertFrom-Json)
            }
        }

        { $_ -ilike '*/xml' } {
            $Result.Data = [xml]($Content)
        }

        { $_ -ilike '*/csv' } {
            $Result.Data = ($Content | ConvertFrom-Csv)
        }

        { $_ -ilike '*/x-www-form-urlencoded' } {
            # parse x-www-form-urlencoded data
            $Result.Data = (ConvertFrom-PodeNameValueToHashTable -Collection ([System.Web.HttpUtility]::ParseQueryString($Content)))
        }

        { $_ -ieq 'multipart/form-data' } {
            # parse multipart form data
            $form = $null

            if ($PodeContext.Server.IsServerless) {
                switch ($PodeContext.Server.ServerlessType.ToLowerInvariant()) {
                    'awslambda' {
                        $Content = $Request.body
                    }

                    'azurefunctions' {
                        $Content = $Request.Body
                    }
                }

                $form = [PodeForm]::Parse($Content, $WebEvent.ContentType, [System.Text.Encoding]::UTF8)
            }
            else {
                $Request.ParseFormData()
                $form = $Request.Form
            }

            # set the files/data
            foreach ($file in $form.Files) {
                $Result.Files.Add($file.FileName, $file)
            }

            foreach ($item in $form.Data) {
                if ($item.IsSingular) {
                    $Result.Data.Add($item.Key, $item.Values[0])
                }
                else {
                    $Result.Data.Add($item.Key, $item.Values)
                }
            }

            $form = $null
        }

        default {
            $Result.Data = $Content
        }
    }

    $Content = $null
    return $Result
}
 

function ConvertFrom-PodeNameValueToHashTable {
    param(
        [Parameter()]
        [System.Collections.Specialized.NameValueCollection]
        $Collection
    )

    if ((Get-PodeCount -Object $Collection) -eq 0) {
        return @{}
    }

    $ht = @{}
    foreach ($key in $Collection.Keys) {
        $htKey = $key
        if (!$key) {
            $htKey = ''
        }

        $ht[$htKey] = $Collection.Get($key)
    }

    return $ht
}

<#
.SYNOPSIS
    Gets the count of elements in the provided object or the length of a string.

.DESCRIPTION
    This function returns the count of elements in various types of objects including strings, collections, and arrays.
    If the object is a string, it returns the length of the string. If the object is null or an empty collection, it returns 0.
    This function is useful for determining the size or length of data containers in PowerShell scripts.

.PARAMETER Object
    The object from which the count or length will be determined. This can be a string, array, collection, or any other object that has a Count property.

.OUTPUTS
    [int]
    Returns an integer representing the count of elements or length of the string.

.EXAMPLE
    $array = @(1, 2, 3)
    Get-PodeCount -Object $array

    This example returns 3, as there are three elements in the array.

.EXAMPLE
    $string = "hello"
    Get-PodeCount -Object $string

    This example returns 5, as there are five characters in the string.

.EXAMPLE
    $nullObject = $null
    Get-PodeCount -Object $nullObject

    This example returns 0, as the object is null.
#>
function Get-PodeCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter()]
        $Object  # The object to be evaluated for its count.
    )

    # Check if the object is null.
    if ($null -eq $Object) {
        return 0  # Return 0 if the object is null.
    }

    # Check if the object is a string and return its length.
    if ($Object -is [string]) {
        return $Object.Length
    }

    # Check if the object is a NameValueCollection and is empty.
    if ($Object -is [System.Collections.Specialized.NameValueCollection] -and $Object.Count -eq 0) {
        return 0  # Return 0 if the collection is empty.
    }

    # For other types of collections, return their Count property.
    return $Object.Count
}


<#
.SYNOPSIS
    Tests if a given file system path is valid and optionally if it is not a directory.

.DESCRIPTION
    This function tests if the provided file system path is valid. It checks if the path is not null or whitespace, and if the item at the path exists. If the item exists and is not a directory (unless the $FailOnDirectory switch is not used), it returns true. If the path is not valid, it can optionally set a 404 response status code.

.PARAMETER Path
    The file system path to test for validity.

.PARAMETER NoStatus
    A switch to suppress setting the 404 response status code if the path is not valid.

.PARAMETER FailOnDirectory
    A switch to indicate that the function should return false if the path is a directory.

.PARAMETER Force
    A switch to indicate that the file with the hidden attribute has to be includede

.PARAMETER ReturnItem
    Return the item file item itself instead of true or false

.EXAMPLE
    $isValid = Test-PodePath -Path "C:\temp\file.txt"
    if ($isValid) {
        # The file exists and is not a directory
    }

.EXAMPLE
    $isValid = Test-PodePath -Path "C:\temp\folder" -FailOnDirectory
    if (!$isValid) {
        # The path is a directory or does not exist
    }

.NOTES
    This function is used within the Pode framework to validate file system paths for serving static content.

#>
function Test-PodePath {
    param(
        [Parameter()]
        $Path,

        [switch]
        $NoStatus,

        [switch]
        $FailOnDirectory,

        [switch]
        $Force,

        [switch]
        $ReturnItem
    )

    $statusCode = 404

    if (![string]::IsNullOrWhiteSpace($Path)) {
        try {
            $item = Get-Item $Path -Force:$Force -ErrorAction Stop
            if (($null -ne $item) -and (!$FailOnDirectory -or !$item.PSIsContainer)) {
                $statusCode = 200
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            $statusCode = 404
        }
        catch [System.UnauthorizedAccessException] {
            $statusCode = 401
        }
        catch {
            $statusCode = 400
        }
    }

    if ($statusCode -eq 200) {
        if ($ReturnItem) {
            return $item
        }
        return $true
    }

    # if we failed to get the file, report back the status code and/or return true/false
    if (!$NoStatus) {
        Set-PodeResponseStatus -Code $statusCode
    }

    if ($ReturnItem) {
        return $null
    }

    return $false
}

function Test-PodePathIsFile {
    param(
        [Parameter()]
        [string]
        $Path,

        [switch]
        $FailOnWildcard
    )

    if ([string]::IsNullOrEmpty($Path)) {
        return $false
    }

    if ($FailOnWildcard -and (Test-PodePathIsWildcard -Path $Path)) {
        return $false
    }

    return (![string]::IsNullOrEmpty([System.IO.Path]::GetExtension($Path)))
}

function Test-PodePathIsWildcard {
    param(
        [Parameter()]
        [string]
        $Path
    )

    if ([string]::IsNullOrEmpty($Path)) {
        return $false
    }

    return $Path.Contains('*')
}

function Test-PodePathIsDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [switch]
        $FailOnWildcard

    )

    if ($FailOnWildcard -and (Test-PodePathIsWildcard $Path)) {
        return $false
    }

    return ([string]::IsNullOrWhiteSpace([System.IO.Path]::GetExtension($Path)))
}



function Convert-PodePathPatternToRegex {
    param(
        [Parameter()]
        [string]
        $Path,

        [switch]
        $NotSlashes,

        [switch]
        $NotStrict
    )

    if (!$NotSlashes) {
        if ($Path -match '[\\/]\*$') {
            $Path = $Path -replace '[\\/]\*$', '/{0,1}*'
        }

        $Path = $Path -ireplace '[\\/]', '[\\/]'
    }

    $Path = $Path -ireplace '\.', '\.'
    $Path = $Path -ireplace '\*', '.*?'

    if ($NotStrict) {
        return $Path
    }

    return "^$($Path)$"
}

function Convert-PodePathPatternsToRegex {
    param(
        [Parameter()]
        [string[]]
        $Paths,

        [switch]
        $NotSlashes,

        [switch]
        $NotStrict
    )

    # replace certain chars
    $Paths = @(foreach ($path in $Paths) {
            if (![string]::IsNullOrEmpty($path)) {
                Convert-PodePathPatternToRegex -Path $path -NotStrict -NotSlashes:$NotSlashes
            }
        })

    # if no paths, return null
    if (($null -eq $Paths) -or ($Paths.Length -eq 0)) {
        return $null
    }

    # join them all together
    $joined = "($($Paths -join '|'))"

    if ($NotStrict) {
        return $joined
    }

    return "^$($joined)$"
}

<#
.SYNOPSIS
	Determines the default allowed SSL/TLS protocols based on the operating system.

.DESCRIPTION
	This function detects the operating system and determines the allowed SSL/TLS protocols
	based on the system’s native support. The function returns an array of
	[System.Security.Authentication.SslProtocols] enum values representing the supported protocols.

.OUTPUTS
	A [System.Security.Authentication.SslProtocols] enum array containing the allowed SSL/TLS protocols.

.EXAMPLE
	Get-PodeDefaultSslProtocol
	[System.Security.Authentication.SslProtocols]::Tls12, [System.Security.Authentication.SslProtocols]::Tls13

.NOTES
	This is an internal function and may change in future releases of Pode.
	Overriding the default allowed protocols in configuration does not guarantee their availability.
	If a protocol is not natively supported by the OS, additional OS-level configuration may be required.
#>
function Get-PodeDefaultSslProtocol {
    [CmdletBinding()]
    [OutputType([System.Security.Authentication.SslProtocols])]
    param()
    # Cross-platform detection in PowerShell 7.x
    $AllowedProtocols = @()

    if (Test-PodeIsWindows) {
        # Retrieve Windows OS info
        $osInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
        | Select-Object CurrentBuild, CurrentMajorVersionNumber, CurrentMinorVersionNumber

        $osVersion = [version]"$($osInfo.CurrentMajorVersionNumber).$($osInfo.CurrentMinorVersionNumber).$($osInfo.CurrentBuild)"

        Write-Verbose "Detected OS Version: $osVersion"

        # Determine allowed protocols based on Windows version
        if ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 0) {
            # Windows Vista / Server 2008
            $AllowedProtocols = @('Ssl2', 'Ssl3')
        }
        elseif ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 1) {
            # Windows 7 / Server 2008 R2
            $AllowedProtocols = @('Ssl2', 'Ssl3')
        }
        elseif ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 2) {
            # Windows 8 / Server 2012
            $AllowedProtocols = @('Ssl3', 'Tls', 'Tls11', 'Tls12')
        }
        elseif ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3) {
            # Windows 8.1 / Server 2012 R2
            $AllowedProtocols = @('Ssl3', 'Tls', 'Tls11', 'Tls12')
        }
        elseif ($osVersion.Major -eq 10 -and $osVersion.Build -lt 20170) {
            # Windows 10 (Older builds)
            $AllowedProtocols = @('Tls', 'Tls11', 'Tls12')
        }
        elseif ($osVersion.Major -eq 10 -and $osVersion.Build -ge 20170) {
            # Windows 10 (Newer builds with potential TLS 1.3 support)
            $AllowedProtocols = @('Tls', 'Tls11', 'Tls12', 'Tls13')
        }
        elseif ($osVersion.Major -ge 10 -and $osVersion.Build -ge 22000) {
            # Windows 11 / Server 2022 (Modern protocol set)
            $AllowedProtocols = @('Tls12', 'Tls13')
        }
        else {
            Write-Warning 'Unknown Windows version. Defaulting to modern protocols.'
            $AllowedProtocols = @('Tls', 'Tls11', 'Tls12')
        }
    }
    elseif ($IsMacOS) {
        # Use sw_vers to get macOS version info
        $osName = $(sw_vers -productName)
        $productVersion = $(sw_vers -productVersion).Trim()
        Write-Verbose "Detected OS: $osName, Version: $productVersion"
        $versionObj = [version]$productVersion

        # Determine allowed protocols for macOS
        if ($versionObj -lt [version]'10.11') {
            # macOS 10.8 - 10.10: SSL3 allowed, TLS 1.0/1.1/1.2 allowed, TLS1.3 not supported
            $AllowedProtocols = @('Ssl3', 'Tls', 'Tls11', 'Tls12')
        }
        elseif ($versionObj -ge [version]'10.11' -and $versionObj -lt [version]'10.13') {
            # macOS 10.11 (and likely 10.12): SSL3 disabled, TLS 1.0/1.1/1.2 allowed
            $AllowedProtocols = @('Tls', 'Tls11', 'Tls12')
        }
        else {
            # macOS 10.13 and later: TLS 1.3 is supported in addition to TLS 1.0, 1.1, 1.2
            $AllowedProtocols = @('Tls', 'Tls11', 'Tls12', 'Tls13')
        }
    }
    elseif ($IsLinux) {
        # Read /etc/os-release for OS info if available
        if (Test-Path '/etc/os-release') {
            $osRelease = Get-Content '/etc/os-release' | ConvertFrom-StringData
            $osName = $osRelease.NAME
            $osVersion = $osRelease.VERSION_ID
            Write-Verbose "Detected OS: $osName, Version: $osVersion"
        }
        else {
            $osName = 'Linux'
            Write-Verbose "Detected OS: $osName"
        }

        # Determine allowed protocols based on the installed OpenSSL version.
        try {
            $opensslOutput = openssl version 2>&1
            if ($opensslOutput -match 'OpenSSL\s+([\d\.]+)') {
                $opensslVersion = [version]$matches[1]
                Write-Verbose "Detected OpenSSL version: $opensslVersion"
                if ($opensslVersion -ge [version]'1.1.1') {
                    # OpenSSL 1.1.1 and later support TLS 1.3
                    $AllowedProtocols = @('Tls', 'Tls11', 'Tls12', 'Tls13')
                }
                elseif ($opensslVersion -ge [version]'1.0.1g') {
                    # OpenSSL 1.0.1g up to before 1.1.1 disable SSL3
                    $AllowedProtocols = @('Tls', 'Tls11', 'Tls12')
                }
                else {
                    # OpenSSL 1.0.1 to 1.0.1f: SSL3 is allowed along with TLS 1.0/1.1/1.2
                    $AllowedProtocols = @('Ssl3', 'Tls', 'Tls11', 'Tls12')
                }
            }
            else {
                Write-Warning 'Could not parse OpenSSL version. Defaulting to TLS 1.2.'
                $AllowedProtocols = @('Tls', 'Tls11', 'Tls12')
            }
        }
        catch {
            Write-Warning 'OpenSSL version check failed. Defaulting to TLS 1.2.'
            $AllowedProtocols = @('Tls', 'Tls11', 'Tls12')
        }
    }
    else {
        Write-Warning 'Unknown platform. No allowed protocols determined.'
        $AllowedProtocols = @('Ssl3', 'Tls12')
    }

    Write-Verbose "Allowed protocols: $($AllowedProtocols -join ', ')"

    return (ConvertTo-PodeSslProtocol -Protocol $AllowedProtocols)
}

<#
.SYNOPSIS
    Converts a string representation of SSL protocols to the corresponding SslProtocols enum value.

.DESCRIPTION
    This function takes an array of SSL protocol strings (such as 'Tls', 'Tls12', etc.) and combines them into a single SslProtocols enum value. It's useful for configuring SSL/TLS settings in Pode or other PowerShell scripts.

.PARAMETER Protocol
    An array of SSL protocol strings. Valid values are 'Ssl2', 'Ssl3', 'Tls', 'Tls11', 'Tls12', and 'Tls13'.

.OUTPUTS
    A [System.Security.Authentication.SslProtocols] enum value representing the combined protocols.

.EXAMPLE
    ConvertTo-PodeSslProtocol -Protocol 'Tls', 'Tls12'
    # Returns [System.Security.Authentication.SslProtocols]::Tls12

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function ConvertTo-PodeSslProtocol {
    [CmdletBinding()]
    [OutputType([System.Security.Authentication.SslProtocols])]
    param(
        [Parameter()]
        [ValidateSet('Ssl2', 'Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13')]
        [string[]]
        $Protocol
    )

    $protos = 0
    foreach ($item in $Protocol) {
        $protos = [int]($protos -bor [System.Security.Authentication.SslProtocols]::$item)
    }

    return [System.Security.Authentication.SslProtocols]($protos)
}

<#
.SYNOPSIS
    Retrieves details about the Pode module.

.DESCRIPTION
    This function determines the relevant details of the Pode module. It first checks if the module is already imported.
    If so, it uses that module. Otherwise, it attempts to identify the module used for the 'engine' and retrieves its details.
    If there are multiple versions of the module, it selects the newest version. If no module is imported, it uses the latest installed version.

.OUTPUTS
    A hashtable containing the module details.

.EXAMPLE
    Get-PodeModuleInfo
    # Returns a hashtable with module details such as name, path, base path, data path, internal path, and whether it's in the system path.

    .NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Get-PodeModuleInfo {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    # if there's 1 module imported already, use that
    $importedModule = @(Get-Module -Name Pode)
    if (($importedModule | Measure-Object).Count -eq 1) {
        return (Convert-PodeModuleInfo -Module @($importedModule)[0])
    }

    # if there's none or more, attempt to get the module used for 'engine'
    try {
        $usedModule = (Get-Command -Name 'Set-PodeViewEngine').Module
        if (($usedModule | Measure-Object).Count -eq 1) {
            return (Convert-PodeModuleInfo -Module $usedModule)
        }
    }
    catch {
        $_ | Write-PodeErrorLog -Level Debug
    }

    # if there were multiple to begin with, use the newest version
    if (($importedModule | Measure-Object).Count -gt 1) {
        return (Convert-PodeModuleInfo -Module @($importedModule | Sort-Object -Property Version)[-1])
    }

    # otherwise there were none, use the latest installed
    return (Convert-PodeModuleInfo -Module @(Get-Module -ListAvailable -Name Pode | Sort-Object -Property Version)[-1])
}

<#
.SYNOPSIS
    Converts Pode module details to a hashtable.

.DESCRIPTION
    This function takes a Pode module and extracts relevant details such as name, path, base path, data path, internal path, and whether it's in the system path.

.PARAMETER Module
    The Pode module to convert.

.OUTPUTS
    A hashtable containing the module details.

.EXAMPLE
    Convert-PodeModuleInfo -Module (Get-Module Pode)

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Convert-PodeModuleInfo {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [psmoduleinfo]
        $Module
    )

    $details = @{
        Name         = $Module.Name
        Path         = $Module.Path
        BasePath     = $Module.ModuleBase
        DataPath     = (Find-PodeModuleFile -Module $Module -CheckVersion)
        InternalPath = $null
        InPath       = (Test-PodeModuleInPath -Module $Module)
    }

    $details.InternalPath = $details.DataPath -ireplace 'Pode\.(ps[md]1)', 'Pode.Internal.$1'
    return $details
}

<#
.SYNOPSIS
    Checks if a PowerShell module is located within the directories specified in the PSModulePath environment variable.

.DESCRIPTION
    This function determines if the path of a provided PowerShell module starts with any path included in the system's PSModulePath environment variable.
    This is used to ensure that the module is being loaded from expected locations, which can be important for security and configuration verification.

.PARAMETER Module
    The module to be checked. This should be a module info object, typically obtained via Get-Module or Import-Module.

.OUTPUTS
    [bool]
    Returns $true if the module's path is under a path listed in PSModulePath, otherwise returns $false.

.EXAMPLE
    $module = Get-Module -Name Pode
    Test-PodeModuleInPath -Module $module

    This example checks if the 'Pode' module is located within the paths specified by the PSModulePath environment variable.
#>
function Test-PodeModuleInPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [psmoduleinfo]
        $Module
    )

    # Determine the path separator based on the operating system.
    $separator = if (Test-PodeIsUnix) { ':' } else { ';' }

    # Split the PSModulePath environment variable to get individual paths.
    $paths = @($env:PSModulePath -split $separator)

    # Check each path to see if the module's path starts with it.
    foreach ($path in $paths) {
        # Return true if the module is in one of the paths.
        if ($Module.Path.StartsWith($path)) {
            return $true
        }
    }

    # Return false if no matching path is found.
    return $false
}
<#
.SYNOPSIS
    Retrieves a module and all of its recursive dependencies.

.DESCRIPTION
    This function takes a PowerShell module as input and returns an array containing
    the module and all of its required dependencies, retrieved recursively. This is
    useful for understanding the full set of dependencies a module has.

.PARAMETER Module
    The module for which to retrieve dependencies. This must be a valid PowerShell module object.

.EXAMPLE
    $module = Get-Module -Name SomeModuleName
    $dependencies = Get-PodeModuleDependencyList -Module $module
    This example retrieves all dependencies for "SomeModuleName".

.OUTPUTS
    Array[psmoduleinfo]
    Returns an array of psmoduleinfo objects, each representing a module in the dependency tree.
#>

function Get-PodeModuleDependencyList {
    param(
        [Parameter(Mandatory = $true)]
        [psmoduleinfo]
        $Module
    )

    # Check if the module has any required modules (dependencies).
    if (!$Module.RequiredModules) {
        return $Module
    }
    # Initialize an array to hold all dependencies.
    $mods = @()

    # Iterate through each required module and recursively retrieve their dependencies.
    foreach ($mod in $Module.RequiredModules) {
        # Recursive call for each dependency.
        $mods += (Get-PodeModuleDependencyList -Module $mod)
    }

    # Return the list of all dependencies plus the original module.
    return ($mods + $module)
}

function Get-PodeModuleRootPath {
    return (Split-Path -Parent -Path $PodeContext.Server.PodeModule.Path)
}

function Get-PodeModuleMiscPath {
    return [System.IO.Path]::Combine((Get-PodeModuleRootPath), 'Misc')
}

function Get-PodeUrl {
    return "$($WebEvent.Endpoint.Protocol)://$($WebEvent.Endpoint.Address)$($WebEvent.Path)"
}

function Find-PodeErrorPage {
    param(
        [Parameter()]
        [int]
        $Code,

        [Parameter()]
        [string]
        $ContentType
    )

    # if a defined content type is supplied, attempt to find an error page for that first
    if (![string]::IsNullOrWhiteSpace($ContentType)) {
        $path = Get-PodeErrorPage -Code $Code -ContentType $ContentType
        if (![string]::IsNullOrWhiteSpace($path)) {
            return @{ 'Path' = $path; 'ContentType' = $ContentType }
        }
    }

    # if a defined route error page content type is supplied, attempt to find an error page for that
    if (![string]::IsNullOrWhiteSpace($WebEvent.ErrorType)) {
        $path = Get-PodeErrorPage -Code $Code -ContentType $WebEvent.ErrorType
        if (![string]::IsNullOrWhiteSpace($path)) {
            return @{ 'Path' = $path; 'ContentType' = $WebEvent.ErrorType }
        }
    }

    # if route patterns have been defined, see if an error content type matches and attempt that
    if (!(Test-PodeIsEmpty $PodeContext.Server.Web.ErrorPages.Routes)) {
        # find type by pattern
        $matched = @(foreach ($key in $PodeContext.Server.Web.ErrorPages.Routes.Keys) {
                if ($WebEvent.Path -imatch $key) {
                    $key
                }
            })[0]

        # if we have a match, see if a page exists
        if (!(Test-PodeIsEmpty $matched)) {
            $type = $PodeContext.Server.Web.ErrorPages.Routes[$matched]
            $path = Get-PodeErrorPage -Code $Code -ContentType $type
            if (![string]::IsNullOrWhiteSpace($path)) {
                return @{ 'Path' = $path; 'ContentType' = $type }
            }
        }
    }

    # if we're using strict typing, attempt that, if we have a content type
    if ($PodeContext.Server.Web.ErrorPages.StrictContentTyping -and ![string]::IsNullOrWhiteSpace($WebEvent.ContentType)) {
        $path = Get-PodeErrorPage -Code $Code -ContentType $WebEvent.ContentType
        if (![string]::IsNullOrWhiteSpace($path)) {
            return @{ 'Path' = $path; 'ContentType' = $WebEvent.ContentType }
        }
    }

    # if we have a default defined, attempt that
    if (!(Test-PodeIsEmpty $PodeContext.Server.Web.ErrorPages.Default)) {
        $path = Get-PodeErrorPage -Code $Code -ContentType $PodeContext.Server.Web.ErrorPages.Default
        if (![string]::IsNullOrWhiteSpace($path)) {
            return @{ 'Path' = $path; 'ContentType' = $PodeContext.Server.Web.ErrorPages.Default }
        }
    }

    # if there's still no error page, use default HTML logic
    $type = Get-PodeContentType -Extension 'html'
    $path = (Get-PodeErrorPage -Code $Code -ContentType $type)

    if (![string]::IsNullOrWhiteSpace($path)) {
        return @{ 'Path' = $path; 'ContentType' = $type }
    }

    return $null
}

function Get-PodeErrorPage {
    param(
        [Parameter()]
        [int]
        $Code,

        [Parameter()]
        [string]
        $ContentType
    )

    # parse the passed content type
    $ContentType = Split-PodeContentType -ContentType $ContentType

    # object for the page path
    $path = $null

    # attempt to find a custom error page
    $path = Find-PodeCustomErrorPage -Code $Code -ContentType $ContentType

    # if there's no custom page found, attempt to find an inbuilt page
    if ([string]::IsNullOrWhiteSpace($path)) {
        $podeRoot = Get-PodeModuleMiscPath
        $path = Find-PodeFileForContentType -Path $podeRoot -Name 'default-error-page' -ContentType $ContentType -Engine 'pode'
    }

    # if there's no path found, or it's inaccessible, return null
    if (!(Test-PodePath $path -NoStatus)) {
        return $null
    }

    return $path
}

function Find-PodeCustomErrorPage {
    param(
        [Parameter()]
        [int]
        $Code,

        [Parameter()]
        [string]
        $ContentType
    )

    # get the custom errors path
    $customErrPath = $PodeContext.Server.InbuiltDrives['errors']

    # if there's no custom error path, return
    if ([string]::IsNullOrWhiteSpace($customErrPath)) {
        return $null
    }

    # retrieve a status code page
    $path = (Find-PodeFileForContentType -Path $customErrPath -Name "$($Code)" -ContentType $ContentType)
    if (![string]::IsNullOrWhiteSpace($path)) {
        return $path
    }

    # retrieve default page
    $path = (Find-PodeFileForContentType -Path $customErrPath -Name 'default' -ContentType $ContentType)
    if (![string]::IsNullOrWhiteSpace($path)) {
        return $path
    }

    # no file was found
    return $null
}

function Find-PodeFileForContentType {
    param(
        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Name,

        [Parameter()]
        [string]
        $ContentType,

        [Parameter()]
        [string]
        $Engine = $null
    )

    # get all files at the path that start with the name
    $files = @(Get-ChildItem -Path ([System.IO.Path]::Combine($Path, "$($Name).*")))

    # if there are no files, return
    if ($null -eq $files -or $files.Length -eq 0) {
        return $null
    }

    # filter the files by the view engine extension (but only if the current engine is dynamic - non-html)
    if ([string]::IsNullOrWhiteSpace($Engine) -and $PodeContext.Server.ViewEngine.IsDynamic) {
        $Engine = $PodeContext.Server.ViewEngine.Extension
    }

    $Engine = (Protect-PodeValue -Value $Engine -Default 'pode')
    if ($Engine -ine 'pode') {
        $Engine = "($($Engine)|pode)"
    }

    $engineFiles = @(foreach ($file in $files) {
            if ($file.Name -imatch "\.$($Engine)$") {
                $file
            }
        })

    $files = @(foreach ($file in $files) {
            if ($file.Name -inotmatch "\.$($Engine)$") {
                $file
            }
        })

    # only attempt static files if we still have files after any engine filtering
    if ($null -ne $files -and $files.Length -gt 0) {
        # get files of the format '<name>.<type>'
        $file = @(foreach ($f in $files) {
                if ($f.Name -imatch "^$($Name)\.(?<ext>.*?)$") {
                    if (($ContentType -ieq (Get-PodeContentType -Extension $Matches['ext']))) {
                        $f.FullName
                    }
                }
            })[0]

        if (![string]::IsNullOrWhiteSpace($file)) {
            return $file
        }
    }

    # only attempt these formats if we have a files for the view engine
    if ($null -ne $engineFiles -and $engineFiles.Length -gt 0) {
        # get files of the format '<name>.<type>.<engine>'
        $file = @(foreach ($f in $engineFiles) {
                if ($f.Name -imatch "^$($Name)\.(?<ext>.*?)\.$($engine)$") {
                    if ($ContentType -ieq (Get-PodeContentType -Extension $Matches['ext'])) {
                        $f.FullName
                    }
                }
            })[0]

        if (![string]::IsNullOrWhiteSpace($file)) {
            return $file
        }

        # get files of the format '<name>.<engine>'
        $file = @(foreach ($f in $engineFiles) {
                if ($f.Name -imatch "^$($Name)\.$($engine)$") {
                    $f.FullName
                }
            })[0]

        if (![string]::IsNullOrWhiteSpace($file)) {
            return $file
        }
    }

    # no file was found
    return $null
}

<#
.SYNOPSIS
	Resolves and processes a relative or absolute file system path based on the specified parameters.

.DESCRIPTION
	This function processes a given path and applies various transformations and checks based on the provided parameters. It supports resolving relative paths, joining them with a root path, normalizing relative paths, and verifying path existence.

.PARAMETER Path
	The file system path to be processed. This can be relative or absolute.

.PARAMETER RootPath
	(Optional) The root path to join with if the provided path is relative and the -JoinRoot switch is enabled.

.PARAMETER JoinRoot
	Indicates that the relative path should be joined to the specified root path. If no RootPath is provided, the Pode context server root will be used.

.PARAMETER Resolve
	Resolves the path to its absolute, full path.

.PARAMETER TestPath
	Verifies if the resolved path exists. Throws an exception if the path does not exist.

.OUTPUTS
	System.String
	Returns the resolved and processed path as a string.

.EXAMPLE
	# Example 1: Resolve a relative path and join it with a root path
	Get-PodeRelativePath -Path './example' -RootPath 'C:\Root' -JoinRoot

.EXAMPLE
	# Example 3: Test if a path exists
	Get-PodeRelativePath -Path 'C:\Root\example.txt' -TestPath

.NOTES
	This is an internal function and may change in future releases of Pode
#>
function Get-PodeRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $RootPath,

        [switch]
        $JoinRoot,

        [switch]
        $Resolve,

        [switch]
        $TestPath
    )

    # if the path is relative, join to root if flagged
    if ($JoinRoot -and ($Path -match '^\.{1,2}([\\\/]|$)')) {
        if ([string]::IsNullOrWhiteSpace($RootPath)) {
            $RootPath = $PodeContext.Server.Root
        }

        $Path = [System.IO.Path]::Combine($RootPath, $Path)
    }

    # if flagged, resolve the path
    if ($Resolve) {
        $_rawPath = $Path
        $Path = [System.IO.Path]::GetFullPath($Path.Replace('\', '/'))
    }

    # if flagged, test the path and throw error if it doesn't exist
    if ($TestPath -and !(Test-PodePath $Path -NoStatus)) {
        # "The path does not exist: $(Protect-PodeValue -Value $Path -Default $_rawPath)"
        throw ($PodeLocale.pathNotExistExceptionMessage -f (Protect-PodeValue -Value $Path -Default $_rawPath))
    }

    return $Path
}

<#
.SYNOPSIS
    Retrieves files based on a wildcard pattern in a given path.

.DESCRIPTION
    The `Get-PodeWildcardFile` function returns files from the specified path based on a wildcard pattern.
    You can customize the wildcard and provide an optional root path for relative paths.

.PARAMETER Path
    Specifies the path to search for files. This parameter is mandatory.

.PARAMETER Wildcard
    Specifies the wildcard pattern for file matching. Default is '*.*'.

.PARAMETER RootPath
    Specifies an optional root path for relative paths. If provided, the function will join the root path with the specified path.

.OUTPUTS
    Returns an array of file paths matching the wildcard pattern.

.EXAMPLE
    # Example usage:
    $files = Get-PodeWildcardFile -Path '/path/to/files' -Wildcard '*.txt'
    # Returns an array of .txt files in the specified path.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Get-PodeWildcardFile {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Wildcard = '*.*',

        [Parameter()]
        [string]
        $RootPath
    )

    # if the OriginalPath is a directory, add wildcard
    if (Test-PodePathIsDirectory -Path $Path) {
        $Path = [System.IO.Path]::Combine($Path, $Wildcard)
    }

    # if path has a *, assume wildcard
    if (Test-PodePathIsWildcard -Path $Path) {
        $Path = Get-PodeRelativePath -Path $Path -RootPath $RootPath -JoinRoot
        return @((Get-ChildItem $Path -Recurse -Force).FullName)
    }

    return $null
}

function Test-PodeIsServerless {
    param(
        [Parameter()]
        [string]
        $FunctionName,

        [switch]
        $ThrowError
    )

    if ($PodeContext.Server.IsServerless -and $ThrowError) {
        throw ($PodeLocale.unsupportedFunctionInServerlessContextExceptionMessage -f $FunctionName) #"The $($FunctionName) function is not supported in a serverless context"
    }

    if (!$ThrowError) {
        return $PodeContext.Server.IsServerless
    }
}

function Get-PodeEndpointUrl {
    param(
        [Parameter()]
        $Endpoint
    )

    # get the endpoint on which we're currently listening - use first http/https if there are many
    if ($null -eq $Endpoint) {
        $Endpoint = @($PodeContext.Server.Endpoints.Values | Where-Object { $_.Protocol -iin @('http', 'https') -and $_.Default })[0]
        if ($null -eq $Endpoint) {
            $Endpoint = @($PodeContext.Server.Endpoints.Values | Where-Object { $_.Protocol -iin @('http', 'https') })[0]
        }
    }

    if ($null -eq $Endpoint) {
        return $null
    }

    $url = $Endpoint.Url
    if ([string]::IsNullOrWhiteSpace($url)) {
        $url = "$($Endpoint.Protocol)://$($Endpoint.FriendlyName):$($Endpoint.Port)"
    }

    return $url
}

function Get-PodeDefaultPort {
    param(
        [Parameter()]
        [ValidateSet('Http', 'Https', 'Smtp', 'Smtps', 'Tcp', 'Tcps', 'Ws', 'Wss')]
        [string]
        $Protocol,

        [Parameter()]
        [ValidateSet('Implicit', 'Explicit')]
        [string]
        $TlsMode = 'Implicit',

        [switch]
        $Real
    )

    # are we after the real default ports?
    if ($Real) {
        return (@{
                Http  = @{ Implicit = 80 }
                Https = @{ Implicit = 443 }
                Smtp  = @{ Implicit = 25 }
                Smtps = @{ Implicit = 465; Explicit = 587 }
                Tcp   = @{ Implicit = 9001 }
                Tcps  = @{ Implicit = 9002; Explicit = 9003 }
                Ws    = @{ Implicit = 80 }
                Wss   = @{ Implicit = 443 }
            })[$Protocol.ToLowerInvariant()][$TlsMode.ToLowerInvariant()]
    }

    # if we running as iis, return the ASPNET port
    if ($PodeContext.Server.IsIIS) {
        return [int]$env:ASPNETCORE_PORT
    }

    # if we running as heroku, return the port
    if ($PodeContext.Server.IsHeroku) {
        return [int]$env:PORT
    }

    # otherwise, get the port for the protocol
    return (@{
            Http  = @{ Implicit = 8080 }
            Https = @{ Implicit = 8443 }
            Smtp  = @{ Implicit = 25 }
            Smtps = @{ Implicit = 465; Explicit = 587 }
            Tcp   = @{ Implicit = 9001 }
            Tcps  = @{ Implicit = 9002; Explicit = 9003 }
            Ws    = @{ Implicit = 9080 }
            Wss   = @{ Implicit = 9443 }
        })[$Protocol.ToLowerInvariant()][$TlsMode.ToLowerInvariant()]
}

function Set-PodeServerHeader {
    param(
        [Parameter()]
        [string]
        $Type,

        [switch]
        $AllowEmptyType
    )

    $name = 'Pode'
    if (![string]::IsNullOrWhiteSpace($Type) -or $AllowEmptyType) {
        $name += " - $($Type)"
    }

    Set-PodeHeader -Name 'Server' -Value $name
}

function Get-PodeHandler {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Service', 'Smtp')]
        [string]
        $Type,

        [Parameter()]
        [string]
        $Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $PodeContext.Server.Handlers[$Type]
    }

    return $PodeContext.Server.Handlers[$Type][$Name]
}

function Convert-PodeFileToScriptBlock {
    param(
        [Parameter(Mandatory = $true)]
        [Alias('FilePath')]
        [string]
        $Path
    )

    # resolve for relative path
    $Path = Get-PodeRelativePath -Path $Path -JoinRoot

    # if Path doesn't exist, error
    if (!(Test-PodePath -Path $Path -NoStatus)) {
        throw ($PodeLocale.pathNotExistExceptionMessage -f $Path) #  "The Path supplied does not exist: $($Path)"
    }

    # if the path is a wildcard or directory, error
    if (!(Test-PodePathIsFile -Path $Path -FailOnWildcard)) {
        throw ($PodeLocale.invalidPathWildcardOrDirectoryExceptionMessage -f $Path) # "The Path supplied cannot be a wildcard or a directory: $($Path)"
    }

    return ([scriptblock](Use-PodeScript -Path $Path))
}

function Convert-PodeQueryStringToHashTable {
    param(
        [Parameter()]
        [string]
        $Uri
    )

    if ([string]::IsNullOrWhiteSpace($Uri)) {
        return @{}
    }

    $qmIndex = $Uri.IndexOf('?')
    if ($qmIndex -eq -1) {
        return @{}
    }

    if ($qmIndex -gt 0) {
        $Uri = $Uri.Substring($qmIndex)
    }

    $tmpQuery = [System.Web.HttpUtility]::ParseQueryString($Uri)
    return (ConvertFrom-PodeNameValueToHashTable -Collection $tmpQuery)
}

function Get-PodeAstFromFile {
    param(
        [Parameter(Mandatory = $true)]
        [Alias('FilePath')]
        [string]
        $Path
    )

    if (!(Test-Path $Path)) {
        throw ($PodeLocale.pathNotExistExceptionMessage -f $Path) #  "The Path supplied does not exist: $($Path)"
    }

    return [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
}

function Get-PodeFunctionsFromFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $FilePath
    )

    $ast = Get-PodeAstFromFile -FilePath $FilePath
    return @(Get-PodeFunctionsFromAst -Ast $ast)
}

function Get-PodeFunctionsFromAst {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]
        $Ast
    )

    $funcs = @(($Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)))

    return @(foreach ($func in $funcs) {
            # skip null
            if ($null -eq $func) {
                continue
            }

            # skip pode funcs
            if ($func.Name -ilike '*-Pode*') {
                continue
            }

            # definition
            $def = "$($func.Body)".Trim('{}').Trim()
            if (($null -ne $func.Parameters) -and ($func.Parameters.Count -gt 0)) {
                $def = "param($($func.Parameters.Name -join ','))`n$($def)"
            }

            # the found func
            @{
                Name       = $func.Name
                Definition = $def
            }
        })
}

function Get-PodeFunctionsFromScriptBlock {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock
    )

    # functions that have been found
    $foundFuncs = @()

    # get each function in the callstack
    $callstack = Get-PSCallStack
    if ($callstack.Count -gt 3) {
        $callstack = ($callstack | Select-Object -Skip 4)
        $bindingFlags = [System.Reflection.BindingFlags]'NonPublic, Instance, Static'

        foreach ($call in $callstack) {
            $_funcContext = $call.GetType().GetProperty('FunctionContext', $bindingFlags).GetValue($call, $null)
            $_scriptBlock = $_funcContext.GetType().GetField('_scriptBlock', $bindingFlags).GetValue($_funcContext)
            $foundFuncs += @(Get-PodeFunctionsFromAst -Ast $_scriptBlock.Ast)
        }
    }

    # get each function from the main script
    $foundFuncs += @(Get-PodeFunctionsFromAst -Ast $ScriptBlock.Ast)

    # return the found functions
    return $foundFuncs
}

<#
.SYNOPSIS
    Reads details from a web exception and returns relevant information.

.DESCRIPTION
    The `Read-PodeWebExceptionInfo` function processes a web exception (either `WebException` or `HttpRequestException`)
    and extracts relevant details such as status code, status description, and response body.

.PARAMETER ErrorRecord
    Specifies the error record containing the web exception. This parameter is mandatory.

.OUTPUTS
    Returns a hashtable with the following keys:
    - `Status`: A nested hashtable with `Code` (status code) and `Description` (status description).
    - `Body`: The response body from the web exception.

.EXAMPLE
    # Example usage:
    $errorRecord = Get-ErrorRecordFromWebException
    $details = Read-PodeWebExceptionInfo -ErrorRecord $errorRecord
    # Returns a hashtable with status code, description, and response body.

.NOTES
    This is an internal function and may change in future releases of Pode
#>
function Read-PodeWebExceptionInfo {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    switch ($ErrorRecord) {
        { $_.Exception -is [System.Net.WebException] } {
            $stream = $_.Exception.Response.GetResponseStream()
            $stream.Position = 0

            $body = [System.IO.StreamReader]::new($stream).ReadToEnd()
            $code = [int]$_.Exception.Response.StatusCode
            $desc = $_.Exception.Response.StatusDescription
        }

        { $_.Exception -is [System.Net.Http.HttpRequestException] } {
            $body = $_.ErrorDetails.Message
            $code = [int]$_.Exception.Response.StatusCode
            $desc = $_.Exception.Response.ReasonPhrase
        }

        default {
            #Exception is of an invalid type, should be either WebException or HttpRequestException
            throw ($PodeLocale.invalidWebExceptionTypeExceptionMessage -f ($_.Exception.GetType().Name))
        }
    }

    return @{
        Status = @{
            Code        = $code
            Description = $desc
        }
        Body   = $body
    }
}

function Use-PodeFolder {
    param(
        [Parameter()]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [string]
        $DefaultPath
    )

    # use default, or custom path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-PodeServerRoot -Folder $DefaultPath
    }
    else {
        $Path = Get-PodeRelativePath -Path $Path -JoinRoot
    }

    # fail if path not found
    if (!(Test-PodePath -Path $Path -NoStatus)) {
        throw ($PodeLocale.pathToLoadNotFoundExceptionMessage -f $DefaultPath, $Path) #"Path to load $($DefaultPath) not found: $($Path)"
    }

    # get .ps1 files and load them
    Get-ChildItem -Path $Path -Filter *.ps1 -Force -Recurse | ForEach-Object {
        Use-PodeScript -Path $_.FullName
    }
}

function Find-PodeModuleFile {
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]
        $Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'Module')]
        [psmoduleinfo]
        $Module,

        [switch]
        $ListAvailable,

        [switch]
        $DataOnly,

        [switch]
        $CheckVersion
    )

    # get module and check psd1, then psm1
    if ($null -eq $Module) {
        $Module = (Get-Module -Name $Name -ListAvailable:$ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1)
    }

    # if the path isn't already a psd1 do this
    $path = Join-Path $Module.ModuleBase "$($Module.Name).psd1"
    if (!(Test-Path $path)) {
        # if we only want a psd1, return null
        if ($DataOnly) {
            $path = $null
        }
        else {
            $path = $Module.Path
        }
    }

    # check the Version of the psd1
    elseif ($CheckVersion) {
        $data = Import-PowerShellDataFile -Path $path -ErrorAction Stop

        $version = $null
        if (![version]::TryParse($data.ModuleVersion, [ref]$version)) {
            if ($DataOnly) {
                $path = $null
            }
            else {
                $path = $Module.Path
            }
        }
    }

    return $path
}

<#
.SYNOPSIS
    Clears the inner keys of a hashtable.

.DESCRIPTION
    This function takes a hashtable as input and clears the values associated with each inner key. If the input hashtable is empty or null, no action is taken.

.PARAMETER InputObject
    The hashtable to process.

.EXAMPLE
    $myHashtable = @{
        'Key1' = 'Value1'
        'Key2' = 'Value2'
    }
    Clear-PodeHashtableInnerKey -InputObject $myHashtable
    # Clears the values associated with 'Key1' and 'Key2' in the hashtable.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Clear-PodeHashtableInnerKey {
    param(
        [Parameter()]
        [hashtable]
        $InputObject
    )

    if (Test-PodeIsEmpty $InputObject) {
        return
    }

    $InputObject.Keys.Clone() | ForEach-Object {
        $InputObject[$_].Clear()
    }
}

function Set-PodeCronInterval {
    param(
        [Parameter()]
        [hashtable]
        $Cron,

        [Parameter()]
        [string]
        $Type,

        [Parameter()]
        [int[]]
        $Value,

        [Parameter()]
        [int]
        $Interval
    )

    if ($Interval -le 0) {
        return $false
    }

    if ($Value.Length -gt 1) {
        throw ($PodeLocale.singleValueForIntervalExceptionMessage -f $Type) #"You can only supply a single $($Type) value when using intervals"
    }

    if ($Value.Length -eq 1) {
        $Cron[$Type] = "$(@($Value)[0])"
    }

    $Cron[$Type] += "/$($Interval)"
    return ($Value.Length -eq 1)
}

function Test-PodeModuleInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    return ($null -ne (Get-Module -Name $Name -ListAvailable -ErrorAction Ignore -Verbose:$false))
}

function Get-PodePlaceholderRegex {
    return '\:(?<tag>[\w]+)'
}

<#
.SYNOPSIS
    Resolves placeholders in a given path using a specified regex pattern.

.DESCRIPTION
    The `Resolve-PodePlaceholder` function replaces placeholders in the provided path
    with custom placeholders based on the specified regex pattern. You can customize
    the prepend and append strings for the new placeholders. Additionally, you can
    choose to escape slashes in the path.

.PARAMETER Path
    Specifies the path to resolve. This parameter is mandatory.

.PARAMETER Pattern
    Specifies the regex pattern for identifying placeholders. If not provided, the default
    placeholder regex pattern from `Get-PodePlaceholderRegex` is used.

.PARAMETER Prepend
    Specifies the string to prepend to the new placeholders. Default is '(?<'.

.PARAMETER Append
    Specifies the string to append to the new placeholders. Default is '>[^\/]+?)'.

.PARAMETER Slashes
    If specified, escapes slashes in the path.

.OUTPUTS
    Returns the resolved path with replaced placeholders.

.EXAMPLE
    # Example usage:
    $originalPath = '/api/users/{id}'
    $resolvedPath = Resolve-PodePlaceholder -Path $originalPath
    # Returns '/api/users/(?<id>[^\/]+?)' with custom placeholders.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Resolve-PodePlaceholder {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Pattern,

        [Parameter()]
        [string]
        $Prepend = '(?<',

        [Parameter()]
        [string]
        $Append = '>[^\/]+?)',

        [switch]
        $Slashes
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) {
        $Pattern = Get-PodePlaceholderRegex
    }

    if ($Path -imatch $Pattern) {
        $Path = [regex]::Escape($Path)
    }

    if ($Slashes) {
        $Path = ($Path.TrimEnd('\/') -replace '(\\\\|\/)', '[\\\/]')
        $Path = "$($Path)[\\\/]"
    }

    return (Convert-PodePlaceholder -Path $Path -Pattern $Pattern -Prepend $Prepend -Append $Append)
}

<#
.SYNOPSIS
    Converts placeholders in a given path using a specified regex pattern.

.DESCRIPTION
    The `Convert-PodePlaceholder` function replaces placeholders in the provided path
    with custom placeholders based on the specified regex pattern. You can customize
    the prepend and append strings for the new placeholders.

.PARAMETER Path
    Specifies the path to convert. This parameter is mandatory.

.PARAMETER Pattern
    Specifies the regex pattern for identifying placeholders. If not provided, the default
    placeholder regex pattern from `Get-PodePlaceholderRegex` is used.

.PARAMETER Prepend
    Specifies the string to prepend to the new placeholders. Default is '(?<'.

.PARAMETER Append
    Specifies the string to append to the new placeholders. Default is '>[^\/]+?)'.

.OUTPUTS
    Returns the path with replaced placeholders.

.EXAMPLE
    # Example usage:
    $originalPath = '/api/users/{id}'
    $convertedPath = Convert-PodePlaceholder -Path $originalPath
    # Returns '/api/users/(?<id>[^\/]+?)' with custom placeholders.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Convert-PodePlaceholder {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Pattern,

        [Parameter()]
        [string]
        $Prepend = '(?<',

        [Parameter()]
        [string]
        $Append = '>[^\/]+?)'
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) {
        $Pattern = Get-PodePlaceholderRegex
    }

    while ($Path -imatch $Pattern) {
        $Path = ($Path -ireplace $Matches[0], "$($Prepend)$($Matches['tag'])$($Append)")
    }

    return $Path
}

<#
.SYNOPSIS
    Tests whether a given path contains a placeholder based on a specified regex pattern.

.DESCRIPTION
    The `Test-PodePlaceholder` function checks if the provided path contains a placeholder
    by matching it against a regex pattern. Placeholders are typically used for dynamic values.

.PARAMETER Path
    Specifies the path to test. This parameter is mandatory.

.PARAMETER Placeholder
    Specifies the regex pattern for identifying placeholders. If not provided, the default
    placeholder regex pattern from `Get-PodePlaceholderRegex` is used.

.OUTPUTS
    Returns `$true` if the path contains a placeholder; otherwise, returns `$false`.

.EXAMPLE
    # Example usage:
    $isPlaceholder = Test-PodePlaceholder -Path '/api/users/{id}'
    # Returns $true because the path contains a placeholder.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Test-PodePlaceholder {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Placeholder
    )

    if ([string]::IsNullOrWhiteSpace($Placeholder)) {
        $Placeholder = Get-PodePlaceholderRegex
    }

    return ($Path -imatch $Placeholder)
}


<#
.SYNOPSIS
Retrieves the PowerShell module manifest object for the specified module.

.DESCRIPTION
This function constructs the path to a PowerShell module manifest file (.psd1) located in the parent directory of the script root. It then imports the module manifest file to access its properties and returns the manifest object. This can be useful for scripts that need to dynamically discover and utilize module metadata, such as version, dependencies, and exported functions.

.PARAMETERS
This function does not accept any parameters.

.EXAMPLE
$manifest = Get-PodeModuleManifest
This example calls the `Get-PodeModuleManifest` function to retrieve the module manifest object and stores it in the variable `$manifest`.

#>
function Get-PodeModuleManifest {
    # Construct the path to the module manifest (.psd1 file)
    $moduleManifestPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Pode.psd1'

    # Import the module manifest to access its properties
    $moduleManifest = Import-PowerShellDataFile -Path $moduleManifestPath
    return  $moduleManifest
}

<#
.SYNOPSIS
    Tests the running PowerShell version for compatibility with Pode, identifying end-of-life (EOL) and untested versions.

.DESCRIPTION
    The `Test-PodeVersionPwshEOL` function checks the current PowerShell version against a list of versions that were either supported or EOL at the time of the Pode release. It uses the module manifest to determine which PowerShell versions are considered EOL and which are officially supported. If the current version is EOL or was not tested with the current release of Pode, the function generates a warning. This function aids in maintaining best practices for using supported PowerShell versions with Pode.

.PARAMETER ReportUntested
    If specified, the function will report if the current PowerShell version was not available and thus untested at the time of the Pode release. This is useful for identifying potential compatibility issues with newer versions of PowerShell.

.OUTPUTS
    A hashtable containing two keys:
    - `eol`: A boolean indicating if the current PowerShell version was EOL at the time of the Pode release.
    - `supported`: A boolean indicating if the current PowerShell version was officially supported by Pode at the time of the release.

.EXAMPLE
    Test-PodeVersionPwshEOL

    Checks the current PowerShell version against Pode's supported and EOL versions list. Outputs a warning if the version is EOL or untested, and returns a hashtable indicating the compatibility status.

.EXAMPLE
    Test-PodeVersionPwshEOL -ReportUntested

    Similar to the basic usage, but also reports if the current PowerShell version was untested because it was not available at the time of the Pode release.

.NOTES
    This function is part of the Pode module's utilities to ensure compatibility and encourage the use of supported PowerShell versions.

#>
function Test-PodeVersionPwshEOL {
    param(
        [switch] $ReportUntested
    )
    $moduleManifest = Get-PodeModuleManifest
    if ($moduleManifest.ModuleVersion -eq '$version$') {
        return @{
            eol       = $false
            supported = $true
        }
    }

    $psVersion = $PSVersionTable.PSVersion
    $eolVersions = $moduleManifest.PrivateData.PwshVersions.Untested -split ','
    $isEol = "$($psVersion.Major).$($psVersion.Minor)" -in $eolVersions

    if ($isEol) {
        # [WARNING] Pode version has not been tested on PowerShell version, as it is EOL
        Write-PodeHost ($PodeLocale.eolPowerShellWarningMessage -f $PodeVersion, $PSVersion) -ForegroundColor Yellow
    }

    $SupportedVersions = $moduleManifest.PrivateData.PwshVersions.Supported -split ','
    $isSupported = "$($psVersion.Major).$($psVersion.Minor)" -in $SupportedVersions

    if ((! $isSupported) -and (! $isEol) -and $ReportUntested) {
        # [WARNING] Pode version has not been tested on PowerShell version, as it was not available when Pode was released
        Write-PodeHost ($PodeLocale.untestedPowerShellVersionWarningMessage -f $PodeVersion, $PSVersion) -ForegroundColor Yellow
    }

    return @{
        eol       = $isEol
        supported = $isSupported
    }
}


<#
.SYNOPSIS
    creates a YAML description of the data in the object - based on https://github.com/Phil-Factor/PSYaml

.DESCRIPTION
    This produces YAML from any object you pass to it.

.PARAMETER Object
    The object that you want scripted out. This parameter accepts input via the pipeline.

.PARAMETER Depth
    The depth that you want your object scripted to

.EXAMPLE
    Get-PodeOpenApiDefinition|ConvertTo-PodeYaml
#>
function ConvertTo-PodeYaml {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        $InputObject,

        [parameter()]
        [int]
        $Depth = 16
    )

    begin {
        $pipelineObject = @()
    }

    process {
        $pipelineObject += $_
    }

    end {
        if ($pipelineObject.Count -gt 1) {
            $InputObject = $pipelineObject
        }

        if ($PodeContext.Server.Web.OpenApi.UsePodeYamlInternal) {
            return ConvertTo-PodeYamlInternal -InputObject $InputObject -Depth $Depth -NoNewLine
        }

        if ($null -eq $PodeContext.Server.InternalCache.YamlModuleImported) {
            $PodeContext.Server.InternalCache.YamlModuleImported = ((Test-PodeModuleInstalled -Name 'PSYaml') -or (Test-PodeModuleInstalled -Name 'powershell-yaml'))
        }

        if ($PodeContext.Server.InternalCache.YamlModuleImported) {
            return ($InputObject | ConvertTo-Yaml)
        }
        else {
            return ConvertTo-PodeYamlInternal -InputObject $InputObject -Depth $Depth -NoNewLine
        }
    }
}

<#
.SYNOPSIS
    Converts PowerShell objects into a YAML-formatted string.

.DESCRIPTION
    This function takes PowerShell objects and converts them to a YAML string representation.
    It supports various data types including arrays, hashtables, strings, and more.
    The depth of conversion can be controlled, allowing for nested objects to be accurately represented.

.PARAMETER InputObject
    The PowerShell object to convert to YAML.

.PARAMETER Depth
    Specifies the maximum depth of object nesting to convert. Default is 10 levels deep.

.PARAMETER NestingLevel
    Used internally to track the current depth of recursion. Generally not specified by the user.

.PARAMETER NoNewLine
    If specified, suppresses the newline characters in the output to create a single-line string.

.OUTPUTS
    System.String. Returns a string in YAML format.

.EXAMPLE
    ConvertTo-PodeYamlInternal -InputObject $object

    Converts the object into a YAML string.

.NOTES
    This is an internal function and may change in future releases of Pode.
    It converts only basic PowerShell types, such as strings, integers, booleans, arrays, hashtables, and ordered dictionaries into a YAML format.

#>
function ConvertTo-PodeYamlInternal {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [parameter(Mandatory = $true)]
        [AllowNull()]
        $InputObject,

        [parameter()]
        [int]
        $Depth = 10,

        [parameter()]
        [int]
        $NestingLevel = 0,

        [parameter()]
        [switch]
        $NoNewLine
    )

    #report the leaves in terms of object type
    if ($Depth -ilt $NestingLevel) {
        return ''
    }
    # if it is null return null
    If ( !($InputObject) ) {
        if ($InputObject -is [Object[]]) {
            return '[]'
        }
        else {
            return ''
        }
    }

    $padding = [string]::new(' ', $NestingLevel * 2) # lets just create our left-padding for the block
    try {
        $Type = $InputObject.GetType().Name # we start by getting the object's type
        if ($InputObject -is [object[]]) {
            #what it really is
            $Type = "$($InputObject.GetType().BaseType.Name)"
        }

        # Check for specific value types string
        if ($Type -ne 'String') {
            # prevent these values being identified as an object
            if ($InputObject -is [System.Collections.Specialized.OrderedDictionary]) {
                $Type = 'hashTable'
            }
            elseif ($Type -ieq 'List`1') {
                $Type = 'array'
            }
            elseif ($InputObject -is [array]) {
                $Type = 'array'
            } # whatever it thinks it is called
            elseif ($InputObject -is [hashtable] ) {
                $Type = 'hashTable'
            } # for our purposes it is a hashtable
        }

        $output += switch ($Type.ToLower()) {
            'string' {
                $String = "$InputObject"
                if (($string -match '[\r\n]' -or $string.Length -gt 80) -and ($string -notlike 'http*')) {
                    $multiline = [System.Text.StringBuilder]::new("|`n")

                    $items = $string.Split("`n")
                    for ($i = 0; $i -lt $items.Length; $i++) {
                        $workingString = $items[$i] -replace '\r$'
                        $length = $workingString.Length
                        $index = 0
                        $wrap = 80

                        while ($index -lt $length) {
                            $breakpoint = $wrap
                            $linebreak = $false

                            if (($length - $index) -gt $wrap) {
                                $lastSpaceIndex = $workingString.LastIndexOf(' ', $index + $wrap, $wrap)
                                if ($lastSpaceIndex -ne -1) {
                                    $breakpoint = $lastSpaceIndex - $index
                                }
                                else {
                                    $linebreak = $true
                                    $breakpoint--
                                }
                            }
                            else {
                                $breakpoint = $length - $index
                            }

                            $null = $multiline.Append($padding).Append($workingString.Substring($index, $breakpoint).Trim())
                            if ($linebreak) {
                                $null = $multiline.Append('\')
                            }

                            $index += $breakpoint
                            if ($index -lt $length) {
                                $null = $multiline.Append("`n")
                            }
                        }

                        if ($i -lt ($items.Length - 1)) {
                            $null = $multiline.Append("`n")
                        }
                    }

                    $multiline.ToString().TrimEnd()
                    break
                }
                else {
                    # decide if this needs quoting
                    $needsQuote = ($string -match '^[\-?:,\[\]{}#&*!|>''"%@`]') -or
                    $string.StartsWith(' ') -or # leading space
                    $string.EndsWith(' ') -or # trailing space
                        ($string -match ':\s') -or # contains ": "
                        ($string -match '^(?:~|null|true|false)$') -or # bare null/boolean
                        ($string -match '^-?\d+(\.\d+)?$')                # integer or float

                    if ($needsQuote) {
                        # single-quote style: double any internal ' to ''
                        $s = $string -replace '''', ''''''
                        "'$s'"
                    }
                    else {
                        $string
                    }

                    break
                }
                break
            }

            'hashtable' {
                if ($InputObject.GetEnumerator().MoveNext()) {
                    $index = 0
                    $string = [System.Text.StringBuilder]::new()
                    foreach ($item in $InputObject.Keys) {
                        if ($NoNewLine -and $index++ -eq 0) { $NewPadding = '' } else { $NewPadding = "`n$padding" }
                        $null = $string.Append( $NewPadding).Append( $item).Append(': ')
                        if ($InputObject[$item] -is [System.ValueType]) {
                            if ($InputObject[$item] -is [bool]) {
                                $null = $string.Append($InputObject[$item].ToString().ToLower())
                            }
                            else {
                                $null = $string.Append($InputObject[$item])
                            }
                        }
                        else {
                            if ($InputObject[$item] -is [string]) { $increment = 2 } else { $increment = 1 }
                            $null = $string.Append((ConvertTo-PodeYamlInternal -InputObject $InputObject[$item] -Depth $Depth -NestingLevel ($NestingLevel + $increment)))
                        }
                    }
                    $string.ToString()
                }
                else { '{}' }
                break
            }

            'pscustomobject' {
                if ($InputObject.PSObject.Properties.Count -gt 0) {
                    $index = 0
                    $string = [System.Text.StringBuilder]::new()
                    foreach ($item in ($InputObject | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)) {
                        if ($NoNewLine -and $index++ -eq 0) { $NewPadding = '' } else { $NewPadding = "`n$padding" }
                        $null = $string.Append( $NewPadding).Append( $item).Append(': ')
                        if ($InputObject.$item -is [System.ValueType]) {
                            if ($InputObject.$item -is [bool]) {
                                $null = $string.Append($InputObject.$item.ToString().ToLower())
                            }
                            else {
                                $null = $string.Append($InputObject.$item)
                            }
                        }
                        else {
                            if ($InputObject.$item -is [string]) { $increment = 2 } else { $increment = 1 }
                            $null = $string.Append((ConvertTo-PodeYamlInternal -InputObject $InputObject.$item -Depth $Depth -NestingLevel ($NestingLevel + $increment)))
                        }
                    }
                    $string.ToString()
                }
                else { '{}' }
                break
            }

            'array' {
                $string = [System.Text.StringBuilder]::new()
                $index = 0
                foreach ($item in $InputObject ) {
                    if ($NoNewLine -and $index++ -eq 0) { $NewPadding = '' } else { $NewPadding = "`n$padding" }
                    $null = $string.Append($NewPadding).Append('- ').Append((ConvertTo-PodeYamlInternal -InputObject $item -depth $Depth -NestingLevel ($NestingLevel + 1) -NoNewLine))
                }
                $string.ToString()
                break
            }

            default {
                "'$InputObject'"
            }
        }
        return $Output
    }
    catch {
        $_ | Write-PodeErrorLog
        $_.Exception | Write-PodeErrorLog -CheckInnerException
        throw ($PodeLocale.scriptErrorExceptionMessage -f $_, $_.InvocationInfo.ScriptName, $_.InvocationInfo.Line.Trim(), $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.MyCommand, $type, $InputObject, $InputObject.GetType().Name, $InputObject.GetType().BaseType.Name)
    }
}


<#
.SYNOPSIS
    Resolves various types of object arrays into PowerShell objects.

.DESCRIPTION
    This function takes an input property and determines its type.
    It then resolves the property into a PowerShell object or an array of objects,
    depending on whether the property is a hashtable, array, or single object.

.PARAMETER Property
    The property to be resolved. It can be a hashtable, an object array, or a single object.

.RETURNS
    Returns a PowerShell object or an array of PowerShell objects, depending on the input property type.

.EXAMPLE
    $result = Resolve-PodeObjectArray -Property $myProperty
    This example resolves the $myProperty into a PowerShell object or an array of objects.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Resolve-PodeObjectArray {
    [CmdletBinding()]
    [OutputType([object[]])]
    [OutputType([psobject])]
    param (
        [AllowNull()]
        [object]
        $Property
    )

    # Check if the property is a hashtable
    if ($Property -is [hashtable]) {
        # If the hashtable has only one item, convert it to a PowerShell object
        if ($Property.Count -eq 1) {
            return [pscustomobject]$Property
        }
        else {
            # If the hashtable has more than one item, recursively resolve each item
            return @(foreach ($p in $Property) {
                    Resolve-PodeObjectArray -Property $p
                })
        }
    }
    # Check if the property is an array of objects
    elseif ($Property -is [object[]]) {
        # Recursively resolve each item in the array
        return @(foreach ($p in $Property) {
                Resolve-PodeObjectArray -Property $p
            })
    }
    # Check if the property is already a PowerShell object
    elseif ($Property -is [psobject]) {
        return $Property
    }
    else {
        # For any other type, convert it to a PowerShell object
        return [pscustomobject]$Property
    }
}

<#
.SYNOPSIS
    Creates a deep clone of a PSObject by serializing and deserializing the object.

.DESCRIPTION
    The Copy-PodeObjectDeepClone function takes a PSObject as input and creates a deep clone of it.
    This is achieved by serializing the object using the PSSerializer class, and then
    deserializing it back into a new instance. This method ensures that nested objects, arrays,
    and other complex structures are copied fully, without sharing references between the original
    and the cloned object.

.PARAMETER InputObject
    The PSObject that you want to deep clone. This object will be serialized and then deserialized
    to create a deep copy.

.PARAMETER Depth
    Specifies the depth for the serialization. The depth controls how deeply nested objects
    and properties are serialized. The default value is 10.

.INPUTS
    [PSObject] - The function accepts a PSObject to deep clone.

.OUTPUTS
    [PSObject] - The function returns a new PSObject that is a deep clone of the original.

.EXAMPLE
    $originalObject = [PSCustomObject]@{
        Name = 'John Doe'
        Age = 30
        Address = [PSCustomObject]@{
            Street = '123 Main St'
            City = 'Anytown'
            Zip = '12345'
        }
    }

    $clonedObject = $originalObject | Copy-PodeObjectDeepClone -Deep 15

    # The $clonedObject is now a deep clone of $originalObject.
    # Changes to $clonedObject will not affect $originalObject and vice versa.

.NOTES
    - This function uses the System.Management.Automation.PSSerializer class, which is available in
        PowerShell 5.1 and later versions. The default depth parameter is set to 10 to handle nested
        objects appropriately, but it can be customized via the -Deep parameter.
    - This is an internal function and may change in future releases of Pode.
#>
function Copy-PodeObjectDeepClone {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject]$InputObject,

        [Parameter()]
        [int]$Depth = 10
    )

    process {
        # Serialize the object to XML format using PSSerializer
        # The depth parameter controls how deeply nested objects are serialized
        $xmlSerializer = [System.Management.Automation.PSSerializer]::Serialize($InputObject, $Depth)

        # Deserialize the XML back into a new PSObject, creating a deep clone of the original
        return [System.Management.Automation.PSSerializer]::Deserialize($xmlSerializer)
    }
}

<#
.SYNOPSIS
    Converts a duration in milliseconds into a human-readable time format.

.DESCRIPTION
    The `Convert-PodeMillisecondsToReadable` function converts a specified duration in milliseconds into
    a readable time format. The output can be formatted in three styles:
    - `Concise`: A short and simple format (e.g., "1d 2h 3m").
    - `Compact`: A compact representation (e.g., "01:02:03:04").
    - `Verbose`: A detailed, descriptive format (e.g., "1 day, 2 hours, 3 minutes").
    The function also provides an option to exclude milliseconds from the output for all formats.

.PARAMETER Milliseconds
    Specifies the duration in milliseconds to be converted into a human-readable format.

.PARAMETER Format
    Specifies the desired format for the output. Valid options are:
    - `Concise` (default): Short and simple (e.g., "1d 2h 3m").
    - `Compact`: Condensed form (e.g., "01:02:03:04").
    - `Verbose`: Detailed description (e.g., "1 day, 2 hours, 3 minutes, 4 seconds").

.PARAMETER ExcludeMilliseconds
    If specified, milliseconds will be excluded from the output for all formats.

.EXAMPLE
    Convert-PodeMillisecondsToReadable -Milliseconds 123456789

    Output:
    1d 10h 17m 36s

.EXAMPLE
    Convert-PodeMillisecondsToReadable -Milliseconds 123456789 -Format Verbose

    Output:
    1 day, 10 hours, 17 minutes, 36 seconds, 789 milliseconds

.EXAMPLE
    Convert-PodeMillisecondsToReadable -Milliseconds 123456789 -Format Compact -ExcludeMilliseconds

    Output:
    01:10:17:36

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Convert-PodeMillisecondsToReadable {
    param(
        # The duration in milliseconds to convert
        [Parameter(Mandatory = $true)]
        [long]
        $Milliseconds,

        # Specifies the desired output format
        [Parameter()]
        [ValidateSet('Concise', 'Compact', 'Verbose')]
        [string]
        $Format = 'Concise',

        # Omits milliseconds from the output
        [switch]
        $ExcludeMilliseconds
    )

    # Convert the milliseconds input into a TimeSpan object
    $timeSpan = [timespan]::FromMilliseconds($Milliseconds)

    # Generate the formatted output based on the selected format
    switch ($Format.ToLower()) {
        'concise' {
            # Concise format: "1d 2h 3m 4s"
            $output = @()
            if ($timeSpan.Days -gt 0) { $output += "$($timeSpan.Days)d" }
            if ($timeSpan.Hours -gt 0) { $output += "$($timeSpan.Hours)h" }
            if ($timeSpan.Minutes -gt 0) { $output += "$($timeSpan.Minutes)m" }
            if ($timeSpan.Seconds -gt 0) { $output += "$($timeSpan.Seconds)s" }

            # Include milliseconds if they exist and are not excluded
            if ((($timeSpan.Milliseconds -gt 0) -and !$ExcludeMilliseconds) -or ($output.Count -eq 0)) {
                $output += "$($timeSpan.Milliseconds)ms"
            }

            return $output -join ' '
        }

        'compact' {
            # Compact format: "dd:hh:mm:ss"
            $output = '{0:D2}:{1:D2}:{2:D2}:{3:D2}' -f $timeSpan.Days, $timeSpan.Hours, $timeSpan.Minutes, $timeSpan.Seconds

            # Append milliseconds if not excluded
            if (!$ExcludeMilliseconds) {
                $output += '.{0:D3}' -f $timeSpan.Milliseconds
            }

            return $output
        }

        'verbose' {
            # Verbose format: "1 day, 2 hours, 3 minutes, 4 seconds"
            $output = @()
            if ($timeSpan.Days -gt 0) { $output += "$($timeSpan.Days) day$(if ($timeSpan.Days -ne 1) { 's' })" }
            if ($timeSpan.Hours -gt 0) { $output += "$($timeSpan.Hours) hour$(if ($timeSpan.Hours -ne 1) { 's' })" }
            if ($timeSpan.Minutes -gt 0) { $output += "$($timeSpan.Minutes) minute$(if ($timeSpan.Minutes -ne 1) { 's' })" }
            if ($timeSpan.Seconds -gt 0) { $output += "$($timeSpan.Seconds) second$(if ($timeSpan.Seconds -ne 1) { 's' })" }

            # Include milliseconds if they exist and are not excluded
            if ((($timeSpan.Milliseconds -gt 0) -and !$ExcludeMilliseconds) -or ($output.Count -eq 0)) {
                $output += "$($timeSpan.Milliseconds) millisecond$(if ($timeSpan.Milliseconds -ne 1) { 's' })"
            }

            return $output -join ', '
        }
    }
}



<#
.SYNOPSIS
    Converts all instances of 'Start-Sleep' to 'Start-PodeSleep' within a scriptblock.

.DESCRIPTION
    The `ConvertTo-PodeSleep` function processes a given scriptblock and replaces every occurrence
    of 'Start-Sleep' with 'Start-PodeSleep'. This is useful for adapting scripts that need to use
    Pode-specific sleep functionality.

.PARAMETER ScriptBlock
    The scriptblock to be processed. The function will replace 'Start-Sleep' with 'Start-PodeSleep'
    in the provided scriptblock.

.EXAMPLE
  # Example 1: Replace Start-Sleep in a ScriptBlock
    $Original = { Write-Host "Starting"; Start-Sleep -Seconds 5; Write-Host "Done" }
    $Modified = $Original | ConvertTo-PodeSleep
    & $Modified

.EXAMPLE
    # Example 2: Process a ScriptBlock inline
    ConvertTo-PodeSleep -ScriptBlock { Start-Sleep -Seconds 2 } | Invoke-Command

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function ConvertTo-PodeSleep {
    param(
        [Parameter(ValueFromPipeline = $true)]
        [scriptblock]
        $ScriptBlock
    )
    process {
        # Modify the ScriptBlock to replace 'Start-Sleep' with 'Start-PodeSleep'
        return [scriptblock]::Create(("$($ScriptBlock)" -replace 'Start-Sleep ', 'Start-PodeSleep '))
    }
}

<#
.SYNOPSIS
    Tests whether the current PowerShell host is the Integrated Scripting Environment (ISE).

.DESCRIPTION
    This function checks if the current host is running in the Windows PowerShell ISE
    by comparing the `$Host.Name` property with the string 'Windows PowerShell ISE Host'.

.PARAMETER None
    This function does not accept any parameters.

.OUTPUTS
    [Boolean]
    Returns `True` if the host is the Windows PowerShell ISE, otherwise `False`.

.EXAMPLE
    Test-PodeIsISEHost
    Checks if the current PowerShell session is running in the ISE and returns the result.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Test-PodeIsISEHost {
    return ((Test-PodeIsWindows) -and ('Windows PowerShell ISE Host' -eq $Host.Name))
}




<#
.SYNOPSIS
    Checks if two arrays have any common elements.

.DESCRIPTION
    This function takes two arrays as input parameters and checks if they share any common elements.
    It returns $true if there is at least one common element, and $false otherwise.

.PARAMETER ReferenceArray
    The first array to compare.

.PARAMETER DifferenceArray
    The second array to compare.

.EXAMPLE
    $array1 = @('a', 'b', 'c')
    $array2 = @('c', 'd', 'e')
    Test-PodeArraysHaveCommonElement -ReferenceArray $array1 -DifferenceArray $array2
    # Output: True

.EXAMPLE
    $array1 = @('a', 'b', 'c')
    $array2 = @('d', 'e', 'f')
    Test-PodeArraysHaveCommonElement -ReferenceArray $array1 -DifferenceArray $array2
    # Output: False

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Test-PodeArraysHaveCommonElement {
    param (
        [array]$ReferenceArray, # The first array to compare
        [array]$DifferenceArray    # The second array to compare
    )

    # Iterate through each item in the DifferenceArray
    foreach ($item in $DifferenceArray) {
        # Check if the item exists in the ReferenceArray
        if ($ReferenceArray -contains $item) {
            # Return true if a common element is found
            return $true
        }
    }
    # Return false if no common elements are found
    return $false
}


<#
.SYNOPSIS
    Formats a given DateTime object to the ISO 8601 format used in Pode.

.DESCRIPTION
    The `Format-PodeDateToIso8601` function takes a DateTime object and returns
    a string formatted as `yyyy-MM-ddTHH:mm:ss.fffffffZ`, which is the ISO 8601 format
    with seven fractional seconds, suitable for Pode async route tasks.

.PARAMETER Date
    The DateTime object to format.

.EXAMPLE
    $completedTime = Get-Date
    $formattedDate = Format-PodeDateToIso8601 -Date $completedTime
    Write-Output $formattedDate

    This example formats the current date and time to the ISO 8601 format.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Format-PodeDateToIso8601 {
    param (
        [DateTime]$Date
    )

    return $Date.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
}


<#
.SYNOPSIS
    Tests if the current user has administrative privileges on Windows or root/sudo privileges on Linux/macOS.

.DESCRIPTION
    This function checks the current user's privileges. On Windows, it checks if the user is an Administrator.
    If the session is not elevated, you can optionally check if the user has the potential to elevate using the -Elevate switch.
    On Linux and macOS, it checks if the user is either root or has sudo (Linux) or admin (macOS) privileges.
    You can also check if the user has the potential to elevate by belonging to the sudo or admin group using the -Elevate switch.

.PARAMETER Elevate
    The -Elevate switch allows you to check if the current user has the potential to elevate to administrator/root privileges,
    even if the session is not currently elevated.

.PARAMETER Console
    The -Console switch will output errors to the console if an exception occurs.
    Otherwise, the errors will be written to the Pode error log.

.EXAMPLE
    Test-PodeAdminPrivilege

    If the user has administrative privileges, it returns $true. If not, it returns $false.

.EXAMPLE
    Test-PodeAdminPrivilege -Elevate

    This will check if the user has administrative/root/sudo privileges or the potential to elevate,
    even if the session is not currently elevated.

.EXAMPLE
    Test-PodeAdminPrivilege -Elevate -Console

    This will check for admin privileges or potential to elevate and will output errors to the console if any occur.

.OUTPUTS
    [bool]
    Returns $true if the user has administrative/root/sudo/admin privileges or the potential to elevate,
    otherwise returns $false.

.NOTES
    - This function works across multiple platforms: Windows, Linux, and macOS.
        On Linux/macOS, it checks for root, sudo, or admin group memberships, and optionally checks for elevation potential
        if the -Elevate switch is used.
    - This is an internal function and may change in future releases of Pode.
#>
function Test-PodeAdminPrivilege {
    param(
        [switch]
        $Elevate,
        [switch]
        $Console
    )
    try {
        # Check if the operating system is Windows
        if (Test-PodeIsWindows) {

            # Retrieve the current Windows identity and token
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)

            if ($null -eq $principal) {
                return $false
            }

            $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if ($isAdmin) {
                return $true
            }

            # Check if the token is elevated
            if ($identity.IsSystem -or $identity.IsAuthenticated -and $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                return $true
            }

            if ($Elevate.IsPresent) {
                # Use 'whoami /groups' to check if the user has the potential to elevate
                $groups = whoami /groups
                if ($groups -match 'S-1-5-32-544') {
                    return $true
                }
            }
            return $false
        }
        else {
            # Check if the operating system is Linux or macOS (both are Unix-like)

            # Check if the user is root (UID 0)
            $isRoot = [int](id -u)
            if ($isRoot -eq 0) {
                return $true
            }

            if ($Elevate.IsPresent) {
                # Check if the user has sudo privileges by checking sudo group membership
                $user = whoami
                $groups = (groups $user)
                Write-Verbose "User:$user Groups: $( $groups -join ',')"
                # macOS typically uses 'admin' group for sudo privileges
                return ($groups -match '\bwheel\b' -or $groups -match '\badmin\b' -or $groups -match '\bsudo\b' -or $groups -match '\badm\b' -or $groups -match '\bvscode\b')
            }
            return $false
        }
    }
    catch [exception] {
        if ($Console.IsPresent) {
            Write-PodeHost 'Error checking user privileges' -ForegroundColor Red
            Write-PodeHost $_.Exception.Message -ForegroundColor Red
        }
        else {
            $_ | Write-PodeErrorLog
        }
        return $false
    }
}

<#
.SYNOPSIS
    Starts a command with elevated privileges if the current session is not already elevated.

.DESCRIPTION
    This function checks if the current PowerShell session is running with administrator privileges.
    If not, it re-launches the command as an elevated process. If the session is already elevated,
    it will execute the command directly and return the result of the command.

.PARAMETER Command
    The PowerShell command to be executed. This can be any valid PowerShell command, script, or executable.

.PARAMETER Arguments
    The arguments to be passed to the command. This can be any valid argument list for the command or script.

.EXAMPLE
    Invoke-PodeWinElevatedCommand -Command "Get-Service" -Arguments "-Name 'W32Time'"

    This will run the `Get-Service` command with elevated privileges, pass the `-Name 'W32Time'` argument, and return the result.

.EXAMPLE
    Invoke-PodeWinElevatedCommand -Command "C:\Scripts\MyScript.ps1" -Arguments "-Param1 'Value1' -Param2 'Value2'"

    This will run the script `MyScript.ps1` with elevated privileges, pass the parameters `-Param1` and `-Param2`, and return the result.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Invoke-PodeWinElevatedCommand {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    param (
        [string]
        $Command,
        [string]
        $Arguments,
        [PSCredential] $Credential
    )


    # Check if the current session is elevated
    $isElevated = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)


    if (-not $isElevated) {

        # Escape the arguments by replacing " with `" (escaping quotes)
        $escapedArguments = $Arguments -replace '"', '"""'
        $psCredential = ''

        # Combine command and arguments into a string to pass for elevated execution
        #   $escapedCommand = "`"$Command`" $Arguments"
        if ($Credential) {
            $password = Convertfrom-SecureString $Credential.Password
            $psCredential = "-Credential ([pscredential]::new('$($Credential.UserName)', `$('$password'|ConvertTo-SecureString)))"
        }

        # Combine command and arguments into a string for elevated execution
        $escapedCommand = "$Command $psCredential $escapedArguments"
        # Start elevated process with properly escaped command and arguments
        $result = Start-Process -FilePath ((Get-Process -Id $PID).Path) `
            -ArgumentList '-NoProfile', '-ExecutionPolicy Bypass', "-Command & {$escapedCommand}" `
            -Verb RunAs -Wait -PassThru

        return $result
    }

    # Run the command directly with arguments if elevated and capture the output
    return Invoke-Expression "$Command $Arguments"
}

<#
.SYNOPSIS
    Determines the OS architecture for the current system.

.DESCRIPTION
    This function detects the operating system's architecture and maps it to a format compatible with
    PowerShell installation requirements. It works on both Windows and Unix-based systems, translating
    various architecture identifiers (e.g., 'amd64', 'x86_64') into standardized PowerShell-supported names
    like 'x64', 'x86', 'arm64', and 'arm32'. On Linux, the function also checks for musl libc to provide
    an architecture-specific identifier.

.OUTPUTS
    [string] - The architecture string, such as 'x64', 'x86', 'arm64', 'arm32', or 'musl-x64'.

.EXAMPLE
    $arch = Get-PodeOSPwshArchitecture
    Write-Host "Current architecture: $arch"

.NOTES
    - For Windows, architecture is derived from the `PROCESSOR_ARCHITECTURE` environment variable.
    - For Unix-based systems, architecture is determined using the `uname -m` command.
    - The function adds support for identifying musl libc on Linux, returning 'musl-x64' if detected.
    - If the architecture is not supported, the function returns an empty string.
#>
function Get-PodeOSPwshArchitecture {
    # Initialize an empty variable for storing the detected architecture
    $arch = [string]::Empty

    # Detect architecture on Unix-based systems (Linux/macOS)
    if ($IsLinux -or $IsMacOS) {
        # Use the 'uname -m' command to determine the system architecture
        $arch = uname -m
    }
    else {
        # For Windows, use the environment variable 'PROCESSOR_ARCHITECTURE'
        $arch = $env:PROCESSOR_ARCHITECTURE
    }

    # Map the detected architecture to PowerShell-compatible formats
    switch ($arch.ToLowerInvariant()) {
        'amd64' { $arch = 'x64' }          # 64-bit AMD architecture
        'x86' { $arch = 'x86' }            # 32-bit Intel architecture
        'x86_64' { $arch = 'x64' }         # 64-bit Intel architecture
        'armv7*' { $arch = 'arm32' }       # 32-bit ARM architecture (v7 series)
        'aarch64*' { $arch = 'arm64' }     # 64-bit ARM architecture (aarch64 series)
        'arm64' { $arch = 'arm64' }        # Explicit ARM64
        'arm64*' { $arch = 'arm64' }       # Pattern matching for ARM64
        'armv8*' { $arch = 'arm64' }       # ARM v8 series
        default { return '' }              # Unsupported architectures, return empty string
    }

    # Additional check for musl libc on Linux systems
    if ($IsLinux) {
        if ($arch -eq 'x64') {
            # Check if musl libc is present
            if (Get-Command ldd -ErrorAction SilentlyContinue) {
                $lddOutput = ldd --version 2>&1
                if ($lddOutput -match 'musl') {
                    # Append 'musl-' prefix to architecture
                    $arch = 'musl-x64'
                }
            }
        }
    }

    # Return the final architecture string
    return $arch
}

<#
.SYNOPSIS
    Tests whether the current session can bind to one or more privileged ports.

.DESCRIPTION
    Attempts to bind to each port in the specified list using the provided IP address.

    Behavior:
      - Returns $true if any port can be successfully bound.
      - Returns $false if a privilege error (AccessDenied) occurs and $CheckAdmin is enabled.
      - Returns $false if all test ports are in use but no privilege error occurs.
      - If -ThrowError is used:
        • Throws a localized exception if a privilege error is detected and -CheckAdmin is also set.
        • Throws a custom SocketException with a descriptive message when the port is already in use.
        • Throws the raw exception for all other socket or unexpected errors.

.PARAMETER IP
    The IP address to bind to. Defaults to the loopback address (127.0.0.1).

.PARAMETER Port
    A single port number or an array of ports to test. Defaults to a set of typically unused privileged ports.

.PARAMETER ThrowError
    If specified, exceptions will be thrown instead of returning values for error conditions.

.PARAMETER CheckAdmin
    If specified, only privilege-related binding failures will result in a return value of $false;
    otherwise, AccessDenied will return $true (to allow non-admin flows to continue).

.OUTPUTS
    [bool] $true  — Binding was successful on at least one port.
    [bool] $false — Privilege error occurred (with CheckAdmin), or a single port is in use.
    [bool] $false — All ports were in use, but no privilege issue was detected.

.EXAMPLE
    Test-PodeBindToPrivilegedPort

.EXAMPLE
    Test-PodeBindToPrivilegedPort -IP '0.0.0.0' -Port 80

.EXAMPLE
    Test-PodeBindToPrivilegedPort -ThrowError -CheckAdmin
#>

function Test-PodeBindToPrivilegedPort {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$IP = '127.0.0.1',

        [Parameter()]
        [int[]]$Port = @(1, 7, 9, 13, 19, 37, 79, 100),

        [switch]
        $ThrowError,

        [switch]
        $CheckAdmin
    )

    foreach ($p in $Port) {
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($IP), $p)
            $listener.Start()
            $listener.Stop()
            Write-Verbose "Successfully bound to $($IP):$p"
            return $true
        }
        catch [System.Net.Sockets.SocketException] {
            switch ($_.Exception.SocketErrorCode) {
                'AccessDenied' {
                    Write-Debug "Access denied on $($IP):$p"
                    if ($ThrowError) {
                        if (!$CheckAdmin) { return }
                        throw ($PodeLocale.mustBeRunningWithAdminPrivilegesExceptionMessage)
                    }
                    if ($CheckAdmin) {
                        return $false
                    }
                    return $true

                }
                'AddressAlreadyInUse' {
                    Write-Debug "Port $p is already in use on $IP"

                    if ($Port.Count -gt 1) {
                        continue
                    }
                    if ($ThrowError) {
                        throw  ($PodeLocale.cannotBindPortInUseExceptionMessage -f $IP, $p)
                    }
                    return $false
                }
                default {
                    #    Write-Debug "Unhandled socket error on $($IP):$p — $($_.Exception.SocketErrorCode)"
                    if ($ThrowError) {
                        throw  $_
                    }
                    return $false
                }
            }
        }
        catch {
            #Write-Debug "Unexpected error on $($IP):$p — $($_.Exception.Message)"
            if ($ThrowError) {
                throw  $_
            }
            return $false
        }
    }

    Write-Debug "All test ports on $IP were in use, but no privilege error detected"
    return $false
}

<#
    .SYNOPSIS
      Displays a deprecation warning message for a function.

    .DESCRIPTION
      The Write-PodeDeprecationWarning function generates a warning message indicating that
      a specified function is deprecated and suggests the new replacement function.

    .PARAMETER OldFunction
      The name of the deprecated function that is being replaced.

    .PARAMETER NewFunction
      The name of the new function that should be used instead.

    .OUTPUTS
      None.

    .EXAMPLE
      Write-PodeDeprecationWarning -OldFunction "New-PodeLoggingMethod" -NewFunction "New-PodeLogger"

      This will display:
      WARNING: Function `New-PodeLoggingMethod` is deprecated. Please use 'New-PodeLogger' function instead.

    .NOTES
      Internal function for Pode.
      Subject to change in future releases.
#>
function Write-PodeDeprecationWarning {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $OldFunction,

        [Parameter(Mandatory = $true)]
        [string]
        $NewFunction
    )
    # WARNING: Function `New-PodeLoggingMethod` is deprecated. Please use '{0}' function instead.
    Write-PodeHost ($PodeLocale.deprecatedFunctionWarningMessage -f $OldFunction, $NewFunction) -ForegroundColor Yellow
}

<#
.SYNOPSIS
    Converts a SecureString to its plain text equivalent.

.DESCRIPTION
    Converts a [securestring] object into a plain text [string]. This is useful for logging, debugging,
    or passing credentials in plain text form when needed. If the input is $null, the function returns $null.

    The function supports pipeline input for seamless composition with other commands.

.PARAMETER SecureString
    The SecureString instance to convert to plain text. If null, the function returns null.

.INPUTS
    [securestring] Accepts a SecureString object from the pipeline.

.OUTPUTS
    [string] The plain text representation of the SecureString, or $null if the input was null.

.NOTES
    Internal Pode function - subject to change without notice.
#>
function Convert-PodeSecureStringToPlainText {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [securestring]
        $SecureString
    )

    process {
        if ($null -eq $SecureString) {
            return $null
        }
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        try {
            [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

<#
.SYNOPSIS
    Converts a SecureString to a UTF8 byte array.

.DESCRIPTION
    This function takes a SecureString input and converts it into a UTF8 encoded byte array.
    Supports pipeline input for seamless integration with other cmdlets.

.PARAMETER SecureString
    The SecureString that needs to be converted.

.OUTPUTS
    [byte[]] A UTF8 encoded byte array representation of the SecureString.

.NOTES
    Internal Pode function - subject to change.
#>
function Convert-PodeSecureStringToByteArray {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [securestring]
        $SecureString
    )

    process {
        if ($null -ne $SecureString) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
            try {
                [System.Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr))
            }
            finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
        else {
            return [byte[]]::new(0)  # Return empty byte array instead of $null
        }
    }
}

<#
.SYNOPSIS
    Retrieves the name of the main Pode application script.

.DESCRIPTION
    The `Get-PodeApplicationName` function determines the name of the primary script (`.ps1`)
    that started execution. It does this by examining the PowerShell call stack and
    extracting the first script file that appears.

    If no script file is found in the call stack, the function returns `"NoName"`.

.OUTPUTS
    [string]
    Returns the filename of the main application script, or `"NoName"` if no script is found.

.EXAMPLE
    Get-PodeApplicationName

    This retrieves the name of the main script that launched the Pode application.

.EXAMPLE
    $AppName = Get-PodeApplicationName
    Write-Host "Application Name: $AppName"

    This stores the retrieved application name in a variable and prints it.

.NOTES
    - This function relies on `Get-PSCallStack`, meaning it must be run within a script execution context.
    - If called interactively or if no `.ps1` script is in the call stack, it will return `"NoName"`.
    - This is an internal function and may change in future releases of Pode.
#>
function Get-PodeApplicationName {
    $scriptFrame = (Get-PSCallStack | Where-Object { $_.Command -match '\.ps1$' } | Select-Object -First 1)
    if ($scriptFrame) {
        return    [System.IO.Path]::GetFileName($scriptFrame.Command)
    }
    else {
        return 'NoName'
    }
}


<#
.SYNOPSIS
    Returns the current date and time in UTC format.

.DESCRIPTION
    This function retrieves the current date and time in Coordinated Universal Time (UTC), ensuring consistency across different time zones.

.OUTPUTS
    [DateTime] - The current UTC date and time.

.EXAMPLE
    Get-PodeUtcNow

    Returns the current UTC datetime.

.NOTES
    - This function is required to allow Pester test to mock it
    - This function is for internal Pode usage and may be subject to change.
#>
function Get-PodeUtcNow {
    [CmdletBinding()]
    [OutputType([System.DateTime])]
    param ()

    process {
        return [System.DateTime]::UtcNow
    }
}

<#
.SYNOPSIS
	Evaluates if a given state version is valid against the current Pode version.

.DESCRIPTION
	This internal function compares two Pode version strings to determine if the state version is acceptable for use with the current version.
	It accounts for semantic versioning rules and special handling for pre-release identifiers (e.g., alpha, beta).
	If the current version is set to '[dev]', it always returns true to permit development overrides.

.PARAMETER CurrentVersion
	The currently executing Pode version string. This may include pre-release identifiers or be '[dev]'.

.PARAMETER StateVersion
	The version string from state data that should be validated against the current Pode version.

.OUTPUTS
	System.Boolean

.EXAMPLE
	Compare-PodeVersion -CurrentVersion '2.5.0' -StateVersion '2.4.3'
	# Returns $true since the state version is less than the current version.

.EXAMPLE
	Compare-PodeVersion -CurrentVersion '2.5.0-beta.2' -StateVersion '2.5.0-beta.1'
	# Returns $true since the state version is a lower pre-release of the same channel.

.EXAMPLE
	Compare-PodeVersion -CurrentVersion '2.5.0' -StateVersion '2.5.0-beta.1'
	# Returns $false since a production version cannot accept a pre-release state.

.NOTES
	This is an internal Pode function and is subject to change.
#>
function Compare-PodeVersion {
    param (
        [string]$CurrentVersion,
        [string]$StateVersion
    )

    # [dev] always passes.
    if ($CurrentVersion -eq '[dev]') {
        return $true
    }

    # Determine if versions have pre-release parts.
    $currentHasPre = $CurrentVersion -match '-'
    $stateHasPre = $StateVersion -match '-'

    # Rule: Production (no pre-release) should never accept a pre-release state.
    if (-not $currentHasPre -and $stateHasPre) {
        return $false
    }

    # Split each version into base and pre-release components.
    $currentSplit = $CurrentVersion -split '-', 2
    $stateSplit = $StateVersion -split '-', 2

    $currentBase = [System.Version]::Parse($currentSplit[0])
    $stateBase = [System.Version]::Parse($stateSplit[0])


    # Compare base versions.
    if ($stateBase -lt $currentBase) {
        return $true
    }
    elseif ($stateBase -gt $currentBase) {
        return $false
    }

    # Base versions are equal.
    $currentPre = if ($currentSplit.Length -gt 1) { $currentSplit[1] } else { $null }
    $statePre = if ($stateSplit.Length -gt 1) { $stateSplit[1] } else { $null }

    # If current is production (no pre-release) and state is not, allow it.
    if ($null -eq $currentPre -and $null -eq $statePre) {
        return $true
    }
    # If current has a pre-release but state is production, that's not allowed.
    if ($null -ne $currentPre -and $null -eq $statePre) {
        return $false
    }

    # Both have pre-release parts: split on the period.
    $currentParts = $currentPre -split '\.'
    $stateParts = $statePre -split '\.'

    # Compare pre-release channels (e.g. alpha vs beta)
    $currentTag = $currentParts[0]
    $stateTag = $stateParts[0]

    if ($currentTag -ne $stateTag) {
        # Different channels are not allowed.
        return $false
    }

    # Compare numeric identifiers if available.
    $currentNum = if ($currentParts.Length -gt 1) { [int]$currentParts[1] } else { 0 }
    $stateNum = if ($stateParts.Length -gt 1) { [int]$stateParts[1] } else { 0 }

    # Allow state only if its numeric part is less than or equal to current.
    return ($stateNum -le $currentNum)
}

<#
.SYNOPSIS
    Determines the MIME type of an image from its binary header.

.DESCRIPTION
    This function accepts a byte array representing an image and analyzes the first few bytes
    (converted to hexadecimal strings) to determine its file format. It supports PNG, JPEG, GIF
    (both GIF87a and GIF89a), ICO, WebP, and SVG formats. If the image format cannot be determined,
    it returns a generic MIME type of 'application/octet-stream'.

.PARAMETER Image
    A byte array containing the image data.

.OUTPUTS
    A string representing the MIME type of the image.

.EXAMPLE
    $bytes = [System.IO.File]::ReadAllBytes("C:\path\to\image.gif")
    $mimeType = Get-PodeImageContentType -Image $bytes
    # $mimeType will be 'image/gif' if the image is a GIF.

.NOTES
    This is an internal function and may change in future releases of Pode.
#>
function Get-PodeImageContentType {
    param(
        [Parameter()]
        [byte[]]
        $Image
    )

    if (($null -eq $Image) -or ($Image.Length -lt 12)) {
        return 'application/octet-stream'
    }

    # WebP: starts with "RIFF....WEBP"
    if (
        $Image[0] -eq 0x52 -and $Image[1] -eq 0x49 -and $Image[2] -eq 0x46 -and $Image[3] -eq 0x46 -and
        $Image[8] -eq 0x57 -and $Image[9] -eq 0x45 -and $Image[10] -eq 0x42 -and $Image[11] -eq 0x50
    ) {
        return 'image/webp'
    }

    # PNG: starts with "89 50 4E 47 0D 0A 1A 0A"
    if (
        $Image[0] -eq 0x89 -and $Image[1] -eq 0x50 -and $Image[2] -eq 0x4E -and $Image[3] -eq 0x47 -and
        $Image[4] -eq 0x0D -and $Image[5] -eq 0x0A -and $Image[6] -eq 0x1A -and $Image[7] -eq 0x0A
    ) {
        return 'image/png'
    }

    # GIF (GIF87a or GIF89a): starts with "47 49 46 38 37 61" or "47 49 46 38 39 61"
    if (
        $Image[0] -eq 0x47 -and $Image[1] -eq 0x49 -and $Image[2] -eq 0x46 -and $Image[3] -eq 0x38 -and
        (
            ($Image[4] -eq 0x37 -and $Image[5] -eq 0x61) -or
            ($Image[4] -eq 0x39 -and $Image[5] -eq 0x61)
        )
    ) {
        return 'image/gif'
    }

    # ICO: starts with "00 00 01 00"
    if (
        $Image[0] -eq 0x00 -and $Image[1] -eq 0x00 -and
        $Image[2] -eq 0x01 -and $Image[3] -eq 0x00
    ) {
        return 'image/x-icon'
    }

    # SVG: starts with "<svg"
    if (
        $Image[0] -eq 0x3C -and $Image[1] -eq 0x73 -and
        $Image[2] -eq 0x76 -and $Image[3] -eq 0x67
    ) {
        return 'image/svg+xml'
    }

    # JPEG: starts with "FF D8 FF"
    if (
        $Image[0] -eq 0xFF -and $Image[1] -eq 0xD8 -and $Image[2] -eq 0xFF
    ) {
        return 'image/jpeg'
    }

    # If none of the above formats match, return a generic binary type
    return 'application/octet-stream'
}