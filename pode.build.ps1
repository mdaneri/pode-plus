<#
.SYNOPSIS
    Build script for the Pode project, defining tasks for compilation, testing, packaging, and deployment.

.DESCRIPTION
    This script uses Invoke-Build to automate the Pode project build process across different environments (Windows, macOS, Linux).
    It includes tasks for setting up dependencies, compiling .NET targets, running tests, generating documentation, and packaging.

.PARAMETER Version
    Specifies the project version for stamping, packaging, and documentation. Defaults to '0.0.0'.

.PARAMETER Prerelease
    Specifies the prerelease label to append to the module version, following semantic versioning conventions.
    Examples include 'alpha.1', 'alpha.2', 'beta.1', etc. This label indicates the stability and iteration of the prerelease version.

.PARAMETER PersistVersion
  If specified, the provided version and prerelease label will be saved to `Version.json`.
  This ensures future builds use the same versioning information unless explicitly overridden.

.PARAMETER PesterVerbosity
    Sets the verbosity level for Pester tests. Options: None, Normal, Detailed, Diagnostic.

.PARAMETER PowerShellVersion
    Defines the target PowerShell version for installation, e.g., 'lts' or a specific version.

.PARAMETER ReleaseNoteVersion
    Specifies the release version for generating release notes.

.PARAMETER UICulture
    Sets the culture for running tests, defaulting to 'en-US'.

.PARAMETER TargetFrameworks
    Specifies the target .NET frameworks for building the project, e.g., netstandard2.0, net8.0.

.PARAMETER SdkVersion
    Sets the SDK version used for building .NET projects, defaulting to net8.0.

.NOTES
    This build script requires Invoke-Build. Below is a list of all available tasks:

    - Default: Lists all available tasks.
    - StampVersion: Stamps the specified version onto the module.
    - PrintChecksum: Generates and displays a checksum of the ZIP archive.
    - ChocoDeps: Installs Chocolatey (for Windows).
    - BuildDeps: Installs dependencies required for building/compiling.
    - TestDeps: Installs dependencies required for testing.
    - DocsDeps: Installs dependencies required for documentation generation.
    - IndexSamples: Indexes sample files for documentation.
    - Build: Builds the .NET Listener for specified frameworks.
    - DeliverableFolder: Creates a folder for deliverables.
    - Compress: Compresses the module into a ZIP format for distribution.
    - ChocoPack: Creates a Chocolatey package of the module (Windows only).
    - DockerPack: Builds Docker images for the module.
    - Pack: Packages the module, including ZIP, Chocolatey, and Docker.
    - PackageFolder: Creates the `pkg` folder for module packaging.
    - TestNoBuild: Runs tests without building, including Pester tests.
    - Test: Runs tests after building the project.
    - CheckFailedTests: Checks if any tests failed and throws an error if so.
    - PushCodeCoverage: Pushes code coverage results to a coverage service.
    - Docs: Serves the documentation locally for review.
    - DocsHelpBuild: Builds function help documentation.
    - DocsBuild: Builds the documentation for distribution.
    - Clean: Cleans the build environment, removing all generated files.
    - CleanDeliverable: Removes the `deliverable` folder.
    - CleanPkg: Removes the `pkg` folder.
    - CleanLibs: Removes the `Libs` folder under `src`.
    - CleanListener: Removes the Listener folder.
    - CleanDocs: Cleans up generated documentation files.
    - Install-Module: Installs the Pode module locally.
    - Remove-Module: Removes the Pode module from the local registry.
    - SetupPowerShell: Sets up the PowerShell environment for the build.
    - ReleaseNotes: Generates release notes based on merged pull requests.
    - Sort-LanguageFiles: Sort Language resource files
    - AutoMerge-LanguageFiles: Automerge Language Resource files.
    - Format-FunctionHeaders: Formats function headers in the file to follow Pode's standard style.
    - Refresh-HeaderFooter: Adds or refreshes the file-level header and footer using Pode's standard formatting.

.EXAMPLE
    Invoke-Build -Task Default
        # Displays a list of all available tasks.

    Invoke-Build -Task Build -Version '1.2.3'
        # Compiles the project for the specified version.

    Invoke-Build -Task Test
        # Runs tests on the project, including Pester tests.

    Invoke-Build -Task Docs
        # Builds and serves the documentation locally.

    Invoke-Build -Task Build -Version '2.13.0' -Prerelease 'beta.1' -PersistVersion
        # Saves "2.13.0-beta.1" to Version.json for future builds.

.LINK
    For more information, visit https://github.com/Badgerati/Pode
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingCmdletAliases', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUSeDeclaredVarsMoreThanAssignments', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '')]
param(
    [string]
    $Version,

    [string]
    $Prerelease,

    [switch]
    $PersistVersion,

    [string]
    [ValidateSet('None', 'Normal' , 'Detailed', 'Diagnostic')]
    $PesterVerbosity = 'Normal',

    [string]
    $PowerShellVersion = 'lts',

    [string]
    $ReleaseNoteVersion,

    [string]
    $UICulture = 'en-US',

    [switch]
    $DisableLifecycleServiceOperations,

    [string[]]
    [ValidateSet('netstandard2.0', 'net8.0', 'net9.0', 'net10.0')]
    $TargetFrameworks = @('netstandard2.0', 'net8.0', 'net9.0'),

    [string]
    [ValidateSet('netstandard2.0', 'net8.0', 'net9.0', 'net10.0')]
    $SdkVersion = 'net9.0'
)

# Dependency Versions
$Versions = @{
    Pester      = '5.7.1'
    MkDocs      = '1.6.1'
    PSCoveralls = '1.0.0'
    DotNet      = $SdkVersion
    MkDocsTheme = '9.6.12'
    PlatyPS     = '0.14.2'
    Yarn        = '1.22.22'
}


# Helper Functions

<#
.SYNOPSIS
    Installs a specified package using the appropriate package manager for the OS.

.DESCRIPTION
    This function installs a specified package at a given version using platform-specific
    package managers. For Windows, it uses Chocolatey (`choco`). On Unix-based systems,
    it checks for `brew`, `apt-get`, and `yum` to handle installations. The function sets
    the security protocol to TLS 1.2 to ensure secure connections during the installation.

.PARAMETER name
    The name of the package to install (e.g., 'git').

.PARAMETER version
    The version of the package to install, required only for Chocolatey on Windows.

.OUTPUTS
    None.

.EXAMPLE
    Invoke-PodeBuildInstall -Name 'git' -Version '2.30.0'
    # Installs version 2.30.0 of Git on Windows if Chocolatey is available.

.NOTES
    - Requires administrator or sudo privileges on Unix-based systems.
    - This function supports package installation on both Windows and Unix-based systems.
    - If `choco` is available, it will use `choco` for Windows, and `brew`, `apt-get`, or `yum` for Unix-based systems.
#>
function Invoke-PodeBuildInstall($name, $version) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if (Test-PodeBuildIsWindows) {
        if (Test-PodeBuildCommand 'choco') {
            choco install $name --version $version -y --no-progress
        }
    }
    else {
        if (Test-PodeBuildCommand 'brew') {
            brew install $name
        }
        elseif (Test-PodeBuildCommand 'apt-get') {
            sudo apt-get install $name -y
        }
        elseif (Test-PodeBuildCommand 'yum') {
            sudo yum install $name -y
        }
    }
}

<#
.SYNOPSIS
    Checks if the script is running in a GitHub Actions environment.

.DESCRIPTION
    This function verifies if the script is running in a GitHub Actions environment
    by checking if the `GITHUB_REF` environment variable is defined and not empty.
    It returns `$true` if the variable is present, indicating a GitHub Actions environment.

.OUTPUTS
    [bool] - Returns `$true` if the script is running on GitHub Actions, otherwise `$false`.

.EXAMPLE
    if (Test-PodeBuildIsGitHub) {
        Write-Host "Running in GitHub Actions."
    }

.NOTES
    - This function is useful for CI/CD pipelines to identify if the script is running in GitHub Actions.
    - Assumes that `GITHUB_REF` is always set in a GitHub Actions environment.
#>
function Test-PodeBuildIsGitHub {
    return (![string]::IsNullOrWhiteSpace($env:GITHUB_REF))
}

<#
.SYNOPSIS
    Checks if code coverage is enabled for the build.

.DESCRIPTION
    This function checks if code coverage is enabled by evaluating the `PODE_RUN_CODE_COVERAGE`
    environment variable. If the variable contains '1' or 'true' (case-insensitive), it returns `$true`;
    otherwise, it returns `$false`.

.OUTPUTS
    [bool] - Returns `$true` if code coverage is enabled, otherwise `$false`.

.EXAMPLE
    if (Test-PodeBuildCanCodeCoverage) {
        Write-Host "Code coverage is enabled for this build."
    }

.NOTES
    - Useful for conditional logic in build scripts that should only execute code coverage-related tasks if enabled.
    - The `PODE_RUN_CODE_COVERAGE` variable is typically set by the CI/CD environment or the user.
#>
function Test-PodeBuildCanCodeCoverage {
    return (@('1', 'true') -icontains $env:PODE_RUN_CODE_COVERAGE)
}

<#
.SYNOPSIS
    Returns the name of the CI/CD service being used for the build.

.DESCRIPTION
    This function returns a string representing the CI/CD service in use.
    Currently, it always returns 'github-actions', indicating that the build
    is running in GitHub Actions.

.OUTPUTS
    [string] - The name of the CI/CD service, which is 'github-actions'.

.EXAMPLE
    $service = Get-PodeBuildService
    Write-Host "The build service is: $service"
    # Output: The build service is: github-actions

.NOTES
    - This function is useful for identifying the CI/CD service in logs or reporting.
    - Future modifications could extend this function to detect other CI/CD services.
#>
function Get-PodeBuildService {
    return 'github-actions'
}

<#
.SYNOPSIS
    Checks if a specified command is available on the system.

.DESCRIPTION
    This function checks if a given command is available in the system's PATH.
    On Windows, it uses `Get-Command`, and on Unix-based systems, it uses `which`.
    It returns `$true` if the command exists and `$false` if it does not.

.PARAMETER cmd
    The name of the command to check for availability (e.g., 'choco', 'brew').

.OUTPUTS
    [bool] - Returns `$true` if the command is found, otherwise `$false`.

.EXAMPLE
    if (Test-PodeBuildCommand -Cmd 'git') {
        Write-Host "Git is available."
    }

.NOTES
    - This function supports both Windows and Unix-based platforms.
    - Requires `Test-PodeBuildIsWindows` to detect the OS type.
#>
function Test-PodeBuildCommand($cmd) {
    $path = $null

    if (Test-PodeBuildIsWindows) {
        $path = (Get-Command $cmd -ErrorAction Ignore)
    }
    else {
        $path = (which $cmd)
    }

    return (![string]::IsNullOrWhiteSpace($path))
}

<#
.SYNOPSIS
    Checks if the current environment is running on Windows.

.DESCRIPTION
    This function determines if the current PowerShell session is running on Windows.
    It inspects `$PSVersionTable.Platform` and `$PSVersionTable.PSEdition` to verify the OS,
    returning `$true` for Windows and `$false` for other platforms.

.OUTPUTS
    [bool] - Returns `$true` if the current environment is Windows, otherwise `$false`.

.EXAMPLE
    if (Test-PodeBuildIsWindows) {
        Write-Host "This script is running on Windows."
    }

.NOTES
    - Useful for cross-platform scripts to conditionally execute Windows-specific commands.
    - The `$PSVersionTable.Platform` variable may be `$null` in certain cases, so `$PSEdition` is used as an additional check.
#>
function Test-PodeBuildIsWindows {
    $v = $PSVersionTable
    return ($v.Platform -ilike '*win*' -or ($null -eq $v.Platform -and $v.PSEdition -ieq 'desktop'))
}


<#
.SYNOPSIS
    Retrieves the branch name from the GitHub Actions environment variable.

.DESCRIPTION
    This function extracts the branch name from the `GITHUB_REF` environment variable,
    which is commonly set in GitHub Actions workflows. It removes the 'refs/heads/' prefix
    from the branch reference, leaving only the branch name.

.OUTPUTS
    [string] - The name of the GitHub branch.

.EXAMPLE
    $branch = Get-PodeBuildBranch
    Write-Host "Current branch: $branch"
    # Output example: Current branch: main

.NOTES
    - Only relevant in environments where `GITHUB_REF` is defined (e.g., GitHub Actions).
    - Returns an empty string if `GITHUB_REF` is not set.
#>
function Get-PodeBuildBranch {
    return ($env:GITHUB_REF -ireplace 'refs\/heads\/', '')
}

<#
.SYNOPSIS
    Installs a specified PowerShell module if it is not already installed at the required version.

.DESCRIPTION
    This function checks if the specified PowerShell module is available in the current session
    at the specified version. If not, it installs the module using the PowerShell Gallery, setting
    the security protocol to TLS 1.2. The module is installed in the current user's scope.

.PARAMETER name
    The name of the PowerShell module to check and install.

.OUTPUTS
    None.

.EXAMPLE
    Install-PodeBuildModule -Name 'Pester'
    # Installs the 'Pester' module if the specified version is not already installed.

.NOTES
    - Uses `$Versions` hashtable to look up the required version for the module.
    - Requires internet access to download modules from the PowerShell Gallery.
    - The `-SkipPublisherCheck` parameter bypasses publisher verification; use with caution.
#>
function Install-PodeBuildModule($name) {
    if ($null -ne ((Get-Module -ListAvailable $name) | Where-Object { $_.Version -ieq $Versions[$name] })) {
        return
    }

    Write-Host "Installing $($name) v$($Versions[$name])"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module -Name "$($name)" -Scope CurrentUser -RequiredVersion "$($Versions[$name])" -Force -SkipPublisherCheck
}

<#
.SYNOPSIS
    Converts a .NET target framework identifier to a numeric version.

.DESCRIPTION
    This function maps common .NET target framework identifiers (e.g., 'netstandard2.0', 'net9.0') to their
    numeric equivalents. It is used to ensure compatibility by returning the framework version number as an integer.

.PARAMETER TargetFrameworks
    The target framework identifier (e.g., 'netstandard2.0', 'net9.0').

.OUTPUTS
    [int] - The numeric version of the target framework. Defaults to 2 if an unrecognized framework is provided.

.EXAMPLE
    $version = Get-PodeBuildTargetFramework -TargetFrameworks 'net9.0'
    Write-Host "Target framework version: $version"
    # Output: Target framework version: 6

.NOTES
    - Returns 2 (netstandard2.0) by default if the input framework is not recognized.
    - This function is useful in build scripts that require target framework versioning.
#>
function Get-PodeBuildTargetFramework {
    param(
        [string]
        $TargetFrameworks
    )

    switch ($TargetFrameworks) {
        'netstandard2.0' { return  2 }
        'net8.0' { return 8 }
        'net9.0' { return  9 }
        'net10.0' { return  10 }
        default {
            Write-Warning "$TargetFrameworks is not a valid Framework. Rollback to netstandard2.0"
            return 2
        }
    }
}

<#
.SYNOPSIS
    Converts a .NET target framework version number to a framework identifier.

.DESCRIPTION
    This function maps a numeric version to a .NET target framework identifier (e.g., '2' to 'netstandard2.0').
    If the version number is not recognized, it defaults to 'netstandard2.0'.

.PARAMETER Version
    The numeric version of the .NET target framework (e.g., 2, 6, 8).

.OUTPUTS
    [string] - The target framework identifier (e.g., 'netstandard2.0').

.EXAMPLE
    $frameworkName = Get-PodeBuildTargetFrameworkName -Version 9
    Write-Host "Target framework name: $frameworkName"
    # Output: Target framework name: net9.0

.NOTES
    - Returns 'netstandard2.0' by default if an unrecognized version is provided.
    - Useful for converting numeric framework versions to identifier strings in build processes.
#>
function Get-PodeBuildTargetFrameworkName {
    param(
        $Version
    )

    switch ( $Version) {
        '2' { return 'netstandard2.0' }
        '8' { return  'net8.0' }
        '9' { return 'net9.0' }
        '10' { return 'net10.0' }
        default {
            Write-Warning "$Version is not a valid Framework. Rollback to netstandard2.0"
            return 'netstandard2.0'
        }
    }
}

function Invoke-PodeBuildDotnetBuild {
    param (
        [string]$target
    )

    # Retrieve the installed SDK versions
    $sdkVersions = dotnet --list-sdks | ForEach-Object { $_.Split('[')[0].Trim() }
    if ([string]::IsNullOrEmpty($AvailableSdkVersion)) {
        $majorVersions = $sdkVersions | ForEach-Object { ([version]$_).Major } | Sort-Object -Descending | Select-Object -Unique
    }
    else {
        $majorVersions = $sdkVersions.Where( { ([version]$_).Major -ge (Get-PodeBuildTargetFramework -TargetFrameworks $AvailableSdkVersion) } ) | Sort-Object -Descending | Select-Object -Unique
    }
    # Map target frameworks to minimum SDK versions

    if ($null -eq $majorVersions) {
        Write-Error "The requested '$AvailableSdkVersion' framework is not available."
        return
    }
    $requiredSdkVersion = Get-PodeBuildTargetFramework -TargetFrameworks $target

    # Determine if the target framework is compatible
    $isCompatible = $majorVersions -ge $requiredSdkVersion

    if ($isCompatible) {
        Write-Output "SDK for target framework '$target' is compatible with the '$AvailableSdkVersion' framework."
    }
    else {
        Write-Warning "SDK for target framework '$target' is not compatible with the '$AvailableSdkVersion' framework. Skipping build."
        return
    }

    # Optionally set assembly version
    if ($Version) {
        if ($Prerelease) {
            Write-Output "Assembly Version: $Version-$Prerelease"
            $AssemblyVersion = "-p:VersionPrefix=$Version"
            $AssemblyPrerelease = "-p:VersionSuffix=$Prerelease"
        }
        else {
            Write-Output "Assembly Version: $Version"
            $AssemblyVersion = "-p:Version=$Version"
            $AssemblyPrerelease = ''
        }
    }
    else {
        $AssemblyVersion = ''
        $AssemblyPrerelease = ''
    }

    # restore dependencies
    dotnet restore

    # Use dotnet publish for .NET Core and .NET 5+
    dotnet publish --configuration Release --self-contained --framework $target $AssemblyVersion $AssemblyPrerelease --output ../Libs/$target

    # Throw an error if the build fails
    if (!$?) {
        throw "Build failed for target framework '$target'."
    }
}

<#
.SYNOPSIS
    Builds the Pode Monitor Service for multiple target platforms using .NET SDK.

.DESCRIPTION
    This function automates the build process for the Pode Monitor Service. It:
    - Determines the highest installed .NET SDK version.
    - Verifies compatibility with the required SDK version.
    - Optionally sets an assembly version during the build.
    - Builds the service for specified runtime targets across platforms (Windows, Linux, macOS).
    - Allows defining custom constants for conditional compilation.

.PARAMETER Version
    Specifies the assembly version to use for the build. If not provided, no version is set.

.PARAMETER DisableLifecycleServiceOperations
    If specified, excludes lifecycle service operations during the build by omitting related compilation constants.

.INPUTS
    None. The function does not accept pipeline input.

.OUTPUTS
    None. The function produces build artifacts in the output directory.

.NOTES
    This function is designed to work with .NET SDK and assumes it is installed and configured properly.
    It throws an error if the build process fails for any target.

.EXAMPLE
    Invoke-PodeBuildDotnetMonitorSrvBuild -Version "1.0.0"

    Builds the Pode Monitor Service with an assembly version of 1.0.0.

.EXAMPLE
    Invoke-PodeBuildDotnetMonitorSrvBuild -DisableLifecycleServiceOperations

    Builds the Pode Monitor Service without lifecycle service operations.

.EXAMPLE
    Invoke-PodeBuildDotnetMonitorSrvBuild

    Builds the Pode Monitor Service for all target runtimes without a specific assembly version.
#>
function Invoke-PodeBuildDotnetMonitorSrvBuild() {
    # Retrieve the highest installed SDK version
    $majorVersion = ([version](dotnet --version)).Major

    # Determine if the target framework is compatible
    $isCompatible = $majorVersions -ge $requiredSdkVersion

    # Skip build if not compatible
    if ($isCompatible) {
        Write-Output "SDK for target framework '$target' is compatible with the '$AvailableSdkVersion' framework."
    }
    else {
        Write-Warning "SDK for target framework '$target' is not compatible with the '$AvailableSdkVersion' framework. Skipping build."
        return
    }

    # Optionally set assembly version
    if ($Version) {
        Write-Host "Assembly Version $Version"
        $AssemblyVersion = "-p:Version=$Version"
    }
    else {
        $AssemblyVersion = ''
    }

    foreach ($target in @('win-x64', 'win-arm64' , 'linux-x64', 'linux-arm64', 'osx-x64', 'osx-arm64','linux-arm','win-x86','linux-musl-x64')) {
        $DefineConstants = @()
        $ParamConstants = ''

        # Add compilation constants if lifecycle operations are enabled
        if (!$DisableLifecycleServiceOperations) {
            $DefineConstants += 'ENABLE_LIFECYCLE_OPERATIONS'
        }

        # Prepare constants for the build parameters
        if ($DefineConstants.Count -gt 0) {
            $ParamConstants = "-p:DefineConstants=`"$( $DefineConstants -join ';')`""
        }

        # Perform the build for the target runtime
        dotnet publish --runtime $target --output ../Bin/$target --configuration Release $AssemblyVersion $ParamConstants

        # Throw an error if the build fails
        if (!$?) {
            throw "dotnet publish failed for $($target)"
        }
    }
}

<#
.SYNOPSIS
    Retrieves the end-of-life (EOL) and supported versions of PowerShell.

.DESCRIPTION
    This function queries an online API to retrieve the EOL and supported versions of PowerShell.
    It uses the `Invoke-RestMethod` cmdlet to access data from endoflife.date and returns an object
    with comma-separated lists of supported and EOL PowerShell versions based on the current date.

.OUTPUTS
    [hashtable] - A hashtable containing:
                  - `eol`: Comma-separated string of EOL PowerShell versions.
                  - `supported`: Comma-separated string of supported PowerShell versions.

.EXAMPLE
    $pwshEOLInfo = Get-PodeBuildPwshEOL
    Write-Host "Supported PowerShell versions: $($pwshEOLInfo.supported)"
    Write-Host "EOL PowerShell versions: $($pwshEOLInfo.eol)"

.NOTES
    - Requires internet access to query the endoflife.date API.
    - If the request fails, the function returns an empty string for both `eol` and `supported`.
    - API URL: https://endoflife.date/api/powershell.json
#>
function Get-PodeBuildPwshEOL {
    $uri = 'https://endoflife.date/api/powershell.json'
    try {
        $eol = Invoke-RestMethod -Uri $uri -Headers @{ Accept = 'application/json' }
        return @{
            eol       = ($eol | Where-Object { [datetime]$_.eol -lt [datetime]::Now }).cycle -join ','
            supported = ($eol | Where-Object { [datetime]$_.eol -ge [datetime]::Now }).cycle -join ','
        }
    }
    catch {
        Write-Warning "Invoke-RestMethod to $uri failed: $($_.ErrorDetails.Message)"
        return  @{
            eol       = ''
            supported = ''
        }
    }
}

<#
.SYNOPSIS
    Checks if the current OS is Windows.

.DESCRIPTION
    This function detects whether the current operating system is Windows by checking
    the `Test-PodeBuildIsWindows` automatic variable, the presence of the `$env:ProgramFiles` variable,
    and the PowerShell Edition in `$PSVersionTable`. This function returns `$true` if
    any of these indicate Windows.

.OUTPUTS
    [bool] - Returns `$true` if the OS is Windows, otherwise `$false`.

.EXAMPLE
    if (Test-PodeBuildOSWindows) {
        Write-Host "Running on Windows"
    }

.NOTES
    - Useful for distinguishing between Windows and Unix-based systems for conditional logic.
    - May return `$true` in environments where Windows-related environment variables are present.
#>
function Test-PodeBuildOSWindows {
    return ($IsWindows -or
        ![string]::IsNullOrEmpty($env:ProgramFiles) -or
        (($PSVersionTable.Keys -contains 'PSEdition') -and ($PSVersionTable.PSEdition -eq 'Desktop')))
}

<#
.SYNOPSIS
    Retrieves the current OS name in a PowerShell-compatible format.

.DESCRIPTION
    This function identifies the current operating system and returns a standardized string
    representing the OS name ('win' for Windows, 'linux' for Linux, and 'osx' for macOS).
    It relies on the `Test-PodeBuildOSWindows` function for Windows detection and `$IsLinux`
    and `$IsMacOS` for Linux and macOS, respectively.

.OUTPUTS
    [string] - A string representing the OS name:
               - 'win' for Windows
               - 'linux' for Linux
               - 'osx' for macOS

.EXAMPLE
    $osName = Get-PodeBuildOSPwshName
    Write-Host "Operating system name: $osName"

.NOTES
    - This function enables cross-platform compatibility by standardizing OS name detection.
    - For accurate results, ensure `$IsLinux` and `$IsMacOS` variables are defined for Unix-like systems.
#>
function Get-PodeBuildOSPwshName {
    if (Test-PodeBuildOSWindows) {
        return 'win'
    }

    if ($IsLinux) {
        return 'linux'
    }

    if ($IsMacOS) {
        return 'osx'
    }
}

<#
.SYNOPSIS
    Determines the OS architecture for the current system.

.DESCRIPTION
    This function detects the operating system's architecture and converts it into a format
    compatible with PowerShell installation requirements. It handles both Windows and Unix-based
    systems and maps various architecture identifiers to PowerShell-supported names (e.g., 'x64', 'arm64').

.OUTPUTS
    [string] - The architecture string, such as 'x64', 'x86', 'arm64', or 'arm32'.

.EXAMPLE
    $arch = Get-PodeBuildOSPwshArchitecture
    Write-Host "Current architecture: $arch"

.NOTES
    - For Windows, the architecture is derived from the `PROCESSOR_ARCHITECTURE` environment variable.
    - For Unix-based systems, the architecture is determined using the `uname -m` command.
    - If the architecture is not supported, the function throws an exception.
#>
function Get-PodeBuildOSPwshArchitecture {
    # Initialize architecture variable
    $arch = [string]::Empty

    # Detect architecture on Windows
    if (Test-PodeBuildOSWindows) {
        $arch = $env:PROCESSOR_ARCHITECTURE
    }

    # Detect architecture on Unix-based systems (Linux/macOS)
    if ($IsLinux -or $IsMacOS) {
        $arch = uname -m
    }

    # Output detected architecture for debugging
    Write-Host "OS Architecture: $($arch)"

    # Convert detected architecture to a PowerShell-compatible format
    switch ($arch.ToLowerInvariant()) {
        'amd64' { return 'x64' }          # 64-bit architecture (AMD64)
        'x86' { return 'x86' }            # 32-bit architecture
        'x86_64' { return 'x64' }         # 64-bit architecture (x86_64)
        'armv7*' { return 'arm32' }       # 32-bit ARM architecture
        'aarch64*' { return 'arm64' }     # 64-bit ARM architecture
        'arm64' { return 'arm64' }        # Explicit ARM64
        'arm64*' { return 'arm64' }       # Pattern matching for ARM64
        'armv8*' { return 'arm64' }       # ARM v8 series
        default { throw "Unsupported architecture: $($arch)" } # Throw exception for unsupported architectures
    }
}


<#
.SYNOPSIS
    Converts a PowerShell tag to a version number.

.DESCRIPTION
    This function retrieves PowerShell build information for a specified tag by querying
    an online API. It then extracts and returns the release version associated with the tag.

.PARAMETER PowerShellVersion
    The PowerShell version tag to retrieve build information for (e.g., 'lts', 'stable', or a specific version).

.OUTPUTS
    [string] - The extracted version number corresponding to the provided tag.

.EXAMPLE
    $version = Convert-PodeBuildOSPwshTagToVersion
    Write-Host "Resolved PowerShell version: $version"

.NOTES
    This function depends on internet connectivity to query the build information API.
#>
function Convert-PodeBuildOSPwshTagToVersion {
    # Query PowerShell build info API with the specified tag
    $result = Invoke-RestMethod -Uri "https://aka.ms/pwsh-buildinfo-$($PowerShellVersion)"

    # Extract and return the release tag without the leading 'v'
    return $result.ReleaseTag -ireplace '^v'
}

<#
.SYNOPSIS
    Installs PowerShell on a Windows system.

.DESCRIPTION
    This function installs PowerShell by copying files from a specified target directory
    to the standard installation folder on a Windows system. It first removes any existing
    installation in the Target directory.

.PARAMETER Target
    The directory containing the PowerShell installation files.

.EXAMPLE
    Install-PodeBuildPwshWindows -Target 'C:\Temp\PowerShell'
    # Installs PowerShell from the 'C:\Temp\PowerShell' directory.

.NOTES
    This function requires administrative privileges to modify the Program Files directory.
#>
function Install-PodeBuildPwshWindows {
    param (
        [string]
        $Target
    )

    # Define the installation folder path
    $installFolder = "$($env:ProgramFiles)\PowerShell\7"

    # Remove the existing installation, if any
    if (Test-Path $installFolder) {
        Remove-Item $installFolder -Recurse -Force -ErrorAction Stop
    }

    # Copy the new PowerShell files to the installation folder
    Copy-Item -Path "$($Target)\" -Destination "$($installFolder)\" -Recurse -ErrorAction Stop
}


<#
.SYNOPSIS
    Installs PowerShell on a Unix-based system.

.DESCRIPTION
    This function installs PowerShell on Unix-based systems by copying files from a specified Target directory,
    setting appropriate permissions, and creating a symbolic link to the PowerShell binary.

.PARAMETER Target
    The directory containing the PowerShell installation files.

.EXAMPLE
    Install-PodeBuildPwshUnix -Target '/tmp/powershell'
    # Installs PowerShell from the '/tmp/powershell' directory.

.NOTES
    - This function requires administrative privileges to create symbolic links in system directories.
    - The `sudo` command is used if the script is not run as root.
#>
function Install-PodeBuildPwshUnix {
    param (
        [string]
        $Target
    )

    # Define the full path to the PowerShell binary
    $targetFullPath = Join-Path -Path $Target -ChildPath 'pwsh'

    # Set executable permissions on the PowerShell binary
    $null = chmod 755 $targetFullPath

    # Determine the symbolic link location based on the operating system
    $symlink = $null
    if ($IsMacOS) {
        $symlink = '/usr/local/bin/pwsh'
    }
    else {
        $symlink = '/usr/bin/pwsh'
    }

    # Check if the script is run as root
    $uid = id -u
    if ($uid -ne '0') {
        $sudo = 'sudo'
    }
    else {
        $sudo = ''
    }

    # Create a symbolic link to the PowerShell binary
    & $sudo ln -fs $targetFullPath $symlink
}

<#
.SYNOPSIS
    Retrieves the currently installed PowerShell version.

.DESCRIPTION
    This function runs the `pwsh -v` command and parses the output to return only the version number.
    This is useful for verifying the PowerShell version in the build environment.

.OUTPUTS
    [string] - The current PowerShell version.

.EXAMPLE
    $version = Get-PodeBuildCurrentPwshVersion
    Write-Host "Current PowerShell version: $version"

.NOTES
    This function assumes that `pwsh` is available in the system PATH.
#>
function Get-PodeBuildCurrentPwshVersion {
    # Run pwsh command, split by spaces, and return the version component
    return ("$(pwsh -v)" -split ' ')[1].Trim()
}

<#
.SYNOPSIS
    Builds a Docker image and tags it for the Pode project.

.DESCRIPTION
    This function uses the Docker CLI to build an image for Pode, then tags it for GitHub Packages.
    The function takes a tag and a Dockerfile path as parameters to build and tag the Docker image.

.PARAMETER Tag
    The Docker image tag, typically a version number or label (e.g., 'latest').

.PARAMETER File
    The path to the Dockerfile to use for building the image.

.EXAMPLE
    Invoke-PodeBuildDockerBuild -Tag '1.0.0' -File './Dockerfile'
    # Builds a Docker image using './Dockerfile' and tags it as 'badgerati/pode:1.0.0'.

.NOTES
    Requires Docker to be installed and available in the system PATH.
#>
function Invoke-PodeBuildDockerBuild {
    param (
        [string]
        $Tag,
        [string]
        $File
    )

    # Build the Docker image with the specified tag and Dockerfile
    docker build -t badgerati/pode:$Tag -f $File .
    if (!$?) {
        throw "docker build failed for $($Tag)"
    }

    # Tag the image for GitHub Packages
    docker tag badgerati/pode:$Tag docker.pkg.github.com/badgerati/pode/pode:$Tag
    if (!$?) {
        throw "docker tag failed for $($Tag)"
    }
}


<#
.SYNOPSIS
    Splits the PSModulePath environment variable into an array of paths.

.DESCRIPTION
    This function checks the operating system and splits the PSModulePath variable based on the appropriate separator:
    ';' for Windows and ':' for Unix-based systems.

.OUTPUTS
    [string[]] - An array of paths from the PSModulePath variable.

.EXAMPLE
    $paths = Split-PodeBuildPwshPath
    foreach ($path in $paths) {
        Write-Host $path
    }

.NOTES
    This function enables cross-platform support by handling path separators for Windows and Unix-like systems.
#>
function Split-PodeBuildPwshPath {
    # Check if OS is Windows, then split PSModulePath by ';', otherwise use ':'
    if (Test-PodeBuildOSWindows) {
        return $env:PSModulePath -split ';'
    }
    else {
        return $env:PSModulePath -split ':'
    }
}


<#
.SYNOPSIS
  Processes language resource files and standardizes their formatting.

.DESCRIPTION
  This function scans for `Pode.psd1` language resource files within the specified `Locales` directory.
  It normalizes key-value pairs, removes duplicate keys while preserving the last occurrence, and
  organizes messages into Exception Messages and General Messages. The cleaned and formatted content
  is then written back to the respective files.

.PARAMETER None
  This function does not accept parameters. It operates on files found within `./src/Locales`.

.OUTPUTS
  None. The function modifies `Pode.psd1` files directly by updating their content.

.EXAMPLE
  Group-LanguageResource
  Processes all `Pode.psd1` files in `./src/Locales`, normalizes their format, and removes duplicates.

.NOTES
  - This function ensures that all messages are consistently formatted and sorted.
  - Duplicate keys are detected, with only the first occurrence being retained.
  - Exception messages are grouped separately from general messages.
  - The function enforces single-quoted values while escaping any existing single quotes.
#>
function Group-LanguageResource {
    $localePath = './src/Locales'
    $files = Get-ChildItem -Path $localePath -Filter 'Pode.psd1' -Recurse

    foreach ($file in $files) {
        Write-Host "Processing file: $($file.FullName)"

        # Read raw content
        $content = Get-Content $file.FullName -Raw

        $normalized = [regex]::Replace(
            $content,
            '(?m)^(?<key>\s*[^=\s]+)\s*=\s*(")(?<value>.*?)(")\s*$',
            {
                param($match)
                # Get the value and double any single quotes within it
                $value = $match.Groups['value'].Value -replace "'", "''"
                # Build the new line using single quotes
                return "$($match.Groups['key'].Value) = '$value'"
            }
        )


        # Extract keys and values using improved regex to support accented characters
        $matches = [regex]::Matches($normalized, "(?m)^\s*([^=\s]+)\s*=\s*'(.*?)'\s*$")


        # Use a hashtable to track unique keys and remove duplicates
        $uniqueMessages = [ordered]@{}
        foreach ($match in $matches) {
            $key = $match.Groups[1].Value
            $value = $match.Groups[2].Value

            if (  $uniqueMessages.Contains($key)) {
                Write-Warning "Duplicate key '$key' found in $($file.Name). Keeping only the second occurrence."
            }
            $uniqueMessages[$key] = $value
        }

        # Sort keys
        $sortedKeys = $uniqueMessages.Keys | Sort-Object

        # Split into Exception and General Messages
        $exceptionMessages = [ordered]@{}
        $generalMessages = [ordered]@{}

        foreach ($key in $sortedKeys) {
            if ($key -match 'ExceptionMessage$') {
                $exceptionMessages[$key] = $uniqueMessages[$key]
            }
            else {
                $generalMessages[$key] = $uniqueMessages[$key]
            }
        }

        $maxLength = ($sortedKeys | Measure-Object -Property Length -Maximum).Maximum + 1

        # Build the file content
        $lines = @()
        $lines += '@{'
        $lines += '    # -------------------------------'
        $lines += '    # Exception Messages'
        $lines += '    # -------------------------------'

        foreach ($key in $exceptionMessages.Keys) {
            $padding = ' ' * ($maxLength - $key.Length)
            # Replace single quotes only if they're not already escaped
            $escapedValue = [regex]::Replace($exceptionMessages[$key], "(?<!')'(?!')", "''")
            $lines += "    $key$padding= '$escapedValue'"
        }

        $lines += ''
        $lines += '    # -------------------------------'
        $lines += '    # General Messages'
        $lines += '    # -------------------------------'

        foreach ($key in $generalMessages.Keys) {
            $padding = ' ' * ($maxLength - $key.Length)
            # Replace single quotes only if they're not already escaped
            $escapedValue = [regex]::Replace($generalMessages[$key], "(?<!')'(?!')", "''")
            $lines += "    $key$padding= '$escapedValue'"
        }

        $lines += '}'

        # Write the updated content back to the file
        [System.IO.File]::WriteAllText(
            $file.FullName,
            ($lines -join "`r`n") + "`r`n",
            [System.Text.UTF8Encoding]::new($false)
        )

        Write-Host "Updated file: $($file.FullName)"
    }
}

# Check if the script is running under Invoke-Build
if (($null -eq $PSCmdlet.MyInvocation) -or ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('BuildRoot') -and ($null -eq $BuildRoot))) {
    Write-Host 'This script is intended to be run with Invoke-Build. Please use Invoke-Build to execute the tasks defined in this script.' -ForegroundColor Yellow
    return
}

# Import Version File if needed
if ([string]::IsNullOrEmpty($Version)) {
    if (Test-Path './Version.json' -PathType Leaf) {
        $importedVersion = Get-Content -Path './Version.json' | ConvertFrom-Json
        if ($importedVersion.Version) {
            $Version = $importedVersion.Version
        }
        if ($importedVersion.Prerelease) {
            $Prerelease = $importedVersion.Prerelease
        }
    }
    else {
        $Version = '0.0.0'
        if ($PersistVersion) {
            Write-Error 'The -PersistVersion parameter requires the -Version parameter to be specified.'
            return
        }
    }
}
elseif ($PersistVersion) {
    if ($Prerelease) {
        [ordered]@{Version = $Version; Prerelease = $Prerelease } | ConvertTo-Json | Out-File './Version.json'
    }
    else {
        [ordered]@{Version = $Version } | ConvertTo-Json | Out-File './Version.json'
    }
}


Write-Host '---------------------------------------------------' -ForegroundColor DarkCyan

# Display the Pode build version
if ($Prerelease) {
    Write-Host "Pode Build: v$Version-$Prerelease (Pre-release)" -ForegroundColor DarkCyan
}
else {
    if ($Version -eq '0.0.0') {
        Write-Host 'Pode Build: [Development Version]' -ForegroundColor DarkCyan
    }
    else {
        Write-Host "Pode Build: v$Version" -ForegroundColor DarkCyan
    }
}

# Display the current UTC time in a readable format
$utcTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
Write-Host "Start Time: $utcTime" -ForegroundColor DarkCyan

Write-Host '---------------------------------------------------' -ForegroundColor DarkCyan


Add-BuildTask Default {
    Write-Host 'Tasks in the Build Script:' -ForegroundColor DarkMagenta
    Write-Host
    Write-Host 'Primary Tasks:' -ForegroundColor Green
    Write-Host '- Default: Lists all available tasks.'
    Write-Host '- Build: Builds the .NET Listener for specified frameworks.'
    Write-Host '- Pack: Packages the module, including ZIP, Chocolatey, and Docker.'
    Write-Host '- Test: Runs tests after building the project.'
    Write-Host '- Clean: Cleans the build environment, removing all generated files.'
    Write-Host '- Install-Module: Installs the Pode module locally.'
    Write-Host '- Remove-Module: Removes the Pode module from the local registry.'
    Write-Host '- DocsBuild: Builds the documentation for distribution.'
    Write-Host '- TestNoBuild: Runs tests without building, including Pester tests.'


    Write-Host
    Write-Host 'Other Tasks:' -ForegroundColor Green
    Write-Host '- StampVersion: Stamps the specified version onto the module.'
    Write-Host '- PrintChecksum: Generates and displays a checksum of the ZIP archive.'
    Write-Host '- ChocoDeps: Installs Chocolatey (for Windows).'
    Write-Host '- BuildDeps: Installs dependencies required for building/compiling.'
    Write-Host '- TestDeps: Installs dependencies required for testing.'
    Write-Host '- DocsDeps: Installs dependencies required for documentation generation.'
    Write-Host '- IndexSamples: Indexes sample files for documentation.'
    Write-Host '- DeliverableFolder: Creates a folder for deliverables.'
    Write-Host '- Compress: Compresses the module into a ZIP format for distribution.'
    Write-Host '- ChocoPack: Creates a Chocolatey package of the module (Windows only).'
    Write-Host '- DockerPack: Builds Docker images for the module.'
    Write-Host "- PackageFolder: Creates the `pkg` folder for module packaging."
    Write-Host '- CheckFailedTests: Checks if any tests failed and throws an error if so.'
    Write-Host '- PushCodeCoverage: Pushes code coverage results to a coverage service.'
    Write-Host '- Docs: Serves the documentation locally for review.'
    Write-Host '- DocsHelpBuild: Builds function help documentation.'
    Write-Host "- CleanDeliverable: Removes the `deliverable` folder."
    Write-Host "- CleanPkg: Removes the `pkg` folder."
    Write-Host "- CleanLibs: Removes the `Libs` folder under `src`."
    Write-Host '- CleanListener: Removes the Listener folder.'
    Write-Host '- CleanDocs: Cleans up generated documentation files.'
    Write-Host '- SetupPowerShell: Sets up the PowerShell environment for the build.'
    Write-Host '- ReleaseNotes: Generates release notes based on merged pull requests.'
    Write-Host '- Sort-LanguageFiles: Sort Language resource files.'
    Write-Host '- AutoMerge-LanguageFiles: Automerge Language Resource files.'
    Write-Host "- Format-FunctionHeaders: Formats function headers in the file to follow Pode's standard style."
    Write-Host "- Refresh-HeaderFooter: Adds or refreshes the file-level header and footer using Pode's standard formatting."
}

<#
# Helper Tasks
#>

# Synopsis: Stamps the version onto the Module
Add-BuildTask StampVersion {
    $pwshVersions = Get-PodeBuildPwshEOL
    $prereleaseValue = if ($Prerelease) {
        "Prerelease = '$Prerelease'"
    }
    else {
        ''
    }
    (Get-Content ./pkg/Pode.psd1) | ForEach-Object { $_ -replace '\$version\$', $Version -replace '\$versionsUntested\$', $pwshVersions.eol -replace '\$versionsSupported\$', $pwshVersions.supported -replace '\$buildyear\$', ((get-date).Year) -replace '#\$Prerelease-Here\$', $prereleaseValue } | Set-Content ./pkg/Pode.psd1
    (Get-Content ./pkg/Pode.Internal.psd1) | ForEach-Object { $_ -replace '\$version\$', $Version } | Set-Content ./pkg/Pode.Internal.psd1
    (Get-Content ./packers/choco/pode_template.nuspec) | ForEach-Object { $_ -replace '\$version\$', $Version } | Set-Content ./packers/choco/pode.nuspec
    (Get-Content ./packers/choco/tools/ChocolateyInstall_template.ps1) | ForEach-Object { $_ -replace '\$version\$', $Version } | Set-Content ./packers/choco/tools/ChocolateyInstall.ps1
}

# Synopsis: Generating a Checksum of the Zip
Add-BuildTask PrintChecksum {
    $Script:Checksum = (Get-FileHash "./deliverable/$Version-Binaries.zip" -Algorithm SHA256).Hash
    Write-Host "Checksum: $($Checksum)"
}


<#
# Dependencies
#>

# Synopsis: Installs Chocolatey
Add-BuildTask ChocoDeps -If (Test-PodeBuildIsWindows) {
    if (!(Test-PodeBuildCommand 'choco')) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ([System.Net.WebClient]::new().DownloadString('https://chocolatey.org/install.ps1'))
    }
}

# Synopsis: Install dependencies for compiling/building
Add-BuildTask BuildDeps {
    # install dotnet
    if (Test-PodeBuildIsWindows) {
        $dotnet = 'dotnet'
    }
    elseif (Test-PodeBuildCommand 'brew') {
        $dotnet = 'dotnet-sdk'
    }
    else {
        $dotnet = "dotnet-sdk-$SdkVersion"
    }

    try {
        $sdkVersions = dotnet --list-sdks | ForEach-Object { $_.Split('[')[0].Trim() }
    }
    catch {
        Invoke-PodeBuildInstall $dotnet $SdkVersion
        $sdkVersions = dotnet --list-sdks | ForEach-Object { $_.Split('[')[0].Trim() }
    }
    $majorVersions = ($sdkVersions | ForEach-Object { ([version]$_).Major } | Sort-Object -Descending | Select-Object -Unique)[0]
    $script:AvailableSdkVersion = Get-PodeBuildTargetFrameworkName  -Version $majorVersions

    if ($majorVersions -lt (Get-PodeBuildTargetFramework -TargetFrameworks $SdkVersion)) {
        Invoke-PodeBuildInstall $dotnet $SdkVersion
        $sdkVersions = dotnet --list-sdks | ForEach-Object { $_.Split('[')[0].Trim() }
        $majorVersions = ($sdkVersions | ForEach-Object { ([version]$_).Major } | Sort-Object -Descending | Select-Object -Unique)[0]
        $script:AvailableSdkVersion = Get-PodeBuildTargetFrameworkName  -Version $majorVersions

        if ($majorVersions -lt (Get-PodeBuildTargetFramework -TargetFrameworks $SdkVersion)) {
            Write-Error "The requested framework '$SdkVersion' is not available."
            return
        }
    }
    elseif ($majorVersions -gt (Get-PodeBuildTargetFramework -TargetFrameworks $SdkVersion)) {
        Write-Warning "The requested SDK version '$SdkVersion' is superseded by the installed '$($script:AvailableSdkVersion)' framework."
    }

    if (!(Test-PodeBuildCommand 'yarn')) {
        Invoke-PodeBuildInstall 'yarn' $Versions.Yarn
    }

}

# Synopsis: Install dependencies for running tests
Add-BuildTask TestDeps {
    # install pester
    Install-PodeBuildModule Pester

    # install PSCoveralls
    if (Test-PodeBuildCanCodeCoverage) {
        Install-PodeBuildModule PSCoveralls
    }
}

# Synopsis: Install dependencies for documentation
Add-BuildTask DocsDeps ChocoDeps, {
    # install mkdocs
    if (!(Test-PodeBuildCommand 'mkdocs')) {
        Invoke-PodeBuildInstall 'mkdocs' $Versions.MkDocs
    }

    $_installed = (pip list --format json --disable-pip-version-check | ConvertFrom-Json)
    if (($_installed | Where-Object { $_.name -ieq 'mkdocs-material' -and $_.version -ieq $Versions.MkDocsTheme } | Measure-Object).Count -eq 0) {
        pip install "mkdocs-material==$($Versions.MkDocsTheme)" --force-reinstall --disable-pip-version-check --quiet
    }

    # install platyps
    Install-PodeBuildModule PlatyPS
}

Add-BuildTask IndexSamples {
    $examplesPath = './examples'
    if (!(Test-Path -PathType Container -Path $examplesPath)) {
        return
    }

    # List of directories to exclude
    $sampleMarkDownPath = './docs/Getting-Started/Samples.md'
    $excludeDirs = @('scripts', 'views', 'static', 'public', 'assets', 'timers', 'modules',
        'Authentication', 'certs', 'logs', 'relative', 'routes', 'issues')

    # Convert exclusion list into single regex pattern for directory matching
    $dirSeparator = [IO.Path]::DirectorySeparatorChar
    $excludeDirs = "\$($dirSeparator)($($excludeDirs -join '|'))\$($dirSeparator)"

    # build the page content
    Get-ChildItem -Path $examplesPath -Filter *.ps1 -Recurse -File -Force |
        Where-Object {
            $_.FullName -inotmatch $excludeDirs
        } |
        Sort-Object -Property FullName |
        ForEach-Object {
            Write-Verbose "Processing Sample: $($_.FullName)"

            # get the script help
            $help = Get-Help -Name $_.FullName -ErrorAction Stop

            # add help content
            $urlFileName = ($_.FullName -isplit 'examples')[1].Trim('\/') -replace '[\\/]', '/'
            $markdownContent += "## [$($_.BaseName)](https://github.com/Badgerati/Pode/blob/develop/examples/$($urlFileName))`n`n"
            $markdownContent += "**Synopsis**`n`n$($help.Synopsis)`n`n"
            $markdownContent += "**Description**`n`n$($help.Description.Text)`n`n"
        }

    Write-Output "Write Markdown document for the sample files to $($sampleMarkDownPath)"
    Set-Content -Path $sampleMarkDownPath -Value "# Sample Scripts`n`n$($markdownContent)" -Force
}

<#
# Building
#>

# Synopsis: Build the .NET Listener
Add-BuildTask Build BuildDeps, Yarn, {
    if (Test-Path ./src/Libs) {
        Remove-Item -Path ./src/Libs -Recurse -Force | Out-Null
    }

    # Display the SDK version
    Write-Output "Building targets '$($targetFrameworks -join "','")' using .NET '$AvailableSdkVersion' framework."

    # Build for supported target frameworks
    try {
        Push-Location ./src/Listener
        foreach ($target in $targetFrameworks) {
            Invoke-PodeBuildDotnetBuild -target $target
            Write-Host
            Write-Host '***********************' -ForegroundColor DarkMagenta

        }
    }
    finally {
        Pop-Location
    }

    if (Test-Path ./src/Bin) {
        Remove-Item -Path ./src/Bin -Recurse -Force | Out-Null
    }

    try {
        Push-Location ./src/PodeMonitor
        Invoke-PodeBuildDotnetMonitorSrvBuild
    }
    finally {
        Pop-Location
    }
}

# synopsis: Download the npm packages to pode_modules folder
Add-BuildTask Yarn {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        yarn install --force --ignore-scripts --ignore-optional --ignore-engines --modules-folder pode_modules
    }
    else {
        yarn install --force --ignore-scripts --ignore-optional --ignore-engines  --modules-folder pode_modules 2>&1 | Select-String -NotMatch '^warning'
    }

    if (!$? -or ($LASTEXITCODE -ne 0)) {
        throw "yarn install failed with exit code $($LASTEXITCODE)"
    }
}, MoveLibs

# Synopsis: Move the libraries to the public directory
Add-BuildTask MoveLibs {

    # Define source and target
    $NodeModules = Join-Path -Path $PSScriptRoot -ChildPath 'pode_modules'
    $Target = Join-Path -Path $PSScriptRoot -ChildPath '/src/Misc/libs'
    $LicenseTarget = Join-Path -Path $PSScriptRoot -ChildPath '/licenses'

    # Clean third_party (optional: only if you want to start fresh)
    if (Test-Path $Target) {
        Remove-Item -Recurse -Force -Path $Target | Out-Null
    }
    New-Item -ItemType Directory -Force -Path $Target | Out-Null

    # Create subfolders and copy only needed files
    $CopyList = @(
        @{ From = "$NodeModules/swagger-ui-dist/swagger-ui.css"; To = "$Target/swagger/" },
        @{ From = "$NodeModules/swagger-ui-dist/swagger-ui-bundle.js"; To = "$Target/swagger/" },
        @{ From = "$NodeModules/swagger-ui-dist/LICENSE"; To = "$LicenseTarget/LICENSE.swagger-ui.txt" ; Comment = 'Project URL: https://github.com/swagger-api/swagger-ui' },

        @{ From = "$NodeModules/swagger-editor-dist/swagger-editor.css"; To = "$Target/swagger-editor/" },
        @{ From = "$NodeModules/swagger-editor-dist/swagger-editor-bundle.js"; To = "$Target/swagger-editor/" },
        @{ From = "$NodeModules/swagger-editor-dist/swagger-editor-standalone-preset.js"; To = "$Target/swagger-editor/" },
        @{ From = "$NodeModules/swagger-editor-dist/LICENSE"; To = "$LicenseTarget/LICENSE.swagger-editor.txt" ; Comment = 'Project URL: https://github.com/swagger-api/swagger-editor' },

        @{ From = "$NodeModules/redoc/bundles/redoc.standalone.js"; To = "$Target/redoc/" },
        @{ From = "$NodeModules/redoc/LICENSE"; To = "$LicenseTarget/LICENSE.redoc.txt"  ; Comment = 'Project URL: https://github.com/Redocly/redoc' },

        @{ From = "$NodeModules/@stoplight/elements/styles.min.css"; To = "$Target/stoplight/elements/" },
        @{ From = "$NodeModules/@stoplight/elements/web-components.min.js"; To = "$Target/stoplight/elements/" },
        @{ From = "$NodeModules/@stoplight/elements/LICENSE"; To = "$LicenseTarget/LICENSE.stoplight.txt"  ; Comment = 'Project URL: https://github.com/stoplightio/elements' },

        @{ From = "$NodeModules/@highlightjs/cdn-assets/styles/monokai-sublime.min.css"; To = "$Target/highlightjs/styles/" },
        @{ From = "$NodeModules/@highlightjs/cdn-assets/highlight.min.js"; To = "$Target/highlightjs/" },
        @{ From = "$NodeModules/@highlightjs/cdn-assets/LICENSE"; To = "$LicenseTarget/LICENSE.highlightjs.txt" ; Comment = 'Project URL: https://github.com/highlightjs/highlight.js' },

        @{ From = "$NodeModules/rapipdf/dist/rapipdf-min.js"; To = "$Target/rapipdf/" },
        @{ From = "$NodeModules/rapipdf/LICENSE.txt"; To = "$LicenseTarget/LICENSE.rapipdf.txt"  ; Comment = 'Project URL: https://github.com/mrin9/RapiPdf' },


        @{ From = "$NodeModules/rapidoc/dist/rapidoc-min.js"; To = "$Target/rapidoc/" },
        @{ From = "$NodeModules/rapidoc/LICENSE.txt"; To = "$LicenseTarget/LICENSE.rapidoc.txt"  ; Comment = 'Project URL: https://github.com/rapi-doc/RapiDoc' },

        @{ From = "$NodeModules/openapi-explorer/dist/browser/openapi-explorer.min.js"; To = "$Target/explorer/browser/" }
        @{ From = "$NodeModules/openapi-explorer/LICENSE"; To = "$LicenseTarget/LICENSE.openapi-explorer.txt"  ; Comment = 'Project URL: https://github.com/Authress-Engineering/openapi-explorer' },

        @{ From = "$NodeModules/bootstrap/dist/css/bootstrap.min.css"; To = "$Target/explorer/css/" },

        @{ From = "$NodeModules/bootstrap/dist/css/bootstrap.min.css"; To = "$Target/bootstrap/css/" },
        @{ From = "$NodeModules/bootstrap/LICENSE"; To = "$LicenseTarget/LICENSE.bootstrap.txt"  ; Comment = 'Project URL: https://github.com/twbs/bootstrap' }
    )

    foreach ($Item in $CopyList) {
        # If Comment exists, prepend it properly depending on file type
        if ($Item.Comment) {
            $fileContent = Get-Content -Raw -Path $Item.From
            $newContent = ($Item.Comment + "`n`n" + $fileContent).Trim()
            if (Test-Path -Path $Item.To) {
                $fileOriginalContent = Get-Content -Raw -Path $Item.To
                if ( $newContent -ne ($fileOriginalContent -replace "`r`n", "`n") ) {
                    $newContent | Out-File -FilePath $Item.To -Encoding utf8 -Force -NoNewline
                }
            }
            else {
                $newContent | Out-File -FilePath $Item.To -Encoding utf8 -Force -NoNewline
            }
        }
        else {
            New-Item -ItemType Directory -Force -Path $Item.To | Out-Null
            Copy-Item -Force -Path $Item.From -Destination $Item.To | Out-Null
        }
    }

    Write-Output "All third-party files copied to $Target"
}

<#
# Packaging
#>

#Synopsis: Create the Deliverable folder
Add-BuildTask DeliverableFolder {
    $path = './deliverable'
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }

    # create the deliverable dir
    New-Item -Path $path -ItemType Directory -Force | Out-Null
}

# Synopsis: Creates a Zip of the Module
Add-BuildTask Compress PackageFolder, StampVersion, DeliverableFolder, {
    $path = './deliverable'
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }
    # create the pkg dir
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    Compress-Archive -Path './pkg/*' -DestinationPath "$path/$Version-Binaries.zip"
}, PrintChecksum

# Synopsis: Creates a Chocolately package of the Module
Add-BuildTask ChocoPack -If (Test-PodeBuildIsWindows) ChocoDeps, PackageFolder, StampVersion, DeliverableFolder, {
    exec { choco pack ./packers/choco/pode.nuspec }
    Move-Item -Path "pode.$Version.nupkg" -Destination './deliverable'
}

# Synopsis: Create docker tags
Add-BuildTask DockerPack PackageFolder, StampVersion, {
    # check if github and windows, and output warning
    if ((Test-PodeBuildIsGitHub) -and (Test-PodeBuildIsWindows)) {
        Write-Warning 'Docker images are not built on GitHub Windows runners, and Docker is in Windows container only mode. Exiting task.'
        return
    }

    try {
        # Try to get the Docker version to check if Docker is installed
        docker --version
    }
    catch {
        # If Docker is not available, exit the task
        Write-Warning 'Docker is not installed or not available in the PATH. Exiting task.'
        return
    }

    Invoke-PodeBuildDockerBuild -Tag $Version -File './Dockerfile'
    Invoke-PodeBuildDockerBuild -Tag 'latest' -File './Dockerfile'
    Invoke-PodeBuildDockerBuild -Tag "$Version-alpine" -File './alpine.dockerfile'
    Invoke-PodeBuildDockerBuild -Tag 'latest-alpine' -File './alpine.dockerfile'

    if (!(Test-PodeBuildIsGitHub)) {
        Invoke-PodeBuildDockerBuild -Tag "$Version-arm32" -File './arm32.dockerfile'
        Invoke-PodeBuildDockerBuild -Tag 'latest-arm32' -File './arm32.dockerfile'
    }
    else {
        Write-Warning 'Docker images for ARM32 are not built on GitHub runners due to having the wrong OS architecture. Skipping.'
    }
}

# Synopsis: Package up the Module
Add-BuildTask Pack Compress, ChocoPack, DockerPack

# Synopsis: Package up the Module into a /pkg folder
Add-BuildTask PackageFolder Build, {
    $path = './pkg'
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }

    # create the pkg dir
    New-Item -Path $path -ItemType Directory -Force | Out-Null

    # which source folders do we need? create them and copy their contents
    $folders = @('Private', 'Public', 'Misc', 'Libs', 'Locales', 'Bin')
    $folders | ForEach-Object {
        New-Item -ItemType Directory -Path (Join-Path $path $_) -Force | Out-Null
        Copy-Item -Path "./src/$($_)/*" -Destination (Join-Path $path $_) -Force -Recurse | Out-Null
    }

    # which route folders to we need? create them and copy their contents
    $folders = @('licenses')
    $folders | ForEach-Object {
        New-Item -ItemType Directory -Path (Join-Path $path $_) -Force | Out-Null
        Copy-Item -Path "./$($_)/*" -Destination (Join-Path $path $_) -Force -Recurse | Out-Null
    }

    # copy general files
    $files = @('src/Pode.psm1', 'src/Pode.psd1', 'src/Pode.Internal.psm1', 'src/Pode.Internal.psd1', 'LICENSE.txt')
    $files | ForEach-Object {
        Copy-Item -Path "./$($_)" -Destination $path -Force | Out-Null
    }
}


<#
# Testing
#>

# Synopsis: Run the tests
Add-BuildTask TestNoBuild TestDeps, {
    $p = (Get-Command Invoke-Pester)
    if ($null -eq $p -or $p.Version -ine $Versions.Pester) {
        Remove-Module Pester -Force -ErrorAction Ignore
        Import-Module Pester -Force -RequiredVersion $Versions.Pester
    }
    Write-Output ''
    # for windows, output current netsh excluded ports
    if (Test-PodeBuildIsWindows) {
        netsh int ipv4 show excludedportrange protocol=tcp | Out-Default

        # Retrieve the current Windows identity and token
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)

        # Gather user information
        $user = $identity.Name
        $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $adminStatus = if ($isElevated) { 'Administrator' } else { 'Standard User' }
        $groups = $identity.Groups | ForEach-Object {
            try {
                $_.Translate([Security.Principal.NTAccount]).Value
            }
            catch {
                $_.Value # Fallback to SID if translation fails
            }
        }

        # Generate output
        Write-Output 'Pester Execution Context (Windows):'
        Write-Output "  - User:                $user"
        Write-Output "  - Role:                $adminStatus"
        Write-Output "  - Elevated Privileges: $isElevated"
        Write-Output "  - Group Memberships:   $( $groups -join ', ')"
    }


    if ($IsLinux) {
        $user = whoami
        $groupsRaw = (groups $user | Out-String).Trim()
        $groups = $groupsRaw -split '\s+' | Where-Object { $_ -ne ':' } | Sort-Object -Unique

        # Check for sudo privileges based on group membership
        $isSudoUser = $groups -match '\bwheel\b' -or $groups -match '\badmin\b' -or $groups -match '\bsudo\b' -or $groups -match '\badm\b'

        Write-Output 'Pester Execution Context (Linux):'
        Write-Output "  - User:    $user"
        Write-Output "  - Groups:  $( $groups -join ', ')"
        Write-Output "  - Sudo:    $($isSudoUser -eq $true)"
    }

    if ($IsMacOS) {
        $user = whoami
        $groups = (id -Gn $user).Split(' ') # Use `id -Gn` for consistent group names on macOS
        $formattedGroups = $groups -join ', '
        Write-Output 'Pester Execution Context (macOS):'
        Write-Output "  - User:    $user"
        Write-Output "  - Groups:  $formattedGroups"
    }

    Write-Output ''

    if ($UICulture -ne ([System.Threading.Thread]::CurrentThread.CurrentUICulture) ) {
        $originalUICulture = [System.Threading.Thread]::CurrentThread.CurrentUICulture
        Write-Output "Original UICulture is $originalUICulture"
        Write-Output "Set UICulture to $UICulture"
        # set new UICulture
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $UICulture
    }
    $Script:TestResultFile = "$($pwd)/TestResults.xml"

    # get default from static property
    $configuration = [PesterConfiguration]::Default
    $configuration.run.path = @('./tests/unit', './tests/integration')
    $configuration.run.PassThru = $true
    $configuration.Output.Verbosity = $PesterVerbosity
    $configuration.TestResult.OutputPath = $Script:TestResultFile
    $excludeTag = @()
    if ( $PSEdition -ne 'Core') {
        $excludeTag += 'Exclude_DesktopEdition'
    }
    if ($IsLinux) {
        $excludeTag += 'Exclude_Linux'
    }
    if ($IsMacOS) {
        $excludeTag += 'Exclude_MacOs'
    }
    if ($IsWindows) {
        $excludeTag += 'Exclude_Windows'
    }
    $configuration.Filter.ExcludeTag = $excludeTag

    # if run code coverage if enabled
    if (Test-PodeBuildCanCodeCoverage) {
        $srcFiles = (Get-ChildItem "$($pwd)/src/*.ps1" -Recurse -Force).FullName
        $configuration.CodeCoverage.Enabled = $true
        $configuration.CodeCoverage.Path = $srcFiles
        $Script:TestStatus = Invoke-Pester -Configuration $configuration
    }
    else {
        $Script:TestStatus = Invoke-Pester -Configuration $configuration
    }
    if ($originalUICulture) {
        Write-Output "Restore UICulture to $originalUICulture"
        # restore original UICulture
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $originalUICulture
    }
}, PushCodeCoverage, CheckFailedTests

# Synopsis: Run tests after a build
Add-BuildTask Test Build, TestNoBuild

# Synopsis: Check if any of the tests failed
Add-BuildTask CheckFailedTests {
    if ($TestStatus.FailedCount -gt 0) {
        throw "$($TestStatus.FailedCount) tests failed"
    }
}

# Synopsis: If AppVeyor or GitHub, push code coverage stats
Add-BuildTask PushCodeCoverage -If (Test-PodeBuildCanCodeCoverage) {
    try {
        $service = Get-PodeBuildService
        $branch = Get-PodeBuildBranch

        Write-Host "Pushing coverage for $($branch) from $($service)"
        $coverage = New-CoverallsReport -Coverage $Script:TestStatus.CodeCoverage -ServiceName $service -BranchName $branch
        Publish-CoverallsReport -Report $coverage -ApiToken $env:PODE_COVERALLS_TOKEN
    }
    catch {
        $_.Exception | Out-Default
    }
}


<#
# Docs
#>

# Synopsis: Run the documentation locally
Add-BuildTask Docs DocsDeps, DocsHelpBuild, {
    mkdocs serve --open
}

# Synopsis: Build the function help documentation
Add-BuildTask DocsHelpBuild IndexSamples, DocsDeps, Build, {
    # import the local module
    Remove-Module Pode -Force -ErrorAction Ignore | Out-Null
    Import-Module ./src/Pode.psm1 -Force | Out-Null

    # build the function docs
    $path = './docs/Functions'
    $map = @{}

    (Get-Module Pode).ExportedFunctions.Keys | ForEach-Object {
        $type = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path -Leaf -Path (Get-Command $_ -Module Pode).ScriptBlock.File))
        New-MarkdownHelp -Command $_ -OutputFolder (Join-Path $path $type) -Force -Metadata @{ PodeType = $type } -AlphabeticParamsOrder | Out-Null
        $map[$_] = $type
    }

    # update docs to bind links to unlinked functions
    $path = Join-Path $pwd 'docs'
    Get-ChildItem -Path $path -Recurse -Filter '*.md' | ForEach-Object {
        $depth = ($_.FullName.Replace($path, [string]::Empty).trim('\/') -split '[\\/]').Length
        $updated = $false

        $content = (Get-Content -Path $_.FullName | ForEach-Object {
                $line = $_

                while ($line -imatch '\[`(?<name>[a-z]+\-pode[a-z]+)`\](?<char>([^(] | $))') {
                    $updated = $true
                    $name = $Matches['name']
                    $char = $Matches['char']
                    $line = ($line -ireplace "\[``$($name)``\]([^(]|$)", "[``$($name)``]($('../' * $depth)Functions/$($map[$name])/$($name))$($char)")
                }

                $line
            })

        if ($updated) {
            $content | Out-File -FilePath $_.FullName -Force -Encoding ascii
        }
    }

    # remove the module
    Remove-Module Pode -Force -ErrorAction Ignore | Out-Null
}

# Synopsis: Build the documentation
Add-BuildTask DocsBuild DocsDeps, DocsHelpBuild, {
    mkdocs build --quiet
}


<#
# Clean-up
#>

# Synopsis: Clean the build environment
Add-BuildTask Clean  CleanPkg, CleanDeliverable, CleanLibs, CleanListener, CleanDocs, CleanYarn

# Synopsis: Clean the Deliverable folder
Add-BuildTask CleanDeliverable {
    $path = './deliverable'
    if (Test-Path -Path $path -PathType Container) {
        Write-Host 'Removing ./deliverable folder'
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }
    Write-Host "Cleanup $path done"
}

# Synopsis: Clean the pkg directory
Add-BuildTask CleanPkg {
    $path = './pkg'
    if ((Test-Path -Path $path -PathType Container )) {
        Write-Host 'Removing ./pkg folder'
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }

    if ((Test-Path -Path .\packers\choco\tools\ChocolateyInstall.ps1 -PathType Leaf )) {
        Write-Host 'Removing .\packers\choco\tools\ChocolateyInstall.ps1'
        Remove-Item -Path .\packers\choco\tools\ChocolateyInstall.ps1
    }

    if ((Test-Path -Path .\packers\choco\pode.nuspec -PathType Leaf )) {
        Write-Host 'Removing .\packers\choco\pode.nuspec'
        Remove-Item -Path .\packers\choco\pode.nuspec
    }

    Write-Host "Cleanup $path done"
}

# Synopsis: Clean the libs folder
Add-BuildTask CleanLibs {
    $path = './src/Libs'
    if (Test-Path -Path $path -PathType Container) {
        Write-Host "Removing $path  contents"
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }

    $path = './src/Bin'
    if (Test-Path -Path $path -PathType Container) {
        Write-Host "Removing $path  contents"
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }

    Write-Host "Cleanup $path done"
}

# Synopsis: Clean the Listener folder
Add-BuildTask CleanListener {
    $path = './src/Listener/bin'
    if (Test-Path -Path $path -PathType Container) {
        Write-Host "Removing $path contents"
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }

    Write-Host "Cleanup $path done"
}

Add-BuildTask CleanDocs {
    $path = './docs/Getting-Started/Samples.md'
    if (Test-Path -Path $path -PathType Leaf) {
        Write-Host "Removing $path"
        Remove-Item -Path $path -Force | Out-Null
    }
}

Add-BuildTask CleanYarn {
    $path = Join-Path -Path $PSScriptRoot -ChildPath 'pode_modules'
    if (Test-Path -Path $path -PathType Container) {
        Write-Host "Removing $path"
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }
    $path = Join-Path -Path $PSScriptRoot -ChildPath '/src/Misc/libs'
    if (Test-Path -Path $path -PathType Container) {
        Write-Host "Removing $path"
        Remove-Item -Path $path -Recurse -Force | Out-Null
    }
}
<#
# Local module management
#>

# Synopsis: Install Pode Module locally
Add-BuildTask Install-Module -If ($Version) Pack, {
    $PSPaths = Split-PodeBuildPwshPath

    $dest = Join-Path -Path $PSPaths[0] -ChildPath 'Pode' -AdditionalChildPath "$Version"
    if (Test-Path $dest) {
        Remove-Item -Path $dest -Recurse -Force | Out-Null
    }

    # create the dest dir
    New-Item -Path $dest -ItemType Directory -Force | Out-Null
    $path = './pkg'

    # copy over folders
    $folders = @('Private', 'Public', 'Misc', 'Libs', 'licenses', 'Locales')
    $folders | ForEach-Object {
        Copy-Item -Path (Join-Path -Path $path -ChildPath $_) -Destination $dest -Force -Recurse | Out-Null
    }

    # copy over general files
    $files = @('Pode.psm1', 'Pode.psd1', 'Pode.Internal.psm1', 'Pode.Internal.psd1', 'LICENSE.txt')
    $files | ForEach-Object {
        Copy-Item -Path (Join-Path -Path $path -ChildPath $_) -Destination $dest -Force | Out-Null
    }

    Write-Host "Deployed to $dest"
}

# Synopsis: Remove the Pode Module from the local registry
Add-BuildTask Remove-Module {
    if (!$Version) {
        throw 'Parameter -Version is required'
    }

    $PSPaths = Split-PodeBuildPwshPath

    $dest = Join-Path -Path $PSPaths[0] -ChildPath 'Pode' -AdditionalChildPath "$Version"
    if (!(Test-Path $dest)) {
        Write-Warning "Directory $dest doesn't exist"
    }

    Write-Host "Deleting module from $dest"
    Remove-Item -Path $dest -Recurse -Force | Out-Null
}


<#
# PowerShell setup
#>

# Synopsis: Setup the PowerShell environment
Add-BuildTask SetupPowerShell {
    # code for this step is altered versions of the code found here:
    # - https://github.com/bjompen/UpdatePWSHAction/blob/main/UpgradePwsh.ps1
    # - https://raw.githubusercontent.com/PowerShell/PowerShell/master/tools/install-powershell.ps1

    # fail if no version supplied
    if ([string]::IsNullOrWhiteSpace($PowerShellVersion)) {
        throw 'No PowerShell version supplied to set up'
    }

    # is the version valid?
    $tags = @('preview', 'lts', 'daily', 'stable')
    if (($PowerShellVersion -inotin $tags) -and ($PowerShellVersion -inotmatch '^\d+\.\d+\.\d+(-\w+(\.\d+)?)?$')) {
        throw "Invalid PowerShell version supplied: $($PowerShellVersion)"
    }

    # tag version or literal version?
    $isTagVersion = $PowerShellVersion -iin $tags
    if ($isTagVersion) {
        Write-Host "Release tag: $($PowerShellVersion)"
        $PowerShellVersion = Convert-PodeBuildOSPwshTagToVersion
    }
    Write-Host "Release version: $($PowerShellVersion)"

    # base/prefix versions
    $atoms = $PowerShellVersion -split '\-'
    $baseVersion = $atoms[0]

    # do nothing if the current version is the version we're trying to set up
    $currentVersion = Get-PodeBuildCurrentPwshVersion
    Write-Host "Current PowerShell version: $($currentVersion)"

    if ($baseVersion -ieq $currentVersion) {
        Write-Host "PowerShell version $($PowerShellVersion) is already installed"
        return
    }

    # build the package name
    $arch = Get-PodeBuildOSPwshArchitecture
    $os = Get-PodeBuildOSPwshName

    $packageName = (@{
            win   = "PowerShell-$($PowerShellVersion)-$($os)-$($arch).zip"
            linux = "powershell-$($PowerShellVersion)-$($os)-$($arch).tar.gz"
            osx   = "powershell-$($PowerShellVersion)-$($os)-$($arch).tar.gz"
        })[$os]

    # build the URL
    $urls = @{
        Old = "https://pscoretestdata.blob.core.windows.net/v$($PowerShellVersion -replace '\.', '-')/$($packageName)"
        New = "https://powershellinfraartifacts-gkhedzdeaghdezhr.z01.azurefd.net/install/v$($PowerShellVersion)/$($packageName)"
    }

    # download the package to a temp location
    $outputFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $packageName
    $downloadParams = @{
        Uri         = $urls.New
        OutFile     = $outputFile
        ErrorAction = 'Stop'
    }

    Write-Host "Output file: $($outputFile)"

    # retry the download 6 times, with a sleep of 10s between each attempt, and altering between old and new URLs
    $counter = 0
    $success = $false

    do {
        try {
            $counter++
            Write-Host "Attempt $($counter) of 6"

            # use new URL for odd attempts, and old URL for even attempts
            if ($counter % 2 -eq 0) {
                $downloadParams.Uri = $urls.Old
            }
            else {
                $downloadParams.Uri = $urls.New
            }

            # download the package
            Write-Host "Attempting download of $($packageName) from $($downloadParams.Uri)"
            Invoke-WebRequest @downloadParams

            $success = $true
            Write-Host "Downloaded $($packageName) successfully"
        }
        catch {
            $success = $false
            if ($counter -ge 6) {
                throw "Failed to download PowerShell package after 6 attempts. Error: $($_.Exception.Message)"
            }

            Start-Sleep -Seconds 5
        }
    } while (!$success)

    # create target folder for package
    $targetFolder = Join-Path -Path (Resolve-Path ~).Path -ChildPath ($packageName -ireplace '\.tar$')
    if (!(Test-Path $targetFolder)) {
        $null = New-Item -Path $targetFolder -ItemType Directory -Force
    }

    # extract the package
    switch ($os) {
        'win' {
            Expand-Archive -Path $outputFile -DestinationPath $targetFolder -Force
        }

        { $_ -iin 'linux', 'osx' } {
            $null = tar -xzf $outputFile -C $targetFolder
        }
    }

    # install the package
    Write-Host "Installing PowerShell $($PowerShellVersion) to $($targetFolder)"
    if (Test-PodeBuildOSWindows) {
        Install-PodeBuildPwshWindows -Target $targetFolder
    }
    else {
        Install-PodeBuildPwshUnix -Target $targetFolder
    }
}


<#
# Release Notes
#>

# Synopsis: Build the Release Notes
Add-BuildTask ReleaseNotes {
    if ([string]::IsNullOrWhiteSpace($ReleaseNoteVersion)) {
        Write-Host 'Please provide a ReleaseNoteVersion' -ForegroundColor Red
        return
    }

    # get the PRs for the ReleaseNoteVersion
    $prs = gh search prs --milestone $ReleaseNoteVersion --repo badgerati/pode --merged --limit 200 --json 'number,title,labels,author' | ConvertFrom-Json

    # group PRs into categories, filtering out some internal PRs
    $categories = [ordered]@{
        Features      = @()
        Enhancements  = @()
        Bugs          = @()
        Documentation = @()
    }

    $dependabot = @{}

    foreach ($pr in $prs) {
        $labels = @($pr.labels.name)

        # skip PRs with certain labels
        if ($labels -icontains 'superseded' -or
            $labels -icontains 'new-release' -or
            $labels -icontains 'internal-code :hammer:' -or
            $labels -icontains 'exclude-from-release-notes') {
            continue
        }

        # filter out labels that are not relevant
        $label = @(foreach ($label in $labels) {
                if ($label -imatch '^(story|priority)') {
                    continue
                }

                if ($label -inotmatch '\s\:') {
                    continue
                }

                ($label -split ' ', 2)[0]
                break
            })[0]

        if ([string]::IsNullOrWhiteSpace($label)) {
            $label = 'misc'
        }

        switch ($label.ToLowerInvariant()) {
            'feature' { $label = 'Features' }
            'enhancement' { $label = 'Enhancements' }
            'bug' { $label = 'Bugs' }
        }

        if (!$categories.Contains($label)) {
            $categories[$label] = @()
        }

        if ($pr.author.login -ilike '*dependabot*') {
            if ($pr.title -imatch 'Bump (?<name>\S+) from (?<from>[0-9\.]+) to (?<to>[0-9\.]+)') {
                if (!$dependabot.ContainsKey($Matches['name'])) {
                    $dependabot[$Matches['name']] = @{
                        Name   = $Matches['name']
                        Number = $pr.number
                        From   = [version]$Matches['from']
                        To     = [version]$Matches['to']
                    }
                }
                else {
                    $item = $dependabot[$Matches['name']]
                    if ([int]$pr.number -gt [int]$item.Number) {
                        $item.Number = $pr.number
                    }
                    if ([version]$Matches['from'] -lt $item.From) {
                        $item.From = [version]$Matches['from']
                    }
                    if ([version]$Matches['to'] -gt $item.To) {
                        $item.To = [version]$Matches['to']
                    }
                }

                continue
            }
        }

        $titles = @($pr.title).Trim()
        if ($pr.title.Contains(';')) {
            $titles = ($pr.title -split ';').Trim()
        }

        $author = $null
        if (($pr.author.login -ine 'badgerati') -and ($pr.author.login -inotlike '*dependabot*')) {
            $author = $pr.author.login
        }

        foreach ($title in $titles) {
            $str = "* #$($pr.number): $($title -replace '`', "'")"
            if (![string]::IsNullOrWhiteSpace($author)) {
                $str += " (thanks @$($author)!)"
            }

            if ($str -imatch '\s+(docs|documentation)\s+') {
                $categories['Documentation'] += $str
            }
            else {
                $categories[$label] += $str
            }
        }
    }

    # add dependabot aggregated PRs
    if ($dependabot.Count -gt 0) {
        $label = 'Packaging'
        if (!$categories.Contains($label)) {
            $categories[$label] = @()
        }

        foreach ($dep in $dependabot.Values) {
            $categories[$label] += "* #$($dep.Number): Bump $($dep.Name) from $($dep.From) to $($dep.To)"
        }
    }

    # output the release notes
    Write-Host "# v$($ReleaseNoteVersion)`n"

    $culture = (Get-Culture).TextInfo
    foreach ($category in $categories.Keys) {
        if ($categories[$category].Length -eq 0) {
            continue
        }

        Write-Host "### $($culture.ToTitleCase($category))"
        $categories[$category] | Sort-Object | ForEach-Object { Write-Host $_ }
        Write-Host ''
    }
}


# Sort the language file contents and remove any duplicate entries.
Add-BuildTask Sort-LanguageFiles {
    Group-LanguageResource
}

# Adds a build task to automatically merge conflicting language files.
# This task identifies unresolved merge conflicts in the 'src/Locales/' directory and attempts to resolve them by:
# 1. Detecting files with merge conflicts using `git diff --name-only --diff-filter=U`.
# 2. Removing Git conflict markers (`<<<<<<< HEAD`, `=======`, and `>>>>>>> pr-<number>`),
#    dynamically detecting the PR number from the conflict markers.
# 3. Running `Group-LanguageResource` to ensure language resources are correctly formatted.
# 4. Staging the resolved files (`git add ./src/Locales/*`).
# 5. Printing status messages for visibility during execution.
Add-BuildTask AutoMerge-LanguageFiles {
    Write-Output 'Attempting auto-merge for language files...'

    # Identify files with unresolved merge conflicts in 'src/Locales/'.
    git diff --name-only --diff-filter=U ./src/Locales/ | ForEach-Object {
        $content = Get-Content $_ -Raw
        if ($content -match '>>>>>>> pr-(\d+)') {
            # Remove Git conflict markers, dynamically resolving PR numbers
            $content -replace '<<<<<<< HEAD', '' -replace '=======', '' -replace ">>>>>>> pr-$($matches[1])", '' | Set-Content $_
        }
    }

    # Ensure language resources are formatted and grouped correctly.
    Group-LanguageResource

    # Stage the resolved files.
    git add ./src/Locales/*

    Write-Output 'Language files auto-merged.'
}



# Adds or refreshes the file-level header and footer using Pode's standard formatting.
Add-BuildTask Refresh-HeaderFooter {
    $baseDirs = '.\src\Public', '.\src\Private'

    foreach ($dir in $baseDirs) {
        $isPrivate = $dir -like '*\Private'

        foreach ($file in Get-ChildItem -Path $dir -Recurse -Filter *.ps1) {
            $path = $file.FullName
            $original = Get-Content -Raw -Path $path

            #
            #  ———  CLEAN UP ANY PREVIOUSLY‑INJECTED HEADER & FOOTER ———
            #

            # Remove an existing Pode file header block (from start-of-file through its closing #>)
            $cleaned = $original -replace '(?ms)^<#\r?\n\s*File:[\s\S]*?#>\s*(?:\r?\n)*', ''
            # Strip old footer (use $cleaned, not $original!)
            $cleaned = $cleaned -replace '(?ms)#[-]{42}\r?\n# End of [\s\S]*$', ''

            # Now split on lines and work off $cleaned
            $lines = $cleaned -split "`n"
            $new = ''

            #—— 1) Gather function names ——
            $functions = @()
            foreach ($ln in $lines) {
                if ($ln -match '^\s*function\s+([a-zA-Z0-9\-_]+)\s*{') {
                    $functions += $Matches[1]
                }
            }

            # — Determine repo root & relative path
            $repoRoot = (& git rev-parse --show-toplevel).Trim()
            $relativePath = $path.Substring($repoRoot.Length + 1).Replace('\', '/')

            # — Query Git for creation & last‐modified info
            #   (uses ISO short dates; adjust --date= if you need time-of-day)
            $gitCreated = (& git log --reverse --format="%ad" --date=short -- $relativePath |
                    Select-Object -First 1)
            if (-not $gitCreated) { $gitCreated = '(untracked)' }

            $gitModified = (& git log -1 --format="%ad" --date=short -- $relativePath) `
                -replace '^$', '(untracked)'
            $lastAuthor = (& git log -1 --format="%an" -- $relativePath) `
                -replace '^$', '—'
            $lastSha = (& git log -1 --format="%h"  -- $relativePath) `
                -replace '^$', '—'


            #—— 2) Build top-of-file header ——
            $headerLines = @(
                '<#'
                "    File:      $relativePath"
                ''
                "    Created:   $gitCreated"
                "    Modified:  $gitModified by $lastAuthor (commit $lastSha)"
            )


            if ($functions.Count) {
                $headerLines += @(
                    ''
                    '    Functions:'
                )
                foreach ($fn in $functions) {
                    $headerLines += "        $fn"
                }
            }
            # Standard Notes section (applies to all)
            $headerLines += @(
                ''
                '    Notes:'
                '        This file is part of the Pode server framework.'
                '        https://github.com/Badgerati/Pode'
                ''
                '    License:'
                '        MIT License - See LICENSE file in the project root for full license information.'
            )
            if ($isPrivate) {
                $headerLines += @(
                    ''
                    '    WARNING: This file may contain internal implementation details.'
                    '    Use at your own risk.'
                )
            }
            $headerLines += @(
                '#>'    # single blank line before code starts
                ''      # first blank line
                ''      # second blank line
            )
            $new += ($headerLines -join "`n")

            $new += $cleaned.TrimEnd()
            #  ——— APPEND A SINGLE FOOTER BLOCK ———
            $new += "`n`n#------------------------------------------`n"
            $new += "# End of $relativePath`n"
            $new += '#------------------------------------------'


            #—— 6) Write if changed ——
            if ($new -and $new -ne $original) {
                Set-Content -Path $path -Value $new
            }
        }
    }
}


# Automatically formats the headers of all functions to match Pode's formatting conventions.
Add-BuildTask Format-FunctionHeaders {
    $baseDirs = '.\src\Public', '.\src\Private'

    foreach ($dir in $baseDirs) {
        $isPrivate = $dir -like '*\Private'

        foreach ($file in Get-ChildItem -Path $dir -Recurse -Filter *.ps1) {
            $path = $file.FullName
            $original = Get-Content -Raw -Path $path

            # ——— Extract and preserve the file header (up through the closing #> plus the two blank lines) ———
            $headerPattern = '(?ms)^(<#\r?\n\s*File:[\s\S]*?#>\s*\r?\n\r?\n)'
            $m = [regex]::Match($original, $headerPattern)
            if ($m.Success) {
                $fileHeader = $m.Value
                $body = $original.Substring($m.Length)
            }
            else {
                $fileHeader = ''
                $body = $original
            }

            # Now split on lines and work off $cleaned
            $lines = $body -split "`n"
            # start your new content with the preserved header
            $new = $fileHeader

            #—— 3) Re‑format any existing help blocks ——
            $insideHelp = $false
            $sections = @()
            foreach ($line in $lines) {
                switch -Regex ($line) {
                    '^\s*<#\s*$' {
                        $insideHelp = $true
                        $sections = @()
                        continue
                    }
                    '^\s*#>\s*$' {
                        # inject default .NOTES on private
                        if ($isPrivate -and -not ($sections.Where({ $_.Header -match '^\.(NOTES)\b' }).Count)) {
                            $sections += [pscustomobject]@{
                                Header = '.NOTES'
                                Lines  = @('This is an internal function and may change in future releases of Pode.')
                            }
                        }
                        # rebuild help block
                        $new += '<#' + "`n"
                        foreach ($sec in $sections) {
                            $new += "$($sec.Header)`n"
                            foreach ($content in $sec.Lines) {
                                if ($content.Trim() -eq '') {
                                    $new += "`n"
                                }
                                else {
                                    if ($sec.Header -match '^\.EXAMPLE\b') {
                                        if ($content -match '^[ ]{4}') {
                                            $new += "$content`n"
                                        }
                                        else {
                                            $new += "    $content`n"
                                        }
                                    }
                                    else {
                                        $new += "    $($content.Trim())`n"
                                    }
                                }
                            }
                        }
                        $new += '#>' + "`n"
                        $insideHelp = $false
                        continue
                    }
                    default {
                        if ($insideHelp) {
                            if ($line -match '^\s*(\.(SYNOPSIS|DESCRIPTION|PARAMETER|EXAMPLE|OUTPUTS|NOTES)\b.*)') {
                                $sections += [pscustomobject]@{
                                    Header = $Matches[1].Trim()
                                    Lines  = @()
                                }
                            }
                            elseif ($sections) {
                                $sections[-1].Lines += $line
                            }
                            continue
                        }
                        $new += $line + "`n"
                    }
                }
            }

            #  BEFORE APPENDING FOOTER: trim any trailing blank lines/spaces
            $new = $new.TrimEnd("`r", "`n", ' ')


            #—— 5) Normalize blank lines ——
            # a) After '#>' collapse any run of blank lines down to exactly one real newline
            $new = $new -replace '(?m)(#>\r?\n)(?:[ \t]*\r?\n)+(?=\s*function\b)', '$1'
            # b) Between a closing '}' and the next '<#', enforce exactly two real newlines
            $new = $new -replace '(?m)(\})\r?\n(?:[ \t]*\r?\n)+<#', "`$1`n`n`n<#"

            #—— 6) Write if changed ——
            if ($new -and $new -ne $original) {
                Set-Content -Path $path -Value $new
            }
        }
    }
}

#------------------------------------------
# End of pode.build.ps1
#------------------------------------------
