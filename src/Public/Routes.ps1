<#
.SYNOPSIS
Adds a Route for a specific HTTP Method(s).

.DESCRIPTION
Adds a Route for a specific HTTP Method(s), with path, that when called with invoke any logic and/or Middleware.

.PARAMETER Method
The HTTP Method of this Route, multiple can be supplied.

.PARAMETER Path
The URI path for the Route.

.PARAMETER Middleware
An array of ScriptBlocks for optional Middleware.

.PARAMETER ScriptBlock
A ScriptBlock for the Route's main logic.

.PARAMETER EndpointName
The EndpointName of an Endpoint(s) this Route should be bound against.

.PARAMETER ContentType
The content type the Route should use when parsing any payloads.

.PARAMETER TransferEncoding
The transfer encoding the Route should use when parsing any payloads.

.PARAMETER ErrorContentType
The content type of any error pages that may get returned.

.PARAMETER FilePath
A literal, or relative, path to a file containing a ScriptBlock for the Route's main logic.

.PARAMETER ArgumentList
An array of arguments to supply to the Route's ScriptBlock.

.PARAMETER Authentication
The name of an Authentication method which should be used as middleware on this Route.

.PARAMETER Access
The name of an Access method which should be used as middleware on this Route.

.PARAMETER AllowAnon
If supplied, the Route will allow anonymous access for non-authenticated users.

.PARAMETER Login
If supplied, the Route will be flagged to Authentication as being a Route that handles user logins.

.PARAMETER Logout
If supplied, the Route will be flagged to Authentication as being a Route that handles users logging out.

.PARAMETER PassThru
If supplied, the route created will be returned so it can be passed through a pipe.

.PARAMETER IfExists
Specifies what action to take when a Route already exists. (Default: Default)

.PARAMETER Role
One or more optional Roles that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER Group
One or more optional Groups that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER Scope
One or more optional Scopes that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER User
One or more optional Users that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER OAResponses
An alternative way to associate OpenApi responses unsing New-PodeOAResponse instead of piping multiple Add-PodeOAResponse

.PARAMETER OAReference
A reference to OpenAPI reusable pathItem component created with Add-PodeOAComponentPathItem

.PARAMETER OADefinitionTag
An Array of strings representing the unique tag for the API specification.
This tag helps in distinguishing between different versions or types of API specifications within the application.
You can use this tag to reference the specific API documentation, schema, or version that your function interacts with.

.EXAMPLE
Add-PodeRoute -Method Get -Path '/' -ScriptBlock { /* logic */ }

.EXAMPLE
Add-PodeRoute -Method Post -Path '/users/:userId/message' -Middleware (Get-PodeCsrfMiddleware) -ScriptBlock { /* logic */ }

.EXAMPLE
Add-PodeRoute -Method Post -Path '/user' -ContentType 'application/json' -ScriptBlock { /* logic */ }

.EXAMPLE
Add-PodeRoute -Method Post -Path '/user' -ContentType 'application/json' -TransferEncoding gzip -ScriptBlock { /* logic */ }

.EXAMPLE
Add-PodeRoute -Method Post -Path '/user' -ContentType 'application/json' -FilePath '/route.ps1'

.EXAMPLE
Add-PodeRoute -Method Get -Path '/api/cpu' -ErrorContentType 'application/json' -ScriptBlock { /* logic */ }

.EXAMPLE
Add-PodeRoute -Method Get -Path '/' -ScriptBlock { /* logic */ } -ArgumentList 'arg1', 'arg2'

.EXAMPLE
Add-PodeRoute -Method Get -Path '/' -Role 'Developer', 'QA' -ScriptBlock { /* logic */ }

.EXAMPLE
$Responses = New-PodeOAResponse -StatusCode 400 -Description 'Invalid username supplied' |
            New-PodeOAResponse -StatusCode 404 -Description 'User not found' |
            New-PodeOAResponse -StatusCode 405 -Description 'Invalid Input'

Add-PodeRoute -PassThru -Method Put -Path '/user/:username' -OAResponses $Responses -ScriptBlock {
            #code is going here
        }
#>
function Add-PodeRoute {
    [CmdletBinding(DefaultParameterSetName = 'Script')]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [ValidateSet('Connect', 'Delete', 'Get', 'Head', 'Merge', 'Options', 'Patch', 'Post', 'Put', 'Trace', '*')]
        [string[]]
        $Method = 'Get',

        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [object[]]
        $Middleware,

        [Parameter(ParameterSetName = 'Script')]
        [scriptblock]
        $ScriptBlock,

        [Parameter( )]
        [AllowNull()]
        [string[]]
        $EndpointName,

        [Parameter()]
        [string]
        $ContentType,

        [Parameter()]
        [ValidateSet('', 'brotli', 'gzip', 'deflate')]
        [string]
        $TransferEncoding,

        [Parameter()]
        [string]
        $ErrorContentType,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $FilePath,

        [Parameter()]
        [object[]]
        $ArgumentList,

        [Parameter()]
        [Alias('Auth')]
        [string]
        $Authentication,

        [Parameter()]
        [string]
        $Access,

        [Parameter()]
        [ValidateSet('Default', 'Error', 'Overwrite', 'Skip')]
        [string]
        $IfExists = 'Default',

        [Parameter()]
        [string[]]
        $Role,

        [Parameter()]
        [string[]]
        $Group,

        [Parameter()]
        [string[]]
        $Scope,

        [Parameter()]
        [string[]]
        $User,

        [switch]
        $AllowAnon,

        [switch]
        $Login,

        [switch]
        $Logout,

        [hashtable]
        $OAResponses,

        [string]
        $OAReference,

        [switch]
        $PassThru,

        [string[]]
        $OADefinitionTag
    )

    # check if we have any route group info defined
    if ($null -ne $RouteGroup) {
        if (![string]::IsNullOrWhiteSpace($RouteGroup.Path)) {
            $Path = "$($RouteGroup.Path)$($Path)"
        }

        if ($null -ne $RouteGroup.Middleware) {
            $Middleware = $RouteGroup.Middleware + $Middleware
        }

        if ([string]::IsNullOrWhiteSpace($EndpointName)) {
            $EndpointName = $RouteGroup.EndpointName
        }

        if ([string]::IsNullOrWhiteSpace($ContentType)) {
            $ContentType = $RouteGroup.ContentType
        }

        if ([string]::IsNullOrWhiteSpace($TransferEncoding)) {
            $TransferEncoding = $RouteGroup.TransferEncoding
        }

        if ([string]::IsNullOrWhiteSpace($ErrorContentType)) {
            $ErrorContentType = $RouteGroup.ErrorContentType
        }

        if ([string]::IsNullOrWhiteSpace($Authentication)) {
            $Authentication = $RouteGroup.Authentication
        }

        if ([string]::IsNullOrWhiteSpace($Access)) {
            $Access = $RouteGroup.Access
        }

        if ($RouteGroup.AllowAnon) {
            $AllowAnon = $RouteGroup.AllowAnon
        }

        if ($RouteGroup.IfExists -ine 'default') {
            $IfExists = $RouteGroup.IfExists
        }

        if ($null -ne $RouteGroup.AccessMeta.Role) {
            $Role = $RouteGroup.AccessMeta.Role + $Role
        }

        if ($null -ne $RouteGroup.AccessMeta.Group) {
            $Group = $RouteGroup.AccessMeta.Group + $Group
        }

        if ($null -ne $RouteGroup.AccessMeta.Scope) {
            $Scope = $RouteGroup.AccessMeta.Scope + $Scope
        }

        if ($null -ne $RouteGroup.AccessMeta.User) {
            $User = $RouteGroup.AccessMeta.User + $User
        }

        if ($null -ne $RouteGroup.AccessMeta.Custom) {
            $CustomAccess = $RouteGroup.AccessMeta.Custom
        }

        if ($null -ne $RouteGroup.OADefinitionTag ) {
            $OADefinitionTag = $RouteGroup.OADefinitionTag
        }
    }

    # var for new routes created
    $newRoutes = @()

    # store the original path
    $origPath = $Path

    # split route on '?' for query
    $Path = Split-PodeRouteQuery -Path $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        # No Path supplied for the Route
        throw ($PodeLocale.noPathSuppliedForRouteExceptionMessage)
    }

    # ensure the route has appropriate slashes
    $Path = Update-PodeRouteSlash -Path $Path
    $OpenApiPath = ConvertTo-PodeOARoutePath -Path $Path
    $Path = Resolve-PodePlaceholder -Path $Path

    # get endpoints from name
    $endpoints = Find-PodeEndpoint -EndpointName $EndpointName

    # get default route IfExists state
    if ($IfExists -ieq 'Default') {
        $IfExists = Get-PodeRouteIfExistsPreference
    }

    # if middleware, scriptblock and file path are all null/empty, create an empty scriptblock
    if ((Test-PodeIsEmpty $Middleware) -and (Test-PodeIsEmpty $ScriptBlock) -and (Test-PodeIsEmpty $FilePath) -and (Test-PodeIsEmpty $Authentication)) {
        $ScriptBlock = {}
    }

    # if we have a file path supplied, load that path as a scriptblock
    if ($PSCmdlet.ParameterSetName -ieq 'file') {
        $ScriptBlock = Convert-PodeFileToScriptBlock -FilePath $FilePath
    }

    # check for scoped vars
    $ScriptBlock, $usingVars = Convert-PodeScopedVariables -ScriptBlock $ScriptBlock -PSSession $PSCmdlet.SessionState

    # convert any middleware into valid hashtables
    $realMiddleware = @(ConvertTo-PodeMiddleware -Middleware $Middleware -PSSession $PSCmdlet.SessionState)

    # if an access name was supplied, setup access as middleware first to it's after auth middleware
    if (![string]::IsNullOrWhiteSpace($Access)) {
        if ([string]::IsNullOrWhiteSpace($Authentication)) {
            # Access requires Authentication to be supplied on Routes
            throw ($PodeLocale.accessRequiresAuthenticationOnRoutesExceptionMessage)
        }

        if (!(Test-PodeAccessExists -Name $Access)) {
            # Access method does not exist
            throw ($PodeLocale.accessMethodDoesNotExistExceptionMessage -f $Access)
        }

        $options = @{
            Name = $Access
        }

        $realMiddleware = (@(Get-PodeAccessMiddlewareScript | New-PodeMiddleware -ArgumentList $options) + $realMiddleware)
    }

    # if an auth name was supplied, setup the auth as the first middleware
    if (![string]::IsNullOrWhiteSpace($Authentication)) {
        if (!(Test-PodeAuthExists -Name $Authentication)) {
            # Authentication method does not exist
            throw ($PodeLocale.authenticationMethodDoesNotExistExceptionMessage -f $Authentication)
        }

        # Validate that the HTTP method supports a request body when using bearer token authentication.
        # This ensures that only PUT, POST, and PATCH methods are used for body-based authentication.
        Test-PodeBodyAuthMethod -Method $Method -Authentication $Authentication

        $options = @{
            Name   = $Authentication
            Login  = $Login
            Logout = $Logout
            Anon   = $AllowAnon.IsPresent
        }

        $realMiddleware = (@(Get-PodeAuthMiddlewareScript | New-PodeMiddleware -ArgumentList $options) + $realMiddleware)
    }

    # custom access
    if ($null -eq $CustomAccess) {
        $CustomAccess = @{}
    }

    # workout a default content type for the route
    $ContentType = Find-PodeRouteContentType -Path $Path -ContentType $ContentType

    # workout a default transfer encoding for the route
    $TransferEncoding = Find-PodeRouteTransferEncoding -Path $Path -TransferEncoding $TransferEncoding

    # loop through each method
    foreach ($_method in $Method) {
        # ensure the route doesn't already exist for each endpoint
        $endpoints = @(foreach ($_endpoint in $endpoints) {
                $found = Test-PodeRouteInternal -Method $_method -Path $Path -Protocol $_endpoint.Protocol -Address $_endpoint.Address -ThrowError:($IfExists -ieq 'Error')

                if ($found) {
                    if ($IfExists -ieq 'Overwrite') {
                        Remove-PodeRoute -Method $_method -Path $origPath -EndpointName $_endpoint.Name
                    }

                    if ($IfExists -ieq 'Skip') {
                        continue
                    }
                }

                $_endpoint
            })

        if (($null -eq $endpoints) -or ($endpoints.Length -eq 0)) {
            continue
        }

        #add security header method if autoMethods is enabled
        if (  $PodeContext.Server.Security.autoMethods ) {
            Add-PodeSecurityHeader -Name 'Access-Control-Allow-Methods' -Value $_method.ToUpper() -Append
        }

        $DefinitionTag = Test-PodeOADefinitionTag -Tag $OADefinitionTag

        #add the default OpenApi responses
        if ( $PodeContext.Server.OpenAPI.Definitions[$DefinitionTag].hiddenComponents.defaultResponses) {
            $DefaultResponse = [ordered]@{}
            foreach ($tag in $DefinitionTag) {
                $DefaultResponse[$tag] = Copy-PodeObjectDeepClone -InputObject $PodeContext.Server.OpenAPI.Definitions[$tag].hiddenComponents.defaultResponses
            }
        }

        # add the route(s)
        Write-Verbose "Adding Route: [$($_method)] $($Path)"
        $methodRoutes = @(foreach ($_endpoint in $endpoints) {
                @{
                    Logic            = $ScriptBlock
                    UsingVariables   = $usingVars
                    Middleware       = $realMiddleware
                    MiddlewareMeta   = @{
                        Name       = $Authentication
                        Login      = $Login
                        Logout     = $Logout
                        Anon       = $AllowAnon.IsPresent
                        Middleware = $Middleware
                    }
                    Authentication   = $Authentication
                    Access           = $Access
                    AccessMeta       = @{
                        Role   = $Role
                        Group  = $Group
                        Scope  = $Scope
                        User   = $User
                        Custom = $CustomAccess
                    }
                    Endpoint         = @{
                        Protocol = $_endpoint.Protocol
                        Address  = $_endpoint.Address.Trim()
                        Name     = $_endpoint.Name
                    }
                    ContentType      = $ContentType
                    TransferEncoding = $TransferEncoding
                    ErrorType        = $ErrorContentType
                    Arguments        = $ArgumentList
                    Method           = $_method
                    Path             = $Path
                    IsAsync          = $false
                    Async            = @{}
                    OpenApi          = @{
                        Path               = $OpenApiPath
                        Responses          = $DefaultResponse
                        Parameters         = [ordered]@{}
                        RequestBody        = [ordered]@{}
                        CallBacks          = [ordered]@{}
                        Authentication     = @()
                        Servers            = @()
                        DefinitionTag      = $DefinitionTag
                        IsDefTagConfigured = ($null -ne $OADefinitionTag) #Definition Tag has been configured (Not default)
                    }
                    IsStatic         = $false
                    Metrics          = @{
                        Requests = @{
                            Total       = 0
                            StatusCodes = @{}
                        }
                    }
                    Cache            = @{
                        Enabled = $false
                        MaxAge  = 60
                    }
                    Compression      = @{
                        Enabled   = $PodeContext.Server.Web.Compression.Enabled
                        Encodings = $PodeContext.Server.Web.Compression.Encodings
                        Request   = $false
                        Response  = $PodeContext.Server.Web.Compression.Enabled
                    }
                }
            })


        if ($PodeContext.Server.OpenAPI.Routes -notcontains $Path ) {
            $PodeContext.Server.OpenAPI.Routes += $Path
        }


        if (![string]::IsNullOrWhiteSpace($Authentication)) {
            Set-PodeOAAuth -Route $methodRoutes -Name $Authentication -AllowAnon:$AllowAnon
        }

        $PodeContext.Server.Routes[$_method][$Path] += @($methodRoutes)
        if ($PassThru) {
            $newRoutes += $methodRoutes
        }
    }
    if ($OAReference) {
        Test-PodeOAComponentInternal -Field pathItems -DefinitionTag $DefinitionTag -Name $OAReference -PostValidation
        foreach ($r in @($newRoutes)) {
            $r.OpenApi = @{
                '$ref'        = "#/components/paths/$OAReference"
                DefinitionTag = $DefinitionTag
                Path          = $OpenApiPath
            }
        }
    }
    elseif ($OAResponses) {
        foreach ($r in @($newRoutes)) {
            $r.OpenApi.Responses = $OAResponses
        }
    }

    # return the routes?
    if ($PassThru) {
        return $newRoutes
    }
}

<#
.SYNOPSIS
Add a static Route for rendering static content.

.DESCRIPTION
Add a static Route for rendering static content. You can also define default pages to display.

.PARAMETER Path
The URI path for the static Route.

.PARAMETER Source
The literal, or relative, path to the directory that contains the static content.

.PARAMETER Middleware
An array of ScriptBlocks for optional Middleware.

.PARAMETER EndpointName
The EndpointName of an Endpoint(s) to bind the static Route against.

.PARAMETER ContentType
The content type the static Route should use when parsing any payloads.

.PARAMETER TransferEncoding
The transfer encoding the static Route should use when parsing any payloads.

.PARAMETER Defaults
An array of default pages to display, such as 'index.html'.

.PARAMETER ErrorContentType
The content type of any error pages that may get returned.

.PARAMETER Authentication
The name of an Authentication method which should be used as middleware on this Route.

.PARAMETER Access
The name of an Access method which should be used as middleware on this Route.

.PARAMETER AllowAnon
If supplied, the static route will allow anonymous access for non-authenticated users.

.PARAMETER DownloadOnly
When supplied, all static content on this Route will be attached as downloads - rather than rendered.

.PARAMETER PassThru
If supplied, the static route created will be returned so it can be passed through a pipe.

.PARAMETER IfExists
Specifies what action to take when a Static Route already exists. (Default: Default)

.PARAMETER Role
One or more optional Roles that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER Group
One or more optional Groups that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER Scope
One or more optional Scopes that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER User
One or more optional Users that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER FileBrowser
If supplied, when the path is a folder, instead of returning 404, will return A browsable content of the directory.

.PARAMETER RedirectToDefault
If supplied, the user will be redirected to the default page if found instead of the page being rendered as the folder path.

.EXAMPLE
Add-PodeStaticRoute -Path '/assets' -Source './assets'

.EXAMPLE
Add-PodeStaticRoute -Path '/assets' -Source './assets' -Defaults @('index.html')

.EXAMPLE
Add-PodeStaticRoute -Path '/installers' -Source './exes' -DownloadOnly

.EXAMPLE
Add-PodeStaticRoute -Path '/assets' -Source './assets' -Defaults @('index.html') -RedirectToDefault
#>
function Add-PodeStaticRoute {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [string]
        $Source,

        [Parameter()]
        [object[]]
        $Middleware,

        [Parameter()]
        [string[]]
        $EndpointName,

        [Parameter()]
        [string]
        $ContentType,

        [Parameter()]
        [ValidateSet('', 'brotli', 'gzip', 'deflate')]
        [string]
        $TransferEncoding,

        [Parameter()]
        [string[]]
        $Defaults,

        [Parameter()]
        [string]
        $ErrorContentType,

        [Parameter()]
        [Alias('Auth')]
        [string]
        $Authentication,

        [Parameter()]
        [string]
        $Access,

        [Parameter()]
        [ValidateSet('Default', 'Error', 'Overwrite', 'Skip')]
        [string]
        $IfExists = 'Default',

        [Parameter()]
        [string[]]
        $Role,

        [Parameter()]
        [string[]]
        $Group,

        [Parameter()]
        [string[]]
        $Scope,

        [Parameter()]
        [string[]]
        $User,

        [switch]
        $AllowAnon,

        [switch]
        $DownloadOnly,

        [switch]
        $FileBrowser,

        [switch]
        $PassThru,

        [switch]
        $RedirectToDefault
    )

    # check if we have any route group info defined
    if ($null -ne $RouteGroup) {
        if (![string]::IsNullOrWhiteSpace($RouteGroup.Path)) {
            $Path = "$($RouteGroup.Path)$($Path)"
        }

        if (![string]::IsNullOrWhiteSpace($RouteGroup.Source)) {
            $Source = [System.IO.Path]::Combine($Source, $RouteGroup.Source.TrimStart('\/'))
        }

        if ($null -ne $RouteGroup.Middleware) {
            $Middleware = $RouteGroup.Middleware + $Middleware
        }

        if ([string]::IsNullOrWhiteSpace($EndpointName)) {
            $EndpointName = $RouteGroup.EndpointName
        }

        if ([string]::IsNullOrWhiteSpace($ContentType)) {
            $ContentType = $RouteGroup.ContentType
        }

        if ([string]::IsNullOrWhiteSpace($TransferEncoding)) {
            $TransferEncoding = $RouteGroup.TransferEncoding
        }

        if ([string]::IsNullOrWhiteSpace($ErrorContentType)) {
            $ErrorContentType = $RouteGroup.ErrorContentType
        }

        if ([string]::IsNullOrWhiteSpace($Authentication)) {
            $Authentication = $RouteGroup.Authentication
        }

        if ([string]::IsNullOrWhiteSpace($Access)) {
            $Access = $RouteGroup.Access
        }

        if (Test-PodeIsEmpty $Defaults) {
            $Defaults = $RouteGroup.Defaults
        }

        if ($RouteGroup.AllowAnon) {
            $AllowAnon = $RouteGroup.AllowAnon
        }

        if ($RouteGroup.DownloadOnly) {
            $DownloadOnly = $RouteGroup.DownloadOnly
        }

        if ($RouteGroup.FileBrowser) {
            $FileBrowser = $RouteGroup.FileBrowser
        }

        if ($RouteGroup.RedirectToDefault) {
            $RedirectToDefault = $RouteGroup.RedirectToDefault
        }

        if ($RouteGroup.IfExists -ine 'default') {
            $IfExists = $RouteGroup.IfExists
        }

        if ($null -ne $RouteGroup.AccessMeta.Role) {
            $Role = $RouteGroup.AccessMeta.Role + $Role
        }

        if ($null -ne $RouteGroup.AccessMeta.Group) {
            $Group = $RouteGroup.AccessMeta.Group + $Group
        }

        if ($null -ne $RouteGroup.AccessMeta.Scope) {
            $Scope = $RouteGroup.AccessMeta.Scope + $Scope
        }

        if ($null -ne $RouteGroup.AccessMeta.User) {
            $User = $RouteGroup.AccessMeta.User + $User
        }

        if ($null -ne $RouteGroup.AccessMeta.Custom) {
            $CustomAccess = $RouteGroup.AccessMeta.Custom
        }
    }

    # store the route method
    $Method = 'Static'

    # store the original path
    $origPath = $Path

    # split route on '?' for query
    $Path = Split-PodeRouteQuery -Path $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        # No Path supplied for the Route.
        throw ($PodeLocale.noPathSuppliedForRouteExceptionMessage)
    }

    # ensure the route has appropriate slashes
    $Path = Update-PodeRouteSlash -Path $Path -Static
    $OpenApiPath = ConvertTo-PodeOARoutePath -Path $Path
    $Path = Resolve-PodePlaceholder -Path $Path

    # get endpoints from name
    $endpoints = Find-PodeEndpoint -EndpointName $EndpointName

    # get default route IfExists state
    if ($IfExists -ieq 'Default') {
        $IfExists = Get-PodeRouteIfExistsPreference
    }

    # ensure the route doesn't already exist for each endpoint
    $endpoints = @(foreach ($_endpoint in $endpoints) {
            $found = Test-PodeRouteInternal -Method $Method -Path $Path -Protocol $_endpoint.Protocol -Address $_endpoint.Address -ThrowError:($IfExists -ieq 'Error')

            if ($found) {
                if ($IfExists -ieq 'Overwrite') {
                    Remove-PodeStaticRoute -Path $origPath -EndpointName $_endpoint.Name
                }

                if ($IfExists -ieq 'Skip') {
                    continue
                }
            }

            $_endpoint
        })

    if (($null -eq $endpoints) -or ($endpoints.Length -eq 0)) {
        return
    }

    # if static, ensure the path exists at server root
    $Source = Get-PodeRelativePath -Path $Source -JoinRoot
    if (!(Test-PodePath -Path $Source -NoStatus)) {
        # [Method)] Path: The Source path supplied for Static Route does not exist
        throw ($PodeLocale.sourcePathDoesNotExistForStaticRouteExceptionMessage -f $Path, $Source)
    }

    # setup a temp drive for the path
    $Source = New-PodePSDrive -Path $Source

    # setup default static files
    if ($null -eq $Defaults) {
        $Defaults = Get-PodeStaticRouteDefault
    }

    if (!$RedirectToDefault) {
        $RedirectToDefault = $PodeContext.Server.Web.Static.RedirectToDefault
    }

    # convert any middleware into valid hashtables
    $Middleware = @(ConvertTo-PodeMiddleware -Middleware $Middleware -PSSession $PSCmdlet.SessionState)

    # if an access name was supplied, setup access as middleware first to it's after auth middleware
    if (![string]::IsNullOrWhiteSpace($Access)) {
        if ([string]::IsNullOrWhiteSpace($Authentication)) {
            # Access requires Authentication to be supplied on Routes
            throw ($PodeLocale.accessRequiresAuthenticationOnRoutesExceptionMessage)
        }

        if (!(Test-PodeAccessExists -Name $Access)) {
            # Access method does not exist
            throw ($PodeLocale.accessMethodDoesNotExistExceptionMessage -f $Access)
        }

        $options = @{
            Name = $Access
        }

        $Middleware = (@(Get-PodeAccessMiddlewareScript | New-PodeMiddleware -ArgumentList $options) + $Middleware)
    }

    # if an auth name was supplied, setup the auth as the first middleware
    if (![string]::IsNullOrWhiteSpace($Authentication)) {
        if (!(Test-PodeAuthExists -Name $Authentication)) {
            # Authentication method does not exist
            throw ($PodeLocale.authenticationMethodDoesNotExistExceptionMessage)
        }

        # Validate that the HTTP method supports a request body when using bearer token authentication.
        # This ensures that only PUT, POST, and PATCH methods are used for body-based authentication.
        Test-PodeBodyAuthMethod -Method $Method -Authentication $Authentication

        $options = @{
            Name = $Authentication
            Anon = $AllowAnon.IsPresent
        }

        $Middleware = (@(Get-PodeAuthMiddlewareScript | New-PodeMiddleware -ArgumentList $options) + $Middleware)
    }

    # workout a default content type for the route
    $ContentType = Find-PodeRouteContentType -Path $Path -ContentType $ContentType

    # workout a default transfer encoding for the route
    $TransferEncoding = Find-PodeRouteTransferEncoding -Path $Path -TransferEncoding $TransferEncoding

    # add the route(s)
    Write-Verbose "Adding Route: [$($Method)] $($Path)"
    $newRoutes = @(foreach ($_endpoint in $endpoints) {
            @{
                Source            = $Source
                Path              = $Path
                Method            = $Method
                Defaults          = $Defaults
                RedirectToDefault = $RedirectToDefault.IsPresent
                Middleware        = $Middleware
                Authentication    = $Authentication
                Access            = $Access
                AccessMeta        = @{
                    Role   = $Role
                    Group  = $Group
                    Scope  = $Scope
                    User   = $User
                    Custom = $CustomAccess
                }
                Endpoint          = @{
                    Protocol = $_endpoint.Protocol
                    Address  = $_endpoint.Address.Trim()
                    Name     = $_endpoint.Name
                }
                ContentType       = $ContentType
                TransferEncoding  = $TransferEncoding
                ErrorType         = $ErrorContentType
                Download          = $DownloadOnly.IsPresent
                IsStatic          = $true
                FileBrowser       = $FileBrowser.IsPresent
                OpenApi           = @{
                    Path           = $OpenApiPath
                    Responses      = @{}
                    Parameters     = [ordered]@{}
                    RequestBody    = [ordered]@{}
                    CallBacks      = @{}
                    Authentication = @()
                    Servers        = @()
                    DefinitionTag  = $DefinitionTag
                }
                Metrics           = @{
                    Requests = @{
                        Total       = 0
                        StatusCodes = @{}
                    }
                }
                Cache             = @{
                    Enabled = $PodeContext.Server.Web.Static.Cache.Enabled
                    MaxAge  = $PodeContext.Server.Web.Static.Cache.MaxAge
                }
                Compression       = @{
                    Enabled   = $PodeContext.Server.Web.Compression.Enabled
                    Encodings = $PodeContext.Server.Web.Compression.Encodings
                    Request   = $false
                    Response  = $PodeContext.Server.Web.Compression.Enabled
                }
            }
        })

    $PodeContext.Server.Routes[$Method][$Path] += @($newRoutes)

    # return the routes?
    if ($PassThru) {
        return $newRoutes
    }
}

<#
.SYNOPSIS
Adds a Signal Route for WebSockets.

.DESCRIPTION
Adds a Signal Route, with path, that when called with invoke any logic.

.PARAMETER Path
The URI path for the Signal Route.

.PARAMETER ScriptBlock
A ScriptBlock for the Signal Route's main logic.

.PARAMETER EndpointName
The EndpointName of an Endpoint(s) this Signal Route should be bound against.

.PARAMETER FilePath
A literal, or relative, path to a file containing a ScriptBlock for the Signal Route's main logic.

.PARAMETER ArgumentList
An array of arguments to supply to the Signal Route's ScriptBlock.

.PARAMETER IfExists
Specifies what action to take when a Signal Route already exists. (Default: Default)

.EXAMPLE
Add-PodeSignalRoute -Path '/message' -ScriptBlock { /* logic */ }

.EXAMPLE
Add-PodeSignalRoute -Path '/message' -ScriptBlock { /* logic */ } -ArgumentList 'arg1', 'arg2'
#>
function Add-PodeSignalRoute {
    [CmdletBinding(DefaultParameterSetName = 'Script')]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter(ParameterSetName = 'Script')]
        [scriptblock]
        $ScriptBlock,

        [Parameter()]
        [string[]]
        $EndpointName,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $FilePath,

        [Parameter()]
        [object[]]
        $ArgumentList,

        [Parameter()]
        [ValidateSet('Default', 'Error', 'Overwrite', 'Skip')]
        [string]
        $IfExists = 'Default'
    )

    # check if we have any route group info defined
    if ($null -ne $RouteGroup) {
        if (![string]::IsNullOrWhiteSpace($RouteGroup.Path)) {
            $Path = "$($RouteGroup.Path)$($Path)"
        }

        if ([string]::IsNullOrWhiteSpace($EndpointName)) {
            $EndpointName = $RouteGroup.EndpointName
        }

        if ($RouteGroup.IfExists -ine 'default') {
            $IfExists = $RouteGroup.IfExists
        }
    }

    $Method = 'Signal'

    # store the original path
    $origPath = $Path

    # ensure the route has appropriate slashes
    $Path = Update-PodeRouteSlash -Path $Path

    # get endpoints from name
    $endpoints = Find-PodeEndpoint -EndpointName $EndpointName

    # get default route IfExists state
    if ($IfExists -ieq 'Default') {
        $IfExists = Get-PodeRouteIfExistsPreference
    }

    # ensure the route doesn't already exist for each endpoint
    $endpoints = @(foreach ($_endpoint in $endpoints) {
            $found = Test-PodeRouteInternal -Method $Method -Path $Path -Protocol $_endpoint.Protocol -Address $_endpoint.Address -ThrowError:($IfExists -ieq 'Error')

            if ($found) {
                if ($IfExists -ieq 'Overwrite') {
                    Remove-PodeSignalRoute -Path $origPath -EndpointName $_endpoint.Name
                }

                if ($IfExists -ieq 'Skip') {
                    continue
                }
            }

            $_endpoint
        })

    if (($null -eq $endpoints) -or ($endpoints.Length -eq 0)) {
        return
    }

    # if scriptblock and file path are all null/empty, error
    if ((Test-PodeIsEmpty $ScriptBlock) -and (Test-PodeIsEmpty $FilePath)) {
        # [Method] Path: No logic passed
        throw ($PodeLocale.noLogicPassedForMethodRouteExceptionMessage -f $Method, $Path)
    }

    # if we have a file path supplied, load that path as a scriptblock
    if ($PSCmdlet.ParameterSetName -ieq 'file') {
        $ScriptBlock = Convert-PodeFileToScriptBlock -FilePath $FilePath
    }

    # check for scoped vars
    $ScriptBlock, $usingVars = Convert-PodeScopedVariables -ScriptBlock $ScriptBlock -PSSession $PSCmdlet.SessionState

    # add the route(s)
    Write-Verbose "Adding Route: [$($Method)] $($Path)"
    $newRoutes = @(foreach ($_endpoint in $endpoints) {
            @{
                Logic          = $ScriptBlock
                UsingVariables = $usingVars
                Endpoint       = @{
                    Protocol = $_endpoint.Protocol
                    Address  = $_endpoint.Address.Trim()
                    Name     = $_endpoint.Name
                }
                Arguments      = $ArgumentList
                Method         = $Method
                Path           = $Path
                IsStatic       = $false
                Metrics        = @{
                    Requests = @{
                        Total = 0
                    }
                }
            }
        })

    $PodeContext.Server.Routes[$Method][$Path] += @($newRoutes)
}

<#
.SYNOPSIS
Adds a Route Group for organizing and sharing configuration across multiple routes.

.DESCRIPTION
Adds a Route Group, enabling multiple routes to share common values such as base path, middleware, authentication, and other configuration.
You can define the group's routes inline via a ScriptBlock using `-Routes`, or load them from an external `.ps1` file using `-FilePath`.

.PARAMETER Path
The URI path to use as a base for the Routes, which is prepended to all routes in the group.

.PARAMETER Routes
A ScriptBlock for adding routes within the group. All routes defined here will inherit the group's shared configuration.

.PARAMETER FilePath
A literal or relative path to a `.ps1` file that contains route definitions. The file will be executed in the context of the group,
and all routes defined within will inherit the group's shared configuration. Cannot be used together with `-Routes`.

.PARAMETER Middleware
An array of ScriptBlocks for middleware to be applied to each route in the group.

.PARAMETER EndpointName
The EndpointName(s) to use for the routes in the group.

.PARAMETER ContentType
The default content type to use for the group's routes when parsing payloads.

.PARAMETER TransferEncoding
The transfer encoding to use for the group's routes, when parsing payloads.

.PARAMETER ErrorContentType
The content type of any error pages returned by the group's routes.

.PARAMETER Authentication
The name of an authentication method to require on the group's routes.

.PARAMETER Access
The name of an access method to require on the group's routes.

.PARAMETER IfExists
Specifies what action to take if a route already exists. (Default: Default)

.PARAMETER Role
One or more optional roles that will be authorized to access these routes (when using authentication and access).

.PARAMETER Group
One or more optional groups that will be authorized to access these routes (when using authentication and access).

.PARAMETER Scope
One or more optional scopes that will be authorized to access these routes (when using authentication and access).

.PARAMETER User
One or more optional users that will be authorized to access these routes (when using authentication and access).

.PARAMETER AllowAnon
If supplied, allows anonymous (non-authenticated) access to the group's routes.

.PARAMETER OADefinitionTag
An array of strings representing unique tags for the OpenAPI specification.
Helps distinguish between different versions or types of API specifications within the application.

.EXAMPLE
Add-PodeRouteGroup -Path '/api' -Routes {
    Add-PodeRoute -Method Get -Path '/one' -ScriptBlock { Write-PodeJsonResponse -Value @{ Msg = "One" } }
    Add-PodeRoute -Method Get -Path '/two' -ScriptBlock { Write-PodeJsonResponse -Value @{ Msg = "Two" } }
}

This creates two routes `/api/one` and `/api/two` sharing the `/api` path.

.EXAMPLE
Add-PodeRouteGroup -Path '/api' -FilePath './routes/api-routes.ps1'

This loads route definitions from the external file `api-routes.ps1` and applies the group settings to them.
#>
function Add-PodeRouteGroup {
    [CmdletBinding(DefaultParameterSetName = 'Routes')]
    param(
        [Parameter()]
        [string]
        $Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'Routes')]
        [scriptblock]
        $Routes,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $FilePath,

        [Parameter()]
        [object[]]
        $Middleware,

        [Parameter()]
        [string[]]
        $EndpointName,

        [Parameter()]
        [string]
        $ContentType,

        [Parameter()]
        [ValidateSet('', 'brotli', 'gzip', 'deflate')]
        [string]
        $TransferEncoding,

        [Parameter()]
        [string]
        $ErrorContentType,

        [Parameter()]
        [Alias('Auth')]
        [string]
        $Authentication,

        [Parameter()]
        [string]
        $Access,

        [Parameter()]
        [ValidateSet('Default', 'Error', 'Overwrite', 'Skip')]
        [string]
        $IfExists = 'Default',

        [Parameter()]
        [string[]]
        $Role,

        [Parameter()]
        [string[]]
        $Group,

        [Parameter()]
        [string[]]
        $Scope,

        [Parameter()]
        [string[]]
        $User,

        [switch]
        $AllowAnon,

        [string[]]
        $OADefinitionTag
    )

    if ($PSCmdlet.ParameterSetName -ieq 'File') {
        $Routes = Convert-PodeFileToScriptBlock -FilePath $FilePath
    }

    if (Test-PodeIsEmpty $Routes) {
        # The Route parameter needs a valid, not empty, scriptblock
        throw ($PodeLocale.routeParameterNeedsValidScriptblockExceptionMessage)
    }

    if ($Path -eq '/') {
        $Path = $null
    }

    # check for scoped vars
    $Routes, $usingVars = Convert-PodeScopedVariables -ScriptBlock $Routes -PSSession $PSCmdlet.SessionState

    # group details
    if ($null -ne $RouteGroup) {
        if (![string]::IsNullOrWhiteSpace($RouteGroup.Path)) {
            $Path = "$($RouteGroup.Path)$($Path)"
        }

        if ($null -ne $RouteGroup.Middleware) {
            $Middleware = $RouteGroup.Middleware + $Middleware
        }

        if ([string]::IsNullOrWhiteSpace($EndpointName)) {
            $EndpointName = $RouteGroup.EndpointName
        }

        if ([string]::IsNullOrWhiteSpace($ContentType)) {
            $ContentType = $RouteGroup.ContentType
        }

        if ([string]::IsNullOrWhiteSpace($TransferEncoding)) {
            $TransferEncoding = $RouteGroup.TransferEncoding
        }

        if ([string]::IsNullOrWhiteSpace($ErrorContentType)) {
            $ErrorContentType = $RouteGroup.ErrorContentType
        }

        if ([string]::IsNullOrWhiteSpace($Authentication)) {
            $Authentication = $RouteGroup.Authentication
        }

        if ([string]::IsNullOrWhiteSpace($Access)) {
            $Access = $RouteGroup.Access
        }

        if ($RouteGroup.AllowAnon) {
            $AllowAnon = $RouteGroup.AllowAnon
        }

        if ($RouteGroup.IfExists -ine 'default') {
            $IfExists = $RouteGroup.IfExists
        }

        if ($null -ne $RouteGroup.AccessMeta.Role) {
            $Role = $RouteGroup.AccessMeta.Role + $Role
        }

        if ($null -ne $RouteGroup.AccessMeta.Group) {
            $Group = $RouteGroup.AccessMeta.Group + $Group
        }

        if ($null -ne $RouteGroup.AccessMeta.Scope) {
            $Scope = $RouteGroup.AccessMeta.Scope + $Scope
        }

        if ($null -ne $RouteGroup.AccessMeta.User) {
            $User = $RouteGroup.AccessMeta.User + $User
        }

        if ($null -ne $RouteGroup.AccessMeta.Custom) {
            $CustomAccess = $RouteGroup.AccessMeta.Custom
        }

        if ($null -ne $RouteGroup.OADefinitionTag ) {
            $OADefinitionTag = $RouteGroup.OADefinitionTag
        }

    }

    $RouteGroup = @{
        Path             = $Path
        Middleware       = $Middleware
        EndpointName     = $EndpointName
        ContentType      = $ContentType
        TransferEncoding = $TransferEncoding
        ErrorContentType = $ErrorContentType
        Authentication   = $Authentication
        Access           = $Access
        AllowAnon        = $AllowAnon
        IfExists         = $IfExists
        OADefinitionTag  = $OADefinitionTag
        AccessMeta       = @{
            Role   = $Role
            Group  = $Group
            Scope  = $Scope
            User   = $User
            Custom = $CustomAccess
        }
    }

    # add routes
    $null = Invoke-PodeScriptBlock -ScriptBlock $Routes -UsingVariables $usingVars -Splat -NoNewClosure
}

<#
.SYNOPSIS
Adds a Static Route Group for organizing and sharing configuration across multiple static routes.

.DESCRIPTION
Adds a Static Route Group, enabling multiple static routes to share common values such as base path, static source, middleware, authentication, and other configuration.
You can define the group's static routes inline via a ScriptBlock using `-Routes`, or load them from an external `.ps1` file using `-FilePath`.

.PARAMETER Path
The URI path to use as a base for the static routes, which is prepended to all routes in the group.

.PARAMETER Source
A literal or relative base path to the directory that contains the static content to be served.

.PARAMETER Routes
A ScriptBlock for adding static routes within the group. All routes defined here will inherit the group's shared configuration.

.PARAMETER FilePath
A literal or relative path to a `.ps1` file that contains static route definitions. The file will be executed in the context of the group,
and all static routes defined within will inherit the group's shared configuration. Cannot be used together with `-Routes`.

.PARAMETER Middleware
An array of ScriptBlocks for middleware to be applied to each static route in the group.

.PARAMETER EndpointName
The EndpointName(s) to use for the static routes in the group.

.PARAMETER ContentType
The default content type to use for the group's static routes when serving files.

.PARAMETER TransferEncoding
The transfer encoding to use for the group's static routes.

.PARAMETER Defaults
An array of default pages to display (such as 'index.html') for each static route.

.PARAMETER ErrorContentType
The content type of any error pages returned by the group's static routes.

.PARAMETER Authentication
The name of an authentication method to require on the group's static routes.

.PARAMETER Access
The name of an access method to require on the group's static routes.

.PARAMETER IfExists
Specifies what action to take if a static route already exists. (Default: Default)

.PARAMETER AllowAnon
If supplied, allows anonymous (non-authenticated) access to the group's static routes.

.PARAMETER FileBrowser
If supplied, and the path is a folder, returns a browsable listing of the directory instead of 404.

.PARAMETER DownloadOnly
If supplied, all static content on the routes will be sent as file downloads rather than rendered.

.PARAMETER Role
One or more optional roles that will be authorized to access these routes (when using authentication and access).

.PARAMETER Group
One or more optional groups that will be authorized to access these routes (when using authentication and access).

.PARAMETER Scope
One or more optional scopes that will be authorized to access these routes (when using authentication and access).

.PARAMETER User
One or more optional users that will be authorized to access these routes (when using authentication and access).

.PARAMETER RedirectToDefault
If supplied, users will be redirected to the default page if found instead of rendering the folder path.

.EXAMPLE
Add-PodeStaticRouteGroup -Path '/static' -Routes {
    Add-PodeStaticRoute -Path '/images' -Source '/images'
    Add-PodeStaticRoute -Path '/docs' -Source '/docs'
}

This creates two static routes at `/static/images` and `/static/docs`, serving files from the corresponding subdirectories.

.EXAMPLE
Add-PodeStaticRouteGroup -Path '/static' -Source './content/static' -FilePath './routes/static-routes.ps1'

This loads static route definitions from `static-routes.ps1` and applies the group settings to them.

.NOTES
- Either `-Routes` or `-FilePath` **must** be supplied, but not both.
- Static routes defined via `-FilePath` are executed in the context of the route group and inherit all shared configuration.
#>
function Add-PodeStaticRouteGroup {
    [CmdletBinding(DefaultParameterSetName = 'Routes')]
    param(
        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Source,

        [Parameter(Mandatory = $true, ParameterSetName = 'Routes')]
        [scriptblock]
        $Routes,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $FilePath,

        [Parameter()]
        [object[]]
        $Middleware,

        [Parameter()]
        [string[]]
        $EndpointName,

        [Parameter()]
        [string]
        $ContentType,

        [Parameter()]
        [ValidateSet('', 'brotli', 'gzip', 'deflate')]
        [string]
        $TransferEncoding,

        [Parameter()]
        [string[]]
        $Defaults,

        [Parameter()]
        [string]
        $ErrorContentType,

        [Parameter()]
        [Alias('Auth')]
        [string]
        $Authentication,

        [Parameter()]
        [string]
        $Access,

        [Parameter()]
        [ValidateSet('Default', 'Error', 'Overwrite', 'Skip')]
        [string]
        $IfExists = 'Default',

        [Parameter()]
        [string[]]
        $Role,

        [Parameter()]
        [string[]]
        $Group,

        [Parameter()]
        [string[]]
        $Scope,

        [Parameter()]
        [string[]]
        $User,

        [switch]
        $AllowAnon,

        [switch]
        $FileBrowser,

        [switch]
        $DownloadOnly,

        [switch]
        $RedirectToDefault
    )
    if ($PSCmdlet.ParameterSetName -ieq 'File') {
        $Routes = Convert-PodeFileToScriptBlock -FilePath $FilePath
    }

    if (Test-PodeIsEmpty $Routes) {
        # The Route parameter needs a valid, not empty, scriptblock
        throw ($PodeLocale.routeParameterNeedsValidScriptblockExceptionMessage)
    }

    if ($Path -eq '/') {
        $Path = $null
    }

    # check for scoped vars
    $Routes, $usingVars = Convert-PodeScopedVariables -ScriptBlock $Routes -PSSession $PSCmdlet.SessionState

    # group details
    if ($null -ne $RouteGroup) {
        if (![string]::IsNullOrWhiteSpace($RouteGroup.Path)) {
            $Path = "$($RouteGroup.Path)$($Path)"
        }

        if (![string]::IsNullOrWhiteSpace($RouteGroup.Source)) {
            $Source = [System.IO.Path]::Combine($Source, $RouteGroup.Source.TrimStart('\/'))
        }

        if ($null -ne $RouteGroup.Middleware) {
            $Middleware = $RouteGroup.Middleware + $Middleware
        }

        if ([string]::IsNullOrWhiteSpace($EndpointName)) {
            $EndpointName = $RouteGroup.EndpointName
        }

        if ([string]::IsNullOrWhiteSpace($ContentType)) {
            $ContentType = $RouteGroup.ContentType
        }

        if ([string]::IsNullOrWhiteSpace($TransferEncoding)) {
            $TransferEncoding = $RouteGroup.TransferEncoding
        }

        if ([string]::IsNullOrWhiteSpace($ErrorContentType)) {
            $ErrorContentType = $RouteGroup.ErrorContentType
        }

        if ([string]::IsNullOrWhiteSpace($Authentication)) {
            $Authentication = $RouteGroup.Authentication
        }

        if ([string]::IsNullOrWhiteSpace($Access)) {
            $Access = $RouteGroup.Access
        }

        if (Test-PodeIsEmpty $Defaults) {
            $Defaults = $RouteGroup.Defaults
        }

        if ($RouteGroup.AllowAnon) {
            $AllowAnon = $RouteGroup.AllowAnon
        }

        if ($RouteGroup.DownloadOnly) {
            $DownloadOnly = $RouteGroup.DownloadOnly
        }

        if ($RouteGroup.FileBrowser) {
            $FileBrowser = $RouteGroup.FileBrowser
        }

        if ($RouteGroup.RedirectToDefault) {
            $RedirectToDefault = $RouteGroup.RedirectToDefault
        }

        if ($RouteGroup.IfExists -ine 'default') {
            $IfExists = $RouteGroup.IfExists
        }

        if ($null -ne $RouteGroup.AccessMeta.Role) {
            $Role = $RouteGroup.AccessMeta.Role + $Role
        }

        if ($null -ne $RouteGroup.AccessMeta.Group) {
            $Group = $RouteGroup.AccessMeta.Group + $Group
        }

        if ($null -ne $RouteGroup.AccessMeta.Scope) {
            $Scope = $RouteGroup.AccessMeta.Scope + $Scope
        }

        if ($null -ne $RouteGroup.AccessMeta.User) {
            $User = $RouteGroup.AccessMeta.User + $User
        }

        if ($null -ne $RouteGroup.AccessMeta.Custom) {
            $CustomAccess = $RouteGroup.AccessMeta.Custom
        }
    }

    $RouteGroup = @{
        Path              = $Path
        Source            = $Source
        Middleware        = $Middleware
        EndpointName      = $EndpointName
        ContentType       = $ContentType
        TransferEncoding  = $TransferEncoding
        Defaults          = $Defaults
        RedirectToDefault = $RedirectToDefault
        ErrorContentType  = $ErrorContentType
        Authentication    = $Authentication
        Access            = $Access
        AllowAnon         = $AllowAnon
        DownloadOnly      = $DownloadOnly
        FileBrowser       = $FileBrowser
        IfExists          = $IfExists
        AccessMeta        = @{
            Role   = $Role
            Group  = $Group
            Scope  = $Scope
            User   = $User
            Custom = $CustomAccess
        }
    }

    # add routes
    $null = Invoke-PodeScriptBlock -ScriptBlock $Routes -UsingVariables $usingVars -Splat -NoNewClosure
}

<#
.SYNOPSIS
Adds a Signal Route Group for organizing and sharing configuration across multiple WebSocket (Signal) routes.

.DESCRIPTION
Adds a Signal Route Group, enabling multiple Signal (WebSocket) routes to share common values such as base path and endpoint configuration.
You can define the group's signal routes inline via a ScriptBlock using `-Routes`, or load them from an external `.ps1` file using `-FilePath`.

.PARAMETER Path
The URI path to use as a base for the Signal routes, which is prepended to all signal routes in the group.

.PARAMETER Routes
A ScriptBlock for adding signal routes within the group. All routes defined here will inherit the group's shared configuration.

.PARAMETER FilePath
A literal or relative path to a `.ps1` file that contains signal route definitions. The file will be executed in the context of the group,
and all signal routes defined within will inherit the group's shared configuration. Cannot be used together with `-Routes`.

.PARAMETER EndpointName
The EndpointName(s) to use for the signal routes in the group.

.PARAMETER IfExists
Specifies what action to take if a signal route already exists. (Default: Default)

.EXAMPLE
Add-PodeSignalRouteGroup -Path '/signals' -Routes {
    Add-PodeSignalRoute -Path '/chat' -ScriptBlock { Send-PodeSignal -Value "hello" }
    Add-PodeSignalRoute -Path '/broadcast' -ScriptBlock { Send-PodeSignal -Value "world" }
}

This creates two signal routes at `/signals/chat` and `/signals/broadcast` that share the `/signals` path.

.EXAMPLE
Add-PodeSignalRouteGroup -Path '/api' -FilePath './routes/signals.ps1'

This loads signal route definitions from `signals.ps1` and applies the group settings to them.

.NOTES
- Either `-Routes` or `-FilePath` **must** be supplied, but not both.
- Signal routes defined via `-FilePath` are executed in the context of the route group and inherit all shared configuration.
#>

function Add-PodeSignalRouteGroup {
    [CmdletBinding(DefaultParameterSetName = 'Routes')]
    param(
        [Parameter()]
        [string]
        $Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'Routes' )]
        [scriptblock]
        $Routes,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $FilePath,

        [Parameter()]
        [string[]]
        $EndpointName,

        [Parameter()]
        [ValidateSet('Default', 'Error', 'Overwrite', 'Skip')]
        [string]
        $IfExists = 'Default'
    )
    if ($PSCmdlet.ParameterSetName -ieq 'File') {
        $Routes = Convert-PodeFileToScriptBlock -FilePath $FilePath
    }

    if (Test-PodeIsEmpty $Routes) {
        # The Route parameter needs a valid, not empty, scriptblock
        throw ($PodeLocale.routeParameterNeedsValidScriptblockExceptionMessage)
    }

    if ($Path -eq '/') {
        $Path = $null
    }

    # check for scoped vars
    $Routes, $usingVars = Convert-PodeScopedVariables -ScriptBlock $Routes -PSSession $PSCmdlet.SessionState

    # group details
    if ($null -ne $RouteGroup) {
        if (![string]::IsNullOrWhiteSpace($RouteGroup.Path)) {
            $Path = "$($RouteGroup.Path)$($Path)"
        }

        if ([string]::IsNullOrWhiteSpace($EndpointName)) {
            $EndpointName = $RouteGroup.EndpointName
        }

        if ($RouteGroup.IfExists -ine 'default') {
            $IfExists = $RouteGroup.IfExists
        }
    }

    $RouteGroup = @{
        Path         = $Path
        EndpointName = $EndpointName
        IfExists     = $IfExists
    }

    # add routes
    $null = Invoke-PodeScriptBlock -ScriptBlock $Routes -UsingVariables $usingVars -Splat -NoNewClosure
}


<#
.SYNOPSIS
Remove a specific Route.

.DESCRIPTION
Remove a specific Route.

.PARAMETER Method
The method of the Route to remove.

.PARAMETER Path
The path of the Route to remove.

.PARAMETER EndpointName
The EndpointName of an Endpoint(s) bound to the Route to be removed.

.EXAMPLE
Remove-PodeRoute -Method Get -Route '/about'

.EXAMPLE
Remove-PodeRoute -Method Post -Route '/users/:userId' -EndpointName User
#>
function Remove-PodeRoute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Connect', 'Delete', 'Get', 'Head', 'Merge', 'Options', 'Patch', 'Post', 'Put', 'Trace', '*')]
        [string]
        $Method,

        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $EndpointName
    )

    # split route on '?' for query
    $Path = Split-PodeRouteQuery -Path $Path

    # ensure the route has appropriate slashes and replace parameters
    $Path = Update-PodeRouteSlash -Path $Path
    $Path = Resolve-PodePlaceholder -Path $Path

    # ensure route does exist
    if (!$PodeContext.Server.Routes[$Method].Contains($Path)) {
        return
    }

    # select the candidate route for deletion
    $route = @($PodeContext.Server.Routes[$Method][$Path] | Where-Object {
            $_.Endpoint.Name -ieq $EndpointName
        })

    foreach ($r in $route) {
        # remove the operationId from the openapi operationId list
        if ($r.OpenAPI) {
            foreach ( $tag in $r.OpenAPI.DefinitionTag) {
                if ($tag -and ($PodeContext.Server.OpenAPI.Definitions[$tag].hiddenComponents.operationId -ccontains $route.OpenAPI.OperationId)) {
                    $PodeContext.Server.OpenAPI.Definitions[$tag].hiddenComponents.operationId = $PodeContext.Server.OpenAPI.Definitions[$tag].hiddenComponents.operationId | Where-Object { $_ -ne $route.OpenAPI.OperationId }
                }
            }
        }
        # remove the runspace
        if ($r.IsAsync) {
            $asyncRouteId = $r.Async.AsyncRouteId
            if ( $asyncRouteId -and $PodeContext.RunspacePools.ContainsKey($asyncRouteId)) {
                $PodeContext.Threads.AsyncRoutes -= $r.Async.MaxRunspaces
                if ( ! $PodeContext.RunspacePools[$asyncRouteId].Pool.IsDisposed) {
                    $PodeContext.RunspacePools[$asyncRouteId].Pool.BeginClose($null, $null)
                    Close-PodeDisposable -Disposable ($PodeContext.RunspacePools[$asyncRouteId].Pool)
                }
                $v = ''
                $null = $PodeContext.RunspacePools.TryRemove($asyncRouteId, [ref]$v)
            }
        }
    }

    # remove the route's logic
    $PodeContext.Server.Routes[$Method][$Path] = @($PodeContext.Server.Routes[$Method][$Path] | Where-Object {
            $_.Endpoint.Name -ine $EndpointName
        })

    # if the route has no more logic, just remove it
    if ((Get-PodeCount $PodeContext.Server.Routes[$Method][$Path]) -eq 0) {
        $null = $PodeContext.Server.Routes[$Method].Remove($Path)
    }
}

<#
.SYNOPSIS
Remove a specific static Route.

.DESCRIPTION
Remove a specific static Route.

.PARAMETER Path
The path of the static Route to remove.

.PARAMETER EndpointName
The EndpointName of an Endpoint(s) bound to the static Route to be removed.

.EXAMPLE
Remove-PodeStaticRoute -Path '/assets'
#>
function Remove-PodeStaticRoute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $EndpointName
    )

    $Method = 'Static'

    # ensure the route has appropriate slashes and replace parameters
    $Path = Update-PodeRouteSlash -Path $Path -Static

    # ensure route does exist
    if (!$PodeContext.Server.Routes[$Method].Contains($Path)) {
        return
    }

    # remove the route's logic
    $PodeContext.Server.Routes[$Method][$Path] = @($PodeContext.Server.Routes[$Method][$Path] | Where-Object {
            $_.Endpoint.Name -ine $EndpointName
        })

    # if the route has no more logic, just remove it
    if ((Get-PodeCount $PodeContext.Server.Routes[$Method][$Path]) -eq 0) {
        $null = $PodeContext.Server.Routes[$Method].Remove($Path)
    }
}

<#
.SYNOPSIS
Remove a specific Signal Route.

.DESCRIPTION
Remove a specific Signal Route.

.PARAMETER Path
The path of the Signal Route to remove.

.PARAMETER EndpointName
The EndpointName of an Endpoint(s) bound to the Signal Route to be removed.

.EXAMPLE
Remove-PodeSignalRoute -Route '/message'
#>
function Remove-PodeSignalRoute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $EndpointName
    )

    $Method = 'Signal'

    # ensure the route has appropriate slashes and replace parameters
    $Path = Update-PodeRouteSlash -Path $Path

    # ensure route does exist
    if (!$PodeContext.Server.Routes[$Method].Contains($Path)) {
        return
    }

    # remove the route's logic
    $PodeContext.Server.Routes[$Method][$Path] = @($PodeContext.Server.Routes[$Method][$Path] | Where-Object {
            $_.Endpoint.Name -ine $EndpointName
        })

    # if the route has no more logic, just remove it
    if ((Get-PodeCount $PodeContext.Server.Routes[$Method][$Path]) -eq 0) {
        $null = $PodeContext.Server.Routes[$Method].Remove($Path)
    }
}

<#
.SYNOPSIS
Removes all added Routes, or Routes for a specific Method.

.DESCRIPTION
Removes all added Routes, or Routes for a specific Method.

.PARAMETER Method
The Method to from which to remove all Routes.

.EXAMPLE
Clear-PodeRoutes

.EXAMPLE
Clear-PodeRoutes -Method Get
#>
function Clear-PodeRoutes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('', 'Connect', 'Delete', 'Get', 'Head', 'Merge', 'Options', 'Patch', 'Post', 'Put', 'Trace', '*')]
        [string]
        $Method
    )

    if (![string]::IsNullOrWhiteSpace($Method)) {
        $PodeContext.Server.Routes[$Method].Clear()
    }
    else {
        $PodeContext.Server.Routes.Keys.Clone() | ForEach-Object {
            $PodeContext.Server.Routes[$_].Clear()
        }
    }
}

<#
.SYNOPSIS
Removes all added static Routes.

.DESCRIPTION
Removes all added static Routes.

.EXAMPLE
Clear-PodeStaticRoutes
#>
function Clear-PodeStaticRoutes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param()

    $PodeContext.Server.Routes['Static'].Clear()
}

<#
.SYNOPSIS
Removes all added Signal Routes.

.DESCRIPTION
Removes all added Signal Routes.

.EXAMPLE
Clear-PodeSignalRoutes
#>
function Clear-PodeSignalRoutes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param()

    $PodeContext.Server.Routes['Signal'].Clear()
}

<#
.SYNOPSIS
Takes an array of Commands, or a Module, and converts them into Routes.

.DESCRIPTION
Takes an array of Commands (Functions/Aliases), or a Module, and generates appropriate Routes for the commands.

.PARAMETER Commands
An array of Commands to convert - if a Module is supplied, these Commands must be present within that Module.

.PARAMETER Module
A Module whose exported commands will be converted.

.PARAMETER Method
An override HTTP method to use when generating the Routes. If not supplied, Pode will make a best guess based on the Command's Verb.

.PARAMETER Path
An optional Path for the Route, to prepend before the Command Name and Module.

.PARAMETER Middleware
Like normal Routes, an array of Middleware that will be applied to all generated Routes.

.PARAMETER Authentication
The name of an Authentication method which should be used as middleware on this Route.

.PARAMETER Access
The name of an Access method which should be used as middleware on this Route.

.PARAMETER AllowAnon
If supplied, the Route will allow anonymous access for non-authenticated users.

.PARAMETER NoVerb
If supplied, the Command's Verb will not be included in the Route's path.

.PARAMETER NoOpenApi
If supplied, no OpenAPI definitions will be generated for the routes created.

.PARAMETER Role
One or more optional Roles that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER Group
One or more optional Groups that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER Scope
One or more optional Scopes that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER User
One or more optional Users that will be authorised to access this Route, when using Authentication with an Access method.

.EXAMPLE
ConvertTo-PodeRoute -Commands @('Get-ChildItem', 'Get-Host', 'Invoke-Expression') -Middleware { ... }

.EXAMPLE
ConvertTo-PodeRoute -Commands @('Get-ChildItem', 'Get-Host', 'Invoke-Expression') -Authentication AuthName

.EXAMPLE
ConvertTo-PodeRoute -Module Pester -Path '/api'

.EXAMPLE
ConvertTo-PodeRoute -Commands @('Invoke-Pester') -Module Pester
#>
function ConvertTo-PodeRoute {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0 )]
        [string[]]
        $Commands,

        [Parameter()]
        [string]
        $Module,

        [Parameter()]
        [ValidateSet('', 'Connect', 'Delete', 'Get', 'Head', 'Merge', 'Options', 'Patch', 'Post', 'Put', 'Trace')]
        [string]
        $Method,

        [Parameter()]
        [string]
        $Path = '/',

        [Parameter()]
        [object[]]
        $Middleware,

        [Parameter()]
        [Alias('Auth')]
        [string]
        $Authentication,

        [Parameter()]
        [string]
        $Access,

        [Parameter()]
        [string[]]
        $Role,

        [Parameter()]
        [string[]]
        $Group,

        [Parameter()]
        [string[]]
        $Scope,

        [Parameter()]
        [string[]]
        $User,

        [switch]
        $AllowAnon,

        [switch]
        $NoVerb,

        [switch]
        $NoOpenApi
    )
    begin {
        # Initialize an array to hold piped-in values
        $pipelineValue = @()
    }

    process {
        # Add the current piped-in value to the array
        $pipelineValue += $_
    }

    end {
        # Set InputObject to the array of values
        if ($pipelineValue.Count -gt 1) {
            $Commands = $pipelineValue
        }

        # if a module was supplied, import it - then validate the commands
        if (![string]::IsNullOrWhiteSpace($Module)) {
            Import-PodeModule -Name $Module

            Write-Verbose 'Getting exported commands from module'
            $ModuleCommands = (Get-Module -Name $Module | Sort-Object -Descending | Select-Object -First 1).ExportedCommands.Keys

            # if commands were supplied validate them - otherwise use all exported ones
            if (Test-PodeIsEmpty $Commands) {
                Write-Verbose "Using all commands in $($Module) for converting to routes"
                $Commands = $ModuleCommands
            }
            else {
                Write-Verbose "Validating supplied commands against module's exported commands"
                foreach ($cmd in $Commands) {
                    if ($ModuleCommands -inotcontains $cmd) {
                        # Module Module does not contain function cmd to convert to a Route
                        throw ($PodeLocale.moduleDoesNotContainFunctionExceptionMessage -f $Module, $cmd)
                    }
                }
            }
        }

        # if there are no commands, fail
        if (Test-PodeIsEmpty $Commands) {
            # No commands supplied to convert to Routes
            throw ($PodeLocale.noCommandsSuppliedToConvertToRoutesExceptionMessage)
        }

        # trim end trailing slashes from the path
        $Path = Protect-PodeValue -Value $Path -Default '/'
        $Path = $Path.TrimEnd('/')

        # create the routes for each of the commands
        foreach ($cmd in $Commands) {
            # get module verb/noun and comvert verb to HTTP method
            $split = ($cmd -split '\-')

            if ($split.Length -ge 2) {
                $verb = $split[0]
                $noun = $split[1..($split.Length - 1)] -join ([string]::Empty)
            }
            else {
                $verb = [string]::Empty
                $noun = $split[0]
            }

            # determine the http method, or use the one passed
            $_method = $Method
            if ([string]::IsNullOrWhiteSpace($_method)) {
                $_method = Convert-PodeFunctionVerbToHttpMethod -Verb $verb
            }

            # use the full function name, or remove the verb
            $name = $cmd
            if ($NoVerb) {
                $name = $noun
            }

            # build the route's path
            $_path = ("$($Path)/$($Module)/$($name)" -replace '[/]+', '/')

            # create the route
            $params = @{
                Method         = $_method
                Path           = $_path
                Middleware     = $Middleware
                Authentication = $Authentication
                Access         = $Access
                Role           = $Role
                Group          = $Group
                Scope          = $Scope
                User           = $User
                AllowAnon      = $AllowAnon
                ArgumentList   = $cmd
                PassThru       = $true
            }

            $route = Add-PodeRoute @params -ScriptBlock {
                param($cmd)

                # either get params from the QueryString or Payload
                if ($WebEvent.Method -ieq 'get') {
                    $parameters = $WebEvent.Query
                }
                else {
                    $parameters = $WebEvent.Data
                }

                # invoke the function
                $result = (. $cmd @parameters)

                # if we have a result, convert it to json
                if (!(Test-PodeIsEmpty $result)) {
                    Write-PodeJsonResponse -Value $result -Depth 1
                }
            }

            # set the openapi metadata of the function, unless told to skip
            if ($NoOpenApi) {
                continue
            }

            $help = Get-Help -Name $cmd
            $route = ($route | Set-PodeOARouteInfo -Summary $help.Synopsis -Tags $Module -PassThru)

            # set the routes parameters (get = query, everything else = payload)
            $params = (Get-Command -Name $cmd).Parameters
            if (($null -eq $params) -or ($params.Count -eq 0)) {
                continue
            }

            $props = @(foreach ($key in $params.Keys) {
                    $params[$key] | ConvertTo-PodeOAPropertyFromCmdletParameter
                })

            if ($_method -ieq 'get') {
                $route | Set-PodeOARequest -Parameters @(foreach ($prop in $props) { $prop | ConvertTo-PodeOAParameter -In Query })
            }

            else {
                $route | Set-PodeOARequest -RequestBody (
                    New-PodeOARequestBody -ContentSchemas @{ 'application/json' = (New-PodeOAObjectProperty -Array -Properties $props) }
                )
            }
        }
    }
}

<#
.SYNOPSIS
Helper function to generate simple GET routes.

.DESCRIPTION
Helper function to generate simple GET routes from ScritpBlocks, Files, and Views.
The output is always rendered as HTML.

.PARAMETER Name
A unique name for the page, that will be used in the Path for the route.

.PARAMETER ScriptBlock
A ScriptBlock to invoke, where any results will be converted to HTML.

.PARAMETER FilePath
A FilePath, literal or relative, to a valid HTML file.

.PARAMETER View
The name of a View to render, this can be HTML or Dynamic.

.PARAMETER Data
A hashtable of Data to supply to a Dynamic File/View, or to be splatted as arguments for the ScriptBlock.

.PARAMETER Path
An optional Path for the Route, to prepend before the Name.

.PARAMETER Middleware
Like normal Routes, an array of Middleware that will be applied to all generated Routes.

.PARAMETER Authentication
The name of an Authentication method which should be used as middleware on this Route.

.PARAMETER Access
The name of an Access method which should be used as middleware on this Route.

.PARAMETER AllowAnon
If supplied, the Page will allow anonymous access for non-authenticated users.

.PARAMETER FlashMessages
If supplied, Views will have any flash messages supplied to them for rendering.

.PARAMETER Role
One or more optional Roles that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER Group
One or more optional Groups that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER Scope
One or more optional Scopes that will be authorised to access this Route, when using Authentication with an Access method.

.PARAMETER User
One or more optional Users that will be authorised to access this Route, when using Authentication with an Access method.

.EXAMPLE
Add-PodePage -Name Services -ScriptBlock { Get-Service }

.EXAMPLE
Add-PodePage -Name Index -View 'index'

.EXAMPLE
Add-PodePage -Name About -FilePath '.\views\about.pode' -Data @{ Date = [DateTime]::UtcNow }
#>
function Add-PodePage {
    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptBlock')]
        [scriptblock]
        $ScriptBlock,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'View')]
        [string]
        $View,

        [Parameter()]
        [hashtable]
        $Data,

        [Parameter()]
        [string]
        $Path = '/',

        [Parameter()]
        [object[]]
        $Middleware,

        [Parameter()]
        [Alias('Auth')]
        [string]
        $Authentication,

        [Parameter()]
        [string]
        $Access,

        [Parameter()]
        [string[]]
        $Role,

        [Parameter()]
        [string[]]
        $Group,

        [Parameter()]
        [string[]]
        $Scope,

        [Parameter()]
        [string[]]
        $User,

        [switch]
        $AllowAnon,

        [Parameter(ParameterSetName = 'View')]
        [switch]
        $FlashMessages
    )

    $logic = $null
    $arg = $null

    # ensure the name is a valid alphanumeric
    if ($Name -inotmatch '^[a-z0-9\-_]+$') {
        # The Page name should be a valid AlphaNumeric value
        throw ($PodeLocale.pageNameShouldBeAlphaNumericExceptionMessage -f $Name)
    }

    # trim end trailing slashes from the path
    $Path = Protect-PodeValue -Value $Path -Default '/'
    $Path = $Path.TrimEnd('/')

    # define the appropriate logic
    switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
        'scriptblock' {
            if (Test-PodeIsEmpty $ScriptBlock) {
                # A non-empty ScriptBlock is required to create a Page Route
                throw ($PodeLocale.nonEmptyScriptBlockRequiredForPageRouteExceptionMessage)
            }

            $arg = @($ScriptBlock, $Data)
            $logic = {
                param($script, $data)

                # invoke the function (optional splat data)
                if (Test-PodeIsEmpty $data) {
                    $result = Invoke-PodeScriptBlock -ScriptBlock $script -Return
                }
                else {
                    $result = Invoke-PodeScriptBlock -ScriptBlock $script -Arguments $data -Return
                }

                # if we have a result, convert it to html
                if (!(Test-PodeIsEmpty $result)) {
                    Write-PodeHtmlResponse -Value $result
                }
            }
        }

        'file' {
            $FilePath = Get-PodeRelativePath -Path $FilePath -JoinRoot -TestPath
            $arg = @($FilePath, $Data)
            $logic = {
                param($file, $data)
                Write-PodeFileResponse -Path $file -ContentType 'text/html' -Data $data
            }
        }

        'view' {
            $arg = @($View, $Data, $FlashMessages)
            $logic = {
                param($view, $data, [bool]$flash)
                Write-PodeViewResponse -Path $view -Data $data -FlashMessages:$flash
            }
        }
    }

    # build the route's path
    $_path = ("$($Path)/$($Name)" -replace '[/]+', '/')

    # create the route
    $params = @{
        Method         = 'Get'
        Path           = $_path
        Middleware     = $Middleware
        Authentication = $Authentication
        Access         = $Access
        Role           = $Role
        Group          = $Group
        Scope          = $Scope
        User           = $User
        AllowAnon      = $AllowAnon
        ArgumentList   = $arg
        ScriptBlock    = $logic
    }

    Add-PodeRoute @params
}

<#
.SYNOPSIS
Get a Route(s).

.DESCRIPTION
Get a Route(s).

.PARAMETER Method
A Method to filter the routes.

.PARAMETER Path
A Path to filter the routes.

.PARAMETER EndpointName
The name of an endpoint to filter routes.

.EXAMPLE
Get-PodeRoute -Method Get -Path '/about'

.EXAMPLE
Get-PodeRoute -Method Post -Path '/users/:userId' -EndpointName User
#>
function Get-PodeRoute {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [ValidateSet('', 'Connect', 'Delete', 'Get', 'Head', 'Merge', 'Options', 'Patch', 'Post', 'Put', 'Trace', '*')]
        [string]
        $Method,

        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [string[]]
        $EndpointName
    )

    # start off with every route
    $routes = @()
    foreach ($route in $PodeContext.Server.Routes.Values.Values) {
        $routes += $route
    }

    # if we have a method, filter
    if (![string]::IsNullOrWhiteSpace($Method)) {
        $routes = @(foreach ($route in $routes) {
                if ($route.Method -ine $Method) {
                    continue
                }

                $route
            })
    }

    # if we have a path, filter
    if (![string]::IsNullOrWhiteSpace($Path)) {
        $Path = Split-PodeRouteQuery -Path $Path
        $Path = Update-PodeRouteSlash -Path $Path
        $Path = Resolve-PodePlaceholder -Path $Path

        $routes = @(foreach ($route in $routes) {
                if ($route.Path -ine $Path) {
                    continue
                }

                $route
            })
    }

    # further filter by endpoint names
    if (($null -ne $EndpointName) -and ($EndpointName.Length -gt 0)) {
        $routes = @(foreach ($name in $EndpointName) {
                foreach ($route in $routes) {
                    if ($route.Endpoint.Name -ine $name) {
                        continue
                    }

                    $route
                }
            })
    }

    # return
    return $routes
}

<#
.SYNOPSIS
Get a static Route(s).

.DESCRIPTION
Get a static Route(s).

.PARAMETER Path
A Path to filter the static routes.

.PARAMETER EndpointName
The name of an endpoint to filter static routes.

.EXAMPLE
Get-PodeStaticRoute -Path '/assets'

.EXAMPLE
Get-PodeStaticRoute -Path '/assets' -EndpointName User
#>
function Get-PodeStaticRoute {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [string[]]
        $EndpointName
    )

    # start off with every route
    $routes = @()
    foreach ($route in $PodeContext.Server.Routes['Static'].Values) {
        $routes += $route
    }

    # if we have a path, filter
    if (![string]::IsNullOrWhiteSpace($Path)) {
        $Path = Update-PodeRouteSlash -Path $Path -Static
        $routes = @(foreach ($route in $routes) {
                if ($route.Path -ine $Path) {
                    continue
                }

                $route
            })
    }

    # further filter by endpoint names
    if (($null -ne $EndpointName) -and ($EndpointName.Length -gt 0)) {
        $routes = @(foreach ($name in $EndpointName) {
                foreach ($route in $routes) {
                    if ($route.Endpoint.Name -ine $name) {
                        continue
                    }

                    $route
                }
            })
    }

    # return
    return $routes
}

<#
.SYNOPSIS
Get a Signal Route(s).

.DESCRIPTION
Get a Signal Route(s).

.PARAMETER Path
A Path to filter the signal routes.

.PARAMETER EndpointName
The name of an endpoint to filter signal routes.

.EXAMPLE
Get-PodeSignalRoute -Path '/message'
#>
function Get-PodeSignalRoute {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [string[]]
        $EndpointName
    )

    # start off with every route
    $routes = @()
    foreach ($route in $PodeContext.Server.Routes['Signal'].Values) {
        $routes += $route
    }

    # if we have a path, filter
    if (![string]::IsNullOrWhiteSpace($Path)) {
        $Path = Update-PodeRouteSlash -Path $Path
        $routes = @(foreach ($route in $routes) {
                if ($route.Path -ine $Path) {
                    continue
                }

                $route
            })
    }

    # further filter by endpoint names
    if (($null -ne $EndpointName) -and ($EndpointName.Length -gt 0)) {
        $routes = @(foreach ($name in $EndpointName) {
                foreach ($route in $routes) {
                    if ($route.Endpoint.Name -ine $name) {
                        continue
                    }

                    $route
                }
            })
    }

    # return
    return $routes
}

<#
.SYNOPSIS
Automatically loads route ps1 files

.DESCRIPTION
Automatically loads route ps1 files from either a /routes folder, or a custom folder. Saves space dot-sourcing them all one-by-one.

.PARAMETER Path
Optional Path to a folder containing ps1 files, can be relative or literal.

.PARAMETER IfExists
Specifies what action to take when a Route already exists. (Default: Default)

.EXAMPLE
Use-PodeRoutes

.EXAMPLE
Use-PodeRoutes -Path './my-routes' -IfExists Skip
#>
function Use-PodeRoutes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [ValidateSet('Default', 'Error', 'Overwrite', 'Skip')]
        [string]
        $IfExists = 'Default'
    )

    if ($IfExists -ieq 'Default') {
        $IfExists = Get-PodeRouteIfExistsPreference
    }

    Use-PodeFolder -Path $Path -DefaultPath 'routes'
}

<#
.SYNOPSIS
Set the default IfExists preference for Routes.

.DESCRIPTION
Set the default IfExists preference for Routes.

.PARAMETER Value
Specifies what action to take when a Route already exists. (Default: Default)

.EXAMPLE
Set-PodeRouteIfExistsPreference -Value Overwrite
#>
function Set-PodeRouteIfExistsPreference {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Default', 'Error', 'Overwrite', 'Skip')]
        [string]
        $Value = 'Default'
    )

    $PodeContext.Server.Preferences.Routes.IfExists = $Value
}

<#
.SYNOPSIS
Test if a Route already exists.

.DESCRIPTION
Test if a Route already exists for a given Method and Path.

.PARAMETER Method
The HTTP Method of the Route.

.PARAMETER Path
The URI path of the Route.

.PARAMETER EndpointName
The EndpointName of an Endpoint the Route is bound against.

.PARAMETER CheckWildcard
If supplied, Pode will check for the Route on the Method first, and then check for the Route on the '*' Method.

.EXAMPLE
Test-PodeRoute -Method Post -Path '/example'

.EXAMPLE
Test-PodeRoute -Method Post -Path '/example' -CheckWildcard

.EXAMPLE
Test-PodeRoute -Method Get -Path '/example/:exampleId' -CheckWildcard
#>
function Test-PodeRoute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Connect', 'Delete', 'Get', 'Head', 'Merge', 'Options', 'Patch', 'Post', 'Put', 'Trace', '*')]
        [string]
        $Method,

        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $EndpointName,

        [switch]
        $CheckWildcard
    )

    # split route on '?' for query
    $Path = Split-PodeRouteQuery -Path $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        # No Path supplied for the Route
        throw ($PodeLocale.noPathSuppliedForRouteExceptionMessage)
    }

    # ensure the route has appropriate slashes
    $Path = Update-PodeRouteSlash -Path $Path
    $Path = Resolve-PodePlaceholder -Path $Path

    # get endpoint from name
    $endpoint = @(Find-PodeEndpoint -EndpointName $EndpointName)[0]

    # check for routes
    $found = (Test-PodeRouteInternal -Method $Method -Path $Path -Protocol $endpoint.Protocol -Address $endpoint.Address)
    if (!$found -and $CheckWildcard) {
        $found = (Test-PodeRouteInternal -Method '*' -Path $Path -Protocol $endpoint.Protocol -Address $endpoint.Address)
    }

    return $found
}

<#
.SYNOPSIS
Test if a Static Route already exists.

.DESCRIPTION
Test if a Static Route already exists for a given Path.

.PARAMETER Path
The URI path of the Static Route.

.PARAMETER EndpointName
The EndpointName of an Endpoint the Static Route is bound against.

.EXAMPLE
Test-PodeStaticRoute -Path '/assets'
#>
function Test-PodeStaticRoute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string[]]
        $EndpointName
    )

    # store the route method
    $Method = 'Static'

    # split route on '?' for query
    $Path = Split-PodeRouteQuery -Path $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        # No Path supplied for the Route
        throw ($PodeLocale.noPathSuppliedForRouteExceptionMessage)
    }

    # ensure the route has appropriate slashes
    $Path = Update-PodeRouteSlash -Path $Path -Static
    $Path = Resolve-PodePlaceholder -Path $Path

    # get endpoint from name
    $endpoint = @(Find-PodeEndpoint -EndpointName $EndpointName)[0]

    # check for routes
    return (Test-PodeRouteInternal -Method $Method -Path $Path -Protocol $endpoint.Protocol -Address $endpoint.Address)
}

<#
.SYNOPSIS
Test if a Signal Route already exists.

.DESCRIPTION
Test if a Signal Route already exists for a given Path.

.PARAMETER Path
The URI path of the Signal Route.

.PARAMETER EndpointName
The EndpointName of an Endpoint the Signal Route is bound against.

.EXAMPLE
Test-PodeSignalRoute -Path '/message'
#>
function Test-PodeSignalRoute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $EndpointName
    )

    $Method = 'Signal'

    # ensure the route has appropriate slashes
    $Path = Update-PodeRouteSlash -Path $Path

    # get endpoint from name
    $endpoint = @(Find-PodeEndpoint -EndpointName $EndpointName)[0]

    # check for routes
    return (Test-PodeRouteInternal -Method $Method -Path $Path -Protocol $endpoint.Protocol -Address $endpoint.Address)
}

<#
.SYNOPSIS
Adds cache settings to Pode route definitions via the pipeline.

.DESCRIPTION
The Add-PodeCache function allows you to apply HTTP caching behavior to Pode route hashtables. It supports enabling and disabling cache, as well as fine-grained control over directives such as Cache-Control visibility, max-age, ETag generation strategy, and immutability. It only applies caching to routes with GET, HEAD, or Static methods.

.PARAMETER Route
An array of route hashtables to which cache settings will be applied. These must include a 'Method' key with values like 'Get', 'Head', or 'Static'. Other methods are ignored.

.PARAMETER Enable
Enable caching for the provided route(s). Must be used with additional options in the 'Cache' parameter set.

.PARAMETER Disable
Disables all cache behavior for the provided route(s), overriding any other settings. Cannot be combined with other cache parameters.

.PARAMETER Visibility
Sets the visibility of the Cache-Control directive. Accepts: 'public', 'private', 'no-cache', 'no-store'.

.PARAMETER MaxAge
Specifies the `max-age` directive in seconds for Cache-Control.

.PARAMETER SharedMaxAge
Specifies the `s-maxage` directive in seconds for shared (proxy) caches.

.PARAMETER MustRevalidate
Adds the `must-revalidate` directive to Cache-Control.

.PARAMETER Immutable
Adds the `immutable` directive to Cache-Control to indicate that the resource will not change.

.PARAMETER ETagMode
Controls how the ETag should be generated. Valid values:
- 'none': disables ETag
- 'auto': chooses 'mtime' for static, 'hash' for dynamic routes
- 'hash': generates ETag based on content hash
- 'mtime': generates ETag based on file modification time
- 'manual': allows manual ETag setting via the ETag parameter of Write-PodeTextResponse, Write-PodeYamlResponse, Write-PodeJsonResponse, Write-PodeCsvResponse,
   Write-PodeHtmlResponse, and Write-PodexmlResponse cmdlets.

.PARAMETER WeakValidation
If specified, the ETag is returned in weak form (prefixed with W/).

.PARAMETER PassThru
If specified, the function outputs the modified route(s) back to the pipeline.

.EXAMPLE
$routes | Add-PodeCache -Enable -MaxAge 3600 -ETagMode auto -Visibility public -PassThru

Enables caching with a max age of 1 hour, automatic ETag strategy, and public visibility for all GET/HEAD routes in the $routes array.

.EXAMPLE
$routes | Add-PodeCache -Disable

Disables cache headers and ETag generation on all GET/HEAD routes.

.NOTES
This function is intended to be used during route configuration in Pode, and will be ignored for unsupported methods.
#>

function Add-PodeRouteCache {
    [CmdletBinding(DefaultParameterSetName = 'Cache')]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        $Route,

        [Parameter(ParameterSetName = 'Cache', Mandatory = $true)]
        [switch]
        $Enable,

        [Parameter(ParameterSetName = 'Cache')]
        [ValidateSet('public', 'private', 'no-cache', 'no-store')]
        [string]
        $Visibility,

        [Parameter(ParameterSetName = 'Cache')]
        [int]
        $MaxAge,

        [Parameter(ParameterSetName = 'Cache')]
        [int]
        $SharedMaxAge,

        [Parameter(ParameterSetName = 'Cache')]
        [switch]
        $MustRevalidate,

        [Parameter(ParameterSetName = 'Cache')]
        [switch]
        $Immutable,

        [Parameter(ParameterSetName = 'Disabled')]
        [switch]
        $Disable,

        [Parameter(ParameterSetName = 'Cache')]
        [ValidateSet('None', 'Auto', 'Hash', 'Mtime', 'Manual')]
        [string]
        $ETagMode = 'None',

        [Parameter(ParameterSetName = 'Cache')]
        [switch]
        $WeakValidation,

        [Parameter()]
        [switch]
        $PassThru
    )

    process {
        foreach ($r in $Route) {
            # Skip if Method is not GET or HEAD
            if (  'Get', 'Static', 'Head' -notcontains $r.Method) {
                if ($PassThru) { $r }
                continue
            }

            if ($Disable) {
                $r.cache.Enabled = $false
            }
            elseif ($Enable) {
                $r.Cache.Enabled = $true
                if ($Visibility) { $r.Cache.Visibility = $Visibility }
                if ($MaxAge -gt 0) { $r.Cache.MaxAge = $MaxAge }
                if ($SharedMaxAge -gt 0) { $r.Cache.SharedMaxAge = $SharedMaxAge }
                if ($MustRevalidate) { $r.Cache.MustRevalidate = $true }
                if ($Immutable) { $r.Cache.Immutable = $true }
                if ($ETagMode -ne 'None') {
                    $r.Cache.ETag = @{
                        Mode = $ETagMode
                        Weak = $WeakValidation.isPresent
                    }
                }
            }


            if ($PassThru) {
                $r
            }
        }
    }
}

<#
.SYNOPSIS
Enables or disables response compression for one or more Pode route hashtables.

.DESCRIPTION
The Add-PodeRouteCompression function allows you to configure compression behavior on Pode routes.
It modifies route hashtables passed through the pipeline by setting their `.Compression` property.

You can enable or disable compression explicitly. When enabled, you may optionally specify the allowed encoding methods
(e.g., gzip, deflate, br). This affects whether Pode compresses the response payload based on the client's Accept-Encoding
and the route’s configuration.

This function is intended for use during server setup when constructing or importing route configurations.

.PARAMETER Route
One or more route hashtables to modify. Must not be null or empty. Accepts pipeline input.

.PARAMETER Enable
Enables compression on the specified routes. Required when enabling compression.

.PARAMETER Disable
Disables compression on the specified routes. Required when disabling compression.

.PARAMETER Encoding
Specifies one or more compression algorithms to allow. Valid values are: 'gzip', 'deflate', and 'br'.
This parameter is only valid when compression is being enabled.

.PARAMETER PassThru
Returns the updated route hashtables to the pipeline.

.PARAMETER Direction
Specifies the direction of compression. Valid values are: 'Request', 'Response', and 'Both'.
The default is 'Response'. This determines whether the route will compress incoming requests, outgoing responses, or both.


.OUTPUTS
System.Collections.Hashtable[]
If -PassThru is specified, the modified route objects are returned.

.EXAMPLE
Add-PodeStaticRoute -Method Get -Path '/compress' -Source './' -PassThru | Add-PodeRouteCompression -Enable -Encoding gzip,br

Enables gzip and Brotli compression on the given route(s).

.EXAMPLE
$route | Add-PodeRouteCompression -Disable

Disables response compression on the given route(s).

.EXAMPLE
$routes = Get-Routes | Add-PodeRouteCompression -Enable -Encoding gzip

Enables gzip compression and captures the updated route hashtables.

.NOTES
This function is part of the Pode web framework.
Compression decisions at runtime depend on request headers and server capabilities.
#>
function Add-PodeRouteCompression {
    [CmdletBinding(DefaultParameterSetName = 'Enable')]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        $Route,

        [Parameter(ParameterSetName = 'Enable', Mandatory = $true)]
        [switch]
        $Enable,

        [Parameter(ParameterSetName = 'Disabled')]
        [switch]
        $Disable,

        [Parameter(ParameterSetName = 'Enable')]
        [ValidateSet('gzip', 'deflate', 'br')]
        [string[]]
        $Encoding,

        [Parameter(ParameterSetName = 'Enable')]
        [ValidateSet('Request', 'Response', 'Both')]
        [string]
        $Direction = 'Response',

        [Parameter()]
        [switch]
        $PassThru
    )

    process {
        foreach ($r in $Route) {
            if ($Disable) {
                $r.Compression.Enabled = $false
                $r.Compression.Request = $false
                $r.Compression.Response = $false
            }
            elseif ($Enable) {
                $r.Compression.Enabled = $true
                if ($Encoding) { $r.Compression.Encodings = @($Encoding) }

                switch ($Direction) {
                    'Request' {
                        $r.Compression.Request = $true
                        $r.Compression.Response = $false
                    }
                    'Response' {
                        $r.Compression.Request = $false
                        $r.Compression.Response = $true
                    }
                    'Both' {
                        $r.Compression.Request = $true
                        $r.Compression.Response = $true
                    }
                    default {
                        # This should never happen, but just in case
                        $r.Compression.Request = $false
                        $r.Compression.Response = $false
                    }
                }
            }

            if ($PassThru) {
                $r
            }
        }
    }
}