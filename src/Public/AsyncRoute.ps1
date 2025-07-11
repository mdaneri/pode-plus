<#
.SYNOPSIS
    Adds or configures asynchronous operation endpoints (Get, Stop, or Query) for existing Pode routes.

.DESCRIPTION
    The `Set-PodeAsyncRouteOperation` function centralizes the setup of common asynchronous endpoints for Pode routes.
    It supports three operation types:
    - **Get**: Retrieves async task status (typically via GET)
    - **Stop**: Aborts async tasks (typically via DELETE)
    - **Query**: Enables advanced querying of async tasks

    The Query mode supports three formats:
    - **QueryJson**: Accepts a structured request body (JSON/YAML/XML) using POST
    - **QueryDeepObject**: Accepts a deepObject-style query string like `filter[State][op]=EQ`
    - **SimpleQuery**: Accepts flat key=value query strings like `?State=Completed,Cancellable=True`

.PARAMETER Route
    One or more Pode route hashtables. This is the target for attaching the async operation endpoint.
    Supports pipeline input and is mandatory.

.PARAMETER Get
    Switch. Creates a status retrieval endpoint for async tasks (usually GET).
    Required for the 'Get' parameter set.

.PARAMETER Stop
    Switch. Creates an endpoint to stop async tasks (usually DELETE).
    Required for the 'Stop' parameter set.

.PARAMETER Query
    Switch. Enables a query endpoint for async tasks.
    Required for the 'QueryJson', 'QueryDeepObject', or 'SimpleQuery' parameter sets.

.PARAMETER DeepObject
    Switch. Used only with the 'QueryDeepObject' parameter set to indicate the query uses deepObject-style query parameters.

.PARAMETER Simple
    Switch. Used only with the 'SimpleQuery' parameter set to indicate the query uses flat key=value parameters like `?State=Completed`.
    This simple query mode supports only equality comparisons (EQ).
    It does not support advanced operators like GT, LT, LIKE, etc.

.PARAMETER ResponseContentType
    An array of response content types (e.g., 'application/json', 'application/yaml').
    Defaults to `'application/json'`.

.PARAMETER In
    For Get/Stop operations, specifies where to read the task Id from.
    Acceptable values: `'Cookie'`, `'Header'`, `'Path'`, `'Query'`.
    Defaults to `'Query'`.

.PARAMETER QueryContentType
    An array of accepted request content types for query operations.
    Only applicable to the 'QueryJson' and 'QueryDeepObject' modes. Defaults to `'application/json'`.

.PARAMETER Payload
    Where the query input should come from. Only valid for `QueryJson`.
    Acceptable values: `'Body'`, `'Header'`, `'Query'`. Defaults to `'Body'`.

.PARAMETER AllowNonStandardBody
    Allows POST-style request bodies on non-POST methods. Only used with `QueryJson`.

.PARAMETER PassThru
    If specified, returns the modified route(s) after applying the operation.

.EXAMPLE
    Add-PodeRoute -Method Post -Path '/tasks' -PassThru |
        Set-PodeAsyncRouteOperation -Query -QueryContentType 'application/json' -ResponseContentType 'application/json' -Payload Body -PassThru |
        Set-PodeOARouteInfo -Summary 'Query Async Route Task Info (JSON Body)'

    Creates a POST route at `/tasks` that accepts a JSON request body for querying async tasks.

.EXAMPLE
    Add-PodeRoute -Method Get -Path '/tasks' -PassThru |
        Set-PodeAsyncRouteOperation -Query -DeepObject -ResponseContentType 'application/json' -PassThru |
        Set-PodeOARouteInfo -Summary 'Query Async Route Task Info (DeepObject)'

    Creates a GET route at `/tasks` that accepts deepObject-style query parameters, e.g.:
    `/tasks?filter[State][op]=EQ&filter[State][value]=Completed`

.EXAMPLE
    Add-PodeRoute -Method Get -Path '/tasks' -PassThru |
        Set-PodeAsyncRouteOperation -Query -Simple -ResponseContentType 'application/json' -PassThru |
        Set-PodeOARouteInfo -Summary 'Query Async Route Task Info (Simple Query)'

    Creates a GET route at `/tasks` that supports flat query strings, e.g.:
    `/tasks?State=Completed,Cancellable=True`

.EXAMPLE
    Add-PodeRoute -Method Get -Path '/task' -PassThru |
        Set-PodeAsyncRouteOperation -Get -In Path -ResponseContentType 'application/json' -PassThru |
        Set-PodeOARouteInfo -Summary 'Get Async Task Info'

.EXAMPLE
    Add-PodeRoute -Method Delete -Path '/task' -PassThru |
        Set-PodeAsyncRouteOperation -Stop -In Query -ResponseContentType 'application/json' -PassThru |
        Set-PodeOARouteInfo -Summary 'Stop Async Task'
#>

function Set-PodeAsyncRouteOperation {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        $Route,

        [Parameter(Mandatory = $true, ParameterSetName = 'Get')]
        [switch]
        $Get,

        [Parameter(Mandatory = $true, ParameterSetName = 'Stop')]
        [switch]
        $Stop,

        [Parameter(Mandatory = $true, ParameterSetName = 'QueryJson')]
        [Parameter(Mandatory = $true, ParameterSetName = 'QueryDeepObject')]
        [Parameter(Mandatory = $true, ParameterSetName = 'SimpleQuery')]
        [switch]
        $Query,

        [Parameter()]
        [string[]]
        [ValidateSet('application/json' , 'application/xml', 'application/yaml')]
        $ResponseContentType = 'application/json',

        [Parameter(ParameterSetName = 'Stop')]
        [Parameter(ParameterSetName = 'Get')]
        [ValidateSet('Cookie', 'Header', 'Path', 'Query')]
        [string]
        $In = 'Query',

        [Parameter(ParameterSetName = 'QueryJson')]
        [string[]]
        [ValidateSet('application/json' , 'application/xml', 'application/yaml')]
        $QueryContentType = 'application/json',

        [Parameter(ParameterSetName = 'QueryDeepObject')]
        [switch]
        $DeepObject,

        [Parameter(ParameterSetName = 'SimpleQuery')]
        [switch]
        $Simple,

        [Parameter(ParameterSetName = 'QueryJson')]
        [string]
        [ValidateSet('Body', 'Header', 'Query' )]
        $Payload = 'Body',

        [Parameter(ParameterSetName = 'QueryJson')]
        [switch]
        $AllowNonStandardBody,

        [Parameter()]
        [switch]
        $PassThru
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
        # Set Route to the array of values
        if ($pipelineValue.Count -gt 1) {
            $Route = $pipelineValue
        }

        $newRoutes = @()

        foreach ($r in @($Route)) {
            if ($null -eq $r) {
                # The parameter 'Route' cannot be null
                throw ($PodeLocale.routeParameterCannotBeNullExceptionMessage)
            }


            # Check if the route is already marked as an Async Route
            if ( $r.IsAsync) {
                # The function cannot be invoked multiple times for the same route
                throw ($PodeLocale.functionCannotBeInvokedMultipleTimesExceptionMessage -f $MyInvocation.MyCommand.Name, $r.Path)
            }

            # Check if a Definition exists
            $oaName = Get-PodeAsyncRouteOAName -Tag $r.OpenAPI.DefinitionTag

            Remove-PodeRoute -Path $r.Path -Method $r.Method  -Endpoint $r.Endpoint.Named

            switch ($PSCmdlet.ParameterSetName) {
                'Get' {

                    # Append task Id to path if the task Id is in the path
                    $Path = if ($In -eq 'Path') {
                        "$($r.Path.TrimEnd('/'))/:$($oaName.TaskIdName)"
                    }
                    else {
                        $r.Path
                    }

                    # Define the parameters for the route
                    $param = @{
                        Method           = $r.Method
                        Path             = $Path
                        ScriptBlock      = Get-PodeAsyncGetScriptBlock
                        ArgumentList     = ($In, $oaName.TaskIdName)
                        ErrorContentType = $ResponseContentType[0]
                        PassThru         = $true
                    }

                }
                'Stop' {
                    # Append task Id to path if the task Id is in the path
                    $Path = if ($In -eq 'Path') {
                        "$($r.Path.TrimEnd('/'))/:$($oaName.TaskIdName)"
                    }
                    else {
                        $r.Path
                    }

                    # Define the parameters for the route
                    $param = @{
                        Method           = $r.Method
                        Path             = $Path
                        ScriptBlock      = Get-PodeAsyncRouteStopScriptBlock
                        ArgumentList     = ($In, $oaName.TaskIdName)
                        ErrorContentType = $ResponseContentType[0]
                        PassThru         = $true
                    }
                }
                'QueryJson' {
                    if ($r.Method -ne 'Post' -and $Payload -eq 'Body' -and (! $AllowNonStandardBody)) {
                        throw ($PodeLocale.getRequestBodyNotAllowedExceptionMessage -f $r.Method )
                    }

                    # Define the parameters for the route
                    $param = @{
                        Method           = $r.Method
                        Path             = $r.Path
                        ScriptBlock      = Get-PodeAsyncRouteQueryScriptBlock
                        ArgumentList     = @($Payload, $r.OpenAPI.DefinitionTag)
                        ErrorContentType = $ResponseContentType[0]
                        ContentType      = $QueryContentType[0]
                        PassThru         = $true
                    }
                }
                'QueryDeepObject' {
                    # Define the parameters for the route
                    $param = @{
                        Method           = $r.Method
                        Path             = $r.Path
                        ScriptBlock      = Get-PodeAsyncRouteQueryScriptBlock
                        ArgumentList     = @('QueryDeepObject', $r.OpenAPI.DefinitionTag)
                        ErrorContentType = $ResponseContentType[0]
                        ContentType      = $QueryContentType[0]
                        PassThru         = $true
                    }
                }
                'SimpleQuery' {
                    # Define the parameters for the route
                    $param = @{
                        Method           = $r.Method
                        Path             = $r.Path
                        ScriptBlock      = Get-PodeAsyncRouteQueryScriptBlock
                        ArgumentList     = @('SimpleQuery', $r.OpenAPI.DefinitionTag)
                        ErrorContentType = $ResponseContentType[0]
                        ContentType      = $QueryContentType[0]
                        PassThru         = $true
                    }
                }
            }


            # Add optional parameters to the route
            if ($r.Middleware) {
                $param.Middleware = $r.Middleware
            }
            if ($r.Endpoint.Name) {
                $param.EndpointName = $r.Endpoint.Name
            }
            if ($r.Authentication) {
                $param.Authentication = $r.Authentication
            }
            if ($r.Access) {
                $param.Access = $r.Access
            }
            if ($r.Access.Role) {
                $param.Role = $r.Access.Role
            }
            if ($r.Access.Group) {
                $param.Group = $r.Access.Group
            }
            if ($r.Access.Scope) {
                $param.Scope = $r.Access.Scope
            }
            if ($r.Access.User) {
                $param.User = $r.Access.User
            }

            if ($r.MiddlewareMeta.Login) {
                $param.Login = $r.MiddlewareMeta.Login
            }
            if ($r.MiddlewareMeta.Logout) {
                $param.Logout = $r.MiddlewareMeta.Logout
            }
            if ($r.MiddlewareMeta.Anon) {
                $param.AllowAnon = [switch]$r.MiddlewareMeta.Anon
            }
            if ($r.MiddlewareMeta.Middleware) {
                $param.Middleware = $r.MiddlewareMeta.Middleware
            }

            # Add the route to Pode
            $newRoute = Add-PodeRoute @param
            switch ($PSCmdlet.ParameterSetName) {
                'Get' {
                    # Add OpenAPI documentation postponed script
                    $newRoute.OpenApi.Postponed = {
                        param($param)
                        $param.Route | Set-PodeOARequest -PassThru -Parameters (
                            New-PodeOAStringProperty -Name $param.OAName.TaskIdName -Format Uuid -Description 'Task Id' -Required | ConvertTo-PodeOAParameter -In $param.In) |
                            Add-PodeOAResponse -StatusCode 200 -Description 'Successful operation' -Content (New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content $param.OAName.OATypeName) -PassThru |
                            Add-PodeOAResponse -StatusCode 4XX -Description 'Client error. The request contains bad syntax or cannot be fulfilled.' -Content (
                                New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content (
                                    New-PodeOAStringProperty -Name 'Id' -Format Uuid -Required | New-PodeOAStringProperty -Name 'Error' -Required | New-PodeOAObjectProperty -XmlName "$($param.OAName.OATypeName)Error"
                                ))
                    }
                }
                'Stop' {
                    # Add OpenAPI documentation postponed script
                    $newRoute.OpenApi.Postponed = {
                        param($param)
                        $param.Route | Set-PodeOARequest -PassThru -Parameters (
                            New-PodeOAStringProperty -Name $param.OAName.TaskIdName -Format Uuid -Description 'Task Id' -Required | ConvertTo-PodeOAParameter -In $param.In) |
                            Add-PodeOAResponse -StatusCode 200 -Description 'Successful operation' -Content (New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content $param.OAName.OATypeName) -PassThru |
                            Add-PodeOAResponse -StatusCode 4XX -Description 'Client error. The request contains bad syntax or cannot be fulfilled.' -Content (
                                New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content (
                                    New-PodeOAStringProperty -Name 'Id' -Format Uuid -Required | New-PodeOAStringProperty -Name 'Error' -Required | New-PodeOAObjectProperty -XmlName "$($param.OAName.OATypeName)Error"
                                )
                            )
                    }
                }
                'QueryJson' {
                    # Add OpenAPI documentation postponed script
                    $newRoute.OpenApi.Postponed = {
                        param($param)
                        New-PodeOAAsyncRouteQueryRequestSchema -OAName $param.OAName

                        # Define an example hashtable for the OpenAPI request
                        $exampleHashTable = @{
                            'StartingTime' = @{
                                op    = 'GT'
                                value = (Get-Date '2024-07-05T20:20:00Z')
                            }
                            'CreationTime' = @{
                                op    = 'LE'
                                value = (Get-Date '2024-07-05T20:20:00Z')
                            }
                            'State'        = @{
                                op    = 'EQ'
                                value = 'Completed'
                            }
                            'AsyncRouteId' = @{
                                op    = 'LIKE'
                                value = 'Get'
                            }
                            'Id'           = @{
                                op    = 'EQ'
                                value = 'b143660f-ebeb-49d9-9f92-cd21f3ff559c'
                            }
                            'Cancellable'  = @{
                                op    = 'EQ'
                                value = $true
                            }
                        }

                        # Add OpenAPI route information and responses
                        $param.Route |
                            Add-PodeOAResponse -StatusCode 200 -Description 'Successful operation' -Content (New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content $param.OAName.OATypeName -Array) -PassThru |
                            Add-PodeOAResponse -StatusCode 400 -Description 'Invalid filter supplied' -Content (
                                New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content (
                                    New-PodeOAStringProperty -Name 'Error' -Required | New-PodeOAObjectProperty -XmlName "$($param.OAName.OATypeName)Error"
                                )
                            ) -PassThru | Add-PodeOAResponse -StatusCode 500 -Content (
                                New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content (
                                    New-PodeOAStringProperty -Name 'Error' -Required | New-PodeOAObjectProperty -XmlName "$($param.OAName.OATypeName)Error"
                                )
                            )


                        # Define examples for different media types
                        $example = [ordered]@{}
                        foreach ($mt in $param.QueryContentType) {
                            $example += New-PodeOAExample -MediaType $mt -Name $param.OAName.QueryRequestName -Value $exampleHashTable
                        }

                        # Set the OpenAPI request based on the payload location
                        switch ($param.Payload.ToLowerInvariant()) {
                            'body' {
                                $param.Route | Set-PodeOARequest -allowNonStandardBody:$param.AllowNonStandardBody -RequestBody (
                                    New-PodeOARequestBody -Content (New-PodeOAContentMediaType -MediaType $param.QueryContentType -Content $param.OAName.QueryRequestName) -Examples $example
                                )
                            }
                            'header' {
                                $param.Route | Set-PodeOARequest -Parameters (ConvertTo-PodeOAParameter -In Header -Schema $param.OAName.QueryRequestName -ContentType $param.QueryContentType[0] -Example $example[0])
                            }
                            'query' {
                                $param.Route | Set-PodeOARequest -Parameters (ConvertTo-PodeOAParameter -In Query -Schema $param.OAName.QueryRequestName -ContentType $param.QueryContentType[0] -Example $example[0])
                            }
                        }
                    }

                }

                'SimpleQuery' {
                    # Add OpenAPI documentation postponed script
                    $newRoute.OpenApi.Postponed = {
                        param($param)
                        New-PodeOAAsyncRouteQueryRequestSchema -OAName $param.OAName



                        # Add OpenAPI route information and responses
                        $param.Route |
                            Add-PodeOAResponse -StatusCode 200 -Description 'Successful operation' -Content (New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content $param.OAName.OATypeName -Array) -PassThru |
                            Add-PodeOAResponse -StatusCode 400 -Description 'Invalid filter supplied' -Content (
                                New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content (
                                    New-PodeOAStringProperty -Name 'Error' -Required | New-PodeOAObjectProperty -XmlName "$($param.OAName.OATypeName)Error"
                                )
                            ) -PassThru | Add-PodeOAResponse -StatusCode 500 -Content (
                                New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content (
                                    New-PodeOAStringProperty -Name 'Error' -Required | New-PodeOAObjectProperty -XmlName "$($param.OAName.OATypeName)Error"
                                )
                            )


                        $param.Route | Set-PodeOARequest -Parameters @(
                                (New-PodeOAStringProperty -Name 'Id' -Description 'Filter by Id (EQ only)' -Example 'b143660f-ebeb-49d9-9f92-cd21f3ff559c' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'AsyncRouteId' -Description 'Filter by async route Id (EQ only)' -Example 'GetAsyncTask' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'State' -Description 'Filter by task state (EQ only)' -Example 'Completed' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'Error' -Description 'Filter by error message (EQ only)' -Example 'Timeout' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'CallbackSettings' -Description 'Filter by callback settings (EQ only)' -Example 'retry:3' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'SseGroup' -Description 'Filter by SSE group (EQ only)' -Example 'monitoring-group' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'User' -Description 'Filter by user (EQ only)' -Example 'admin' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'Url' -Description 'Filter by task URL (EQ only)' -Example '/api/v1/some-task' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'Method' -Description 'Filter by HTTP method (EQ only)' -Example 'POST' | ConvertTo-PodeOAParameter -In Query),

                                (New-PodeOAStringProperty -Name 'StartingTime' -Format date-time -Description 'Filter by task start time (EQ only)' -Example '2024-07-05T20:00:00Z' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'CreationTime' -Format date-time -Description 'Filter by task creation time (EQ only)' -Example '2024-07-05T20:05:00Z' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'CompletedTime' -Format date-time -Description 'Filter by task completion time (EQ only)' -Example '2024-07-05T20:10:00Z' | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOAStringProperty -Name 'ExpireTime' -Format date-time -Description 'Filter by task expiry time (EQ only)' -Example '2024-07-06T20:00:00Z' | ConvertTo-PodeOAParameter -In Query),

                                (New-PodeOABoolProperty -Name 'SseEnabled' -Description 'Filter by SSE enabled flag (EQ only)' -Example $true | ConvertTo-PodeOAParameter -In Query),
                                (New-PodeOABoolProperty -Name 'Cancellable' -Description 'Filter by cancellable flag (EQ only)' -Example $false | ConvertTo-PodeOAParameter -In Query),

                                (New-PodeOANumberProperty -Name 'Progress' -Description 'Filter by progress percentage (EQ only)' -Example 85 | ConvertTo-PodeOAParameter -In Query)
                        )
                    }
                }

                'QueryDeepObject' {
                    # Add OpenAPI documentation postponed script
                    $newRoute.OpenApi.Postponed = {
                        param($param)
                        New-PodeOAAsyncRouteQueryRequestSchema -OAName $param.OAName

                        # Add OpenAPI route information and responses
                        $param.Route |
                            Add-PodeOAResponse -StatusCode 200 -Description 'Successful operation' -Content (New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content $param.OAName.OATypeName -Array) -PassThru |
                            Add-PodeOAResponse -StatusCode 400 -Description 'Invalid filter supplied' -Content (
                                New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content (
                                    New-PodeOAStringProperty -Name 'Error' -Required | New-PodeOAObjectProperty -XmlName "$($param.OAName.OATypeName)Error"
                                )
                            ) -PassThru | Add-PodeOAResponse -StatusCode 500 -Content (
                                New-PodeOAContentMediaType -MediaType $param.ResponseContentType -Content (
                                    New-PodeOAStringProperty -Name 'Error' -Required | New-PodeOAObjectProperty -XmlName "$($param.OAName.OATypeName)Error"
                                )
                            )

                               $exampleHashTable = @{
                            'StartingTime' = @{
                                op    = 'GT'
                                value = (Get-Date '2024-07-05T20:20:00Z')
                            }
                            'CreationTime' = @{
                                op    = 'LE'
                                value = (Get-Date '2024-07-05T20:20:00Z')
                            }
                            'State'        = @{
                                op    = 'EQ'
                                value = 'Completed'
                            }
                            'AsyncRouteId' = @{
                                op    = 'LIKE'
                                value = 'Get'
                            }
                            'Id'           = @{
                                op    = 'EQ'
                                value = 'b143660f-ebeb-49d9-9f92-cd21f3ff559c'
                            }
                            'Cancellable'  = @{
                                op    = 'EQ'
                                value = $true
                            }
                        }
                        $qpm = $param.OAName.QueryDeepObjectName

                        $param.Route | Set-PodeOARequest -Parameters (ConvertTo-PodeOAParameter -In Query -Schema $param.OAName.QueryRequestName -Style DeepObject -Explode `
                                -Example $exampleHashTable)
                    }
                }
            }

            # Attach argument metadata for OpenAPI and further processing.
            $newRoute.OpenApi.PostponedArgumentList = @{
                OAName               = $oaName
                In                   = $In
                ResponseContentType  = $ResponseContentType
                QueryContentType     = $QueryContentType
                Payload              = $Payload
                AllowNonStandardBody = $AllowNonStandardBody.IsPresent
                Route                = $newRoute
            }

            # Collect the created route for possible PassThru return.
            $newRoutes += $newRoute
        }

        # Return the newly created routes if requested.
        if ($PassThru) {
            return $newRoutes
        }
    }
}

<#
.SYNOPSIS
    Assigns or removes permissions to/from an asynchronous route in Pode based on specified criteria such as users, groups, roles, and scopes.

.DESCRIPTION
    The `Set-PodeAsyncRoutePermission` function allows you to define and assign or remove specific permissions to/from an async route.
    You can control access to the route by specifying which users, groups, roles, or scopes have `Read` or `Write` permissions.

.PARAMETER Route
    A hashtable array representing the async route(s) to which permissions will be assigned or from which they will be removed. This parameter is mandatory.

.PARAMETER Type
    Specifies the type of permission to assign or remove. Acceptable values are 'Read' or 'Write'. This parameter is mandatory.

.PARAMETER Groups
    Specifies the groups that will be granted or removed from the specified permission type.

.PARAMETER Users
    Specifies the users that will be granted or removed from the specified permission type.

.PARAMETER Roles
    Specifies the roles that will be granted or removed from the specified permission type.

.PARAMETER Scopes
    Specifies the scopes that will be granted or removed from the specified permission type.

.PARAMETER Remove
    If specified, the function will remove the specified users, groups, roles, or scopes from the permissions instead of adding them.

.PARAMETER PassThru
    If specified, the function will return the modified route object(s) after assigning or removing permissions.

.EXAMPLE
    Add-PodeRoute -PassThru -Method Put -Path '/asyncState' -Authentication 'Validate' -Group 'Support' `
    -ScriptBlock {
        $data = Get-PodeState -Name 'data'
        Write-PodeHost 'data:'
        Write-PodeHost $data -Explode -ShowType
        Start-Sleep $data.sleepTime
        return @{ InnerValue = $data.Message }
    } | Set-PodeAsyncRoute `
        -ResponseContentType 'application/json', 'application/yaml' -Timeout 300 -PassThru |
        Set-PodeAsyncRoutePermission -Type Read -Groups 'Developer'

    This example creates an async route that requires authentication and assigns 'Read' permission to the 'Developer' group.

.EXAMPLE
    # Removing 'Developer' group from Read permissions
    Set-PodeAsyncRoutePermission -Route $route -Type Read -Groups 'Developer' -Remove

    This example removes the 'Developer' group from the 'Read' permissions of the specified async route.

.OUTPUTS
    [hashtable]
#>
function Set-PodeAsyncRoutePermission {
    param(
        [Parameter(Mandatory = $true , ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        $Route,

        [ValidateSet('Read', 'Write')]
        [string]
        $Type,

        [Parameter()]
        [string[]]
        $Groups,

        [Parameter()]
        [string[]]
        $Users,

        [Parameter()]
        [string[]]
        $Roles,

        [Parameter()]
        [string[]]
        $Scopes,

        [switch]
        $Remove,

        [switch]
        $PassThru
    )

    Begin {
        $pipelineValue = @()
    }

    Process {
        # Add the current piped-in value to the array
        $pipelineValue += $_
    }

    End {
        # Helper function to add or remove items from a permission list
        function Update-PermissionList {
            param (
                [Parameter(Mandatory = $true)]
                [AllowEmptyCollection()]
                [string[]]$List,

                [string[]]$Items,

                [switch]$Remove
            )
            # Initialize $List if it's null
            if (! $List) {
                $List = @()
            }

            if ($Remove) {
                return $List | Where-Object { $_ -notin $Items }
            }
            else {
                return $List + $Items
            }
        }

        # Handle multiple piped-in routes
        if ($pipelineValue.Count -gt 1) {
            $Route = $pipelineValue
        }

        # Validate that the Route parameter is not null
        if ($null -eq $Route) {
            # The parameter 'Route' cannot be null
            throw ($PodeLocale.routeParameterCannotBeNullExceptionMessage)
        }

        foreach ($r in $Route) {
            # Check if the route is marked as an Async Route
            if (! $r.IsAsync) {
                # The route '{0}' is not marked as an Async Route.
                throw ($PodeLocale.routeNotMarkedAsAsyncExceptionMessage -f $r.Path)
            }

            # Initialize the permission type hashtable if not already present
            if (! $r.Async.Permission.ContainsKey($Type)) {
                $r.Async.Permission[$Type] = @{}
            }

            # Assign or remove users from the specified permission type
            if ($Users) {
                if (!$r.Async.Permission[$Type].ContainsKey('Users')) {
                    $r.Async.Permission[$Type].Users = @()
                }
                $r.Async.Permission[$Type].Users = Update-PermissionList -List $r.Async.Permission[$Type].Users -Items $Users -Remove:$Remove
            }

            # Assign or remove groups from the specified permission type
            if ($Groups) {
                if (!$r.Async.Permission[$Type].ContainsKey('Groups')) {
                    $r.Async.Permission[$Type].Groups = @()
                }
                $r.Async.Permission[$Type].Groups = Update-PermissionList -List $r.Async.Permission[$Type].Groups -Items $Groups -Remove:$Remove
            }

            # Assign or remove roles from the specified permission type
            if ($Roles) {
                if (!$r.Async.Permission[$Type].ContainsKey('Roles')) {
                    $r.Async.Permission[$Type].Roles = @()
                }
                $r.Async.Permission[$Type].Roles = Update-PermissionList -List $r.Async.Permission[$Type].Roles -Items $Roles -Remove:$Remove
            }

            # Assign or remove scopes from the specified permission type
            if ($Scopes) {
                if (!$r.Async.Permission[$Type].ContainsKey('Scopes')) {
                    $r.Async.Permission[$Type].Scopes = @()
                }
                $r.Async.Permission[$Type].Scopes = Update-PermissionList -List $r.Async.Permission[$Type].Scopes -Items $Scopes -Remove:$Remove
            }
        }

        # Return the route object(s) if PassThru is specified
        if ($PassThru) {
            return $Route
        }
    }
}



<#
.SYNOPSIS
    Adds a callback to an asynchronous route in Pode.

.DESCRIPTION
    The Add-PodeAsyncRouteCallback function allows you to attach a callback to an existing asynchronous route in Pode.
    This function takes various parameters to configure the callback URL, method, headers, and more.

.PARAMETER Route
    The route(s) to which the callback should be added. This parameter is mandatory and accepts hashtable arrays.

.PARAMETER CallbackUrl
    Specifies the URL field for the callback. Default is '$request.body#/callbackUrl'.
    Can accept the following meta values:
    - $request.query.param-name  : query-param-value
    - $request.header.header-name: application/json
    - $request.body#/field-name  : callbackUrl
    Can accept static values for example:
    - 'http://example.com/callback'
    - 'https://api.example.com/callback

.PARAMETER SendResult
    If specified, sends the result of the callback.

.PARAMETER EventName
    Specifies the event name for the callback.

.PARAMETER CallbackContentType
    Specifies the content type for the callback. The default is 'application/json'.
    Can accept the following meta values:
    - $request.query.param-name  : query-param-value
    - $request.header.header-name: application/json
    - $request.body#/field-name  : callbackUrl
    Can accept static values for example:
    - 'application/json'
    - 'application/xml'
    - 'text/plain'

.PARAMETER CallbackMethod
    Specifies the HTTP method for the callback. The default is 'Post'.
    Can accept the following meta values:
    - $request.query.param-name  : query-param-value
    - $request.header.header-name: application/json
    - $request.body#/field-name  : callbackUrl
    Can accept static values for example:
    - `GET`
    - `POST`
    - `PUT`
    - `DELETE`
.PARAMETER CallbackHeaderFields
    Specifies the header fields for the callback as a hashtable. The key can be a string representing
    the header key or one of the meta values. The value is the header value if it's a standard key or
    the default value if the meta value is not resolvable.
    Can accept the following meta values as keys:
    - $request.query.param-name  : query-param-value
    - $request.header.header-name: application/json
    - $request.body#/field-name  : callbackUrl
    Can accept static values for example:
    - `@{ 'Content-Type' = 'application/json' }`
    - `@{ 'Authorization' = 'Bearer token' }`
    - `@{ 'Custom-Header' = 'value' }`

.PARAMETER PassThru
    If specified, the route information is returned.

.EXAMPLE
      Add-PodeRoute -PassThru -Method Put -Path '/example' |
      Add-PodeAsyncRouteCallback -Route $route -CallbackUrl '$request.body#/callbackUrl'

.NOTES
    This function should only be used with routes that have been marked as asynchronous using the Set-PodeAsyncRoute function.

.NOTES
    The parameters CallbackHeaderFields, CallbackMethod, CallbackContentType, and CallbackUrl can accept these meta values:
    - $request.query.param-name  : query-param-value
    - $request.header.header-name: application/json
    - $request.body#/field-name  : callbackUrl
#>
function  Add-PodeAsyncRouteCallback {
    param (
        [Parameter(Mandatory = $true , ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        $Route,

        [Parameter()]
        [string]
        $CallbackUrl = '$request.body#/callbackUrl',

        [Parameter()]
        [switch]
        $SendResult,

        [Parameter()]
        [string]
        $EventName,

        [Parameter()]
        [string]
        $CallbackContentType = 'application/json',

        [Parameter()]
        [string]
        $CallbackMethod = 'Post',

        [Parameter()]
        [hashtable]
        $CallbackHeaderFields = @{},

        [switch]
        $PassThru
    )

    Begin {
        $pipelineValue = @()
        $CallbackSettings = @{
            UrlField     = $CallbackUrl
            ContentType  = $CallbackContentType
            SendResult   = $SendResult.IsPresent
            Method       = $CallbackMethod
            HeaderFields = $CallbackHeaderFields
        }
    }

    Process {
        # Add the current piped-in value to the array
        $pipelineValue += $_
    }

    End {
        # Handle multiple piped-in routes
        if ($pipelineValue.Count -gt 1) {
            $Route = $pipelineValue
        }

        # Validate that the Route parameter is not null
        if ($null -eq $Route) {
            # The parameter 'Route' cannot be null
            throw ($PodeLocale.routeParameterCannotBeNullExceptionMessage)
        }

        foreach ($r in $Route) {
            # Check if the route is marked as an Async Route
            if (! $r.IsAsync) {
                # The route '{0}' is not marked as an Async Route.
                throw ($PodeLocale.routeNotMarkedAsAsyncExceptionMessage -f $r.Path)
            }

            # Generate or use the provided event name for the callback
            if ([string]::IsNullOrEmpty($EventName)) {
                $CallbackSettings.EventName = $r.Path.Replace('/', '_') + '_Callback'
            }
            else {
                if ($Route.Count -gt 1) {
                    $CallbackSettings.EventName = "$EventName_$($r.Path.Replace('/', '_'))"
                }
                else {
                    $CallbackSettings.EventName = $EventName
                }
            }

            # Attach the callback settings to the Async Route
            $r.Async.CallbackSettings = $CallbackSettings

            # Add OpenAPI callback documentation if applicable
            if ( $r.OpenApi.Swagger) {
                $r |
                    Add-PodeOACallBack -Name $CallbackSettings.EventName -Path $CallbackUrl -Method $CallbackMethod -DefinitionTag $r.OpenApi.DefinitionTag -RequestBody (
                        New-PodeOARequestBody -Content @{ $CallbackContentType = (
                                New-PodeOAObjectProperty -Name 'Result' |
                                    New-PodeOAStringProperty -Name 'EventName' -Description 'The event name.' -Required |
                                    New-PodeOAStringProperty -Name 'Url' -Format Uri -Example 'http://localhost/callback' -Required |
                                    New-PodeOAStringProperty -Name 'Method' -Example 'Post' -Required |
                                    New-PodeOAStringProperty -Name 'State' -Description 'The parent async route task status' -Required -Example 'Complete' -Enum @('NotStarted', 'Running', 'Failed', 'Completed', 'Aborted') |
                                    New-PodeOAObjectProperty -Name 'Result' -Description 'The parent result' -NoProperties |
                                    New-PodeOAStringProperty -Name 'Error' -Description 'The parent error' |
                                    New-PodeOAObjectProperty
                                )
                            }
                        ) -Response (
                            New-PodeOAResponse -StatusCode 200 -Description  'Successful operation'
                        )
            }
        }
        # Return the route information if PassThru is specified
        if ($PassThru) {
            return $Route
        }
    }
}

<#
.SYNOPSIS
    Defines an asynchronous route in Pode with runspace management.

.DESCRIPTION
    The `Set-PodeAsyncRoute` function enables you to define routes in Pode that execute asynchronously,
    leveraging runspace management for non-blocking operation. This function allows you to specify
    response types (JSON, XML, YAML) and manage asynchronous task parameters such as timeout and
    unique Id generation. It supports the use of arguments, `$using` variables, and state variables.

.PARAMETER Route
    A hashtable array that contains route definitions. Each hashtable should include
    the `Method`, `Path`, and `Logic` keys at a minimum.

.PARAMETER ResponseContentType
    Specifies the response type(s) for the route. Valid values are 'application/json' , 'application/xml', 'application/yaml'.
    You can specify multiple types. The default is 'application/json'.

.PARAMETER Timeout
    Defines the timeout period for the asynchronous task in seconds.
    The default value is 28800 (8 hours).
    -1 indicating no timeout.

.PARAMETER IdGenerator
    A custom ScriptBlock to generate a random unique Ids for asynchronous route tasks. The default
    is '{ return New-PodeGuid }'.

.PARAMETER PassThru
    If specified, the function returns the route information after processing.

.PARAMETER MaxRunspaces
    The maximum number of Runspaces that can exist in this route. The default is 2.

.PARAMETER MinRunspaces
    The minimum number of Runspaces that exist in this route. The default is 1.

.PARAMETER NotCancellable
    The async route task cannot be forcefully terminated

.OUTPUTS
    [hashtable[]]

.EXAMPLE
    # Using ArgumentList
    Add-PodeRoute -PassThru -Method Put -Path '/asyncParam' -ScriptBlock {
    param($sleepTime2, $Message)
    Write-PodeHost "sleepTime2=$sleepTime2"
    Write-PodeHost "Message=$Message"
    for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep $sleepTime2
    }
    return @{ InnerValue = $Message }
    } -ArgumentList @{sleepTime2 = 2; Message = 'coming as argument' } | Set-PodeAsyncRoute -ResponseType JSON, XML

.EXAMPLE
    # Using $using variables
    $uSleepTime = 5
    $uMessage = 'coming from using'

    Add-PodeRoute -PassThru -Method Put -Path '/asyncUsing' -ScriptBlock {
    Write-PodeHost "sleepTime=$($using:uSleepTime)"
    Write-PodeHost "Message=$($using:uMessage)"
    Start-Sleep $using:uSleepTime
    return @{ InnerValue = $using:uMessage }
    } | Set-PodeAsyncRoute

#>
function Set-PodeAsyncRoute {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        $Route,

        [Parameter()]
        [string[]]
        [ValidateSet('application/json' , 'application/xml', 'application/yaml')]
        $ResponseContentType = 'application/json',

        [Parameter()]
        [int]
        $Timeout = 28800,

        [Parameter()]
        [scriptblock]
        $IdGenerator,

        [Parameter()]
        [switch]
        $PassThru,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]
        $MaxRunspaces = 2,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]
        $MinRunspaces = 1,

        [Parameter()]
        [switch]
        $NotCancellable

    )
    Begin {

        # Initialize an array to hold piped-in values
        $pipelineValue = @()

        # Start the housekeeper for async routes
        Start-PodeAsyncRoutesHousekeeper

    }

    process {
        # Add the current piped-in value to the array
        $pipelineValue += $_
    }

    End {
        # Set Route to the array of values if multiple values are piped in
        if ($pipelineValue.Count -gt 1) {
            $Route = $pipelineValue
        }

        if ($null -eq $Route) {
            # The parameter 'Route' cannot be null
            throw ($PodeLocale.routeParameterCannotBeNullExceptionMessage)
        }

        foreach ($r in $Route) {
            # Check if the route is already marked as an Async Route
            if ( $r.IsAsync) {
                # The function cannot be invoked multiple times for the same route
                throw ($PodeLocale.functionCannotBeInvokedMultipleTimesExceptionMessage -f $MyInvocation.MyCommand.Name, $r.Path)
            }

            # Validates $r.Logic for disallowed Pode commands
            Test-PodeAsyncRouteScriptblockInvalidCommand -ScriptBlock $r.Logic

            # Set the Route as Async
            $r.IsAsync = $true

            # Assing an unique Id to the async route
            if ($r.Endpoint.Name) { $asyncRouteId = "$($r.Endpoint.Name):[$($r.method)]$($r.Path)" } else { $asyncRouteId = "[$($r.method)]$($r.Path)" }

            # Assign the Id generator
            if ($IdGenerator) {
                $asyncRouteTaskIdGenerator = $IdGenerator
            }
            else {
                $asyncRouteTaskIdGenerator = { return (New-PodeGuid) }
            }

            # Store the route's async route task definition in Pode context
            $r.Async = @{
                AsyncRouteId              = $asyncRouteId
                Script                    = Get-PodeAsyncRouteScriptblock -ScriptBlock $r.Logic
                UsingVariables            = $r.UsingVariables
                Arguments                 = (Protect-PodeValue -Value $r.Arguments -Default @{})
                CallbackSettings          = $null
                Cancellable               = !($NotCancellable.IsPresent)
                MinRunspaces              = $MinRunspaces
                MaxRunspaces              = $MaxRunspaces
                Timeout                   = $Timeout
                Permission                = @{}
                AsyncRouteTaskIdGenerator = $asyncRouteTaskIdGenerator
            }

            #Set thread count
            $PodeContext.Threads.AsyncRoutes += $MaxRunspaces
            if (! $PodeContext.RunspacePools.ContainsKey($asyncRouteId)) {
                $PodeContext.RunspacePools[$asyncRouteId] = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

                $PodeContext.RunspacePools[$asyncRouteId]['Pool'] = New-PodeRunspacePoolNetWrapper -MinRunspaces $MinRunspaces -MaxRunspaces $MaxRunspaces -RunspaceState $PodeContext.RunspaceState
                $PodeContext.RunspacePools[$asyncRouteId]['State'] = 'Waiting'
            }

            # Replace the Route logic with this that allow to execute the original logic asynchronously
            $r.logic = Get-PodeAsyncRouteSetScriptBlock

            # Set arguments and clear using variables
            $r.Arguments = @()
            $r.UsingVariables = $null

            # Add OpenAPI documentation if not excluded
            if ( $r.OpenApi.Swagger) {
                $oaName = Get-PodeAsyncRouteOAName -Tag $r.OpenApi.DefinitionTag -ForEachOADefinition
                foreach ($key in $oaName.Keys) {
                    Add-PodeAsyncRouteComponentSchema -Name $oaName[$key].oATypeName -DefinitionTag $key
                    $r |
                        Add-PodeOAResponse -StatusCode 200 -Description 'Successful operation' `
                            -DefinitionTag $key `
                            -Content (New-PodeOAContentMediaType -MediaType $ResponseContentType  -Content $oaName[$key].OATypeName )
                }
            }

        }

        # Return the route information if PassThru is specified
        if ($PassThru) {
            return $Route
        }
    }
}

<#
.SYNOPSIS
    Adds a Server-Sent Events (SSE) route to an existing Pode async route.

.DESCRIPTION
    The `Add-PodeAsyncRouteSse` function registers a new SSE route associated with an existing Pode async route.
    This allows the server to push updates to the client for the specified route.
    The function accepts a hashtable array of routes and sets up the SSE route for each. The response content type can be specified, and you can choose to pass through the modified route object with the `-PassThru` switch.

    The function also ensures that the specified routes are marked as async routes. If a route is not marked as async, an exception will be thrown.

.PARAMETER Route
    A hashtable array representing the route(s) to which the SSE route will be added.
    This parameter is mandatory and supports pipeline input. Each route must be marked as an async route, or an exception will be thrown.

.PARAMETER PassThru
    If specified, the function will return the route object after adding the SSE route.

.PARAMETER SseGroup
    Specifies the group for the SSE connection. If not provided, the group will be set to the path of the route.

.PARAMETER SendResult
    If specified, sends the result upon completion of the async operation.

.OUTPUTS
    Hashtable[]

.NOTES
    The function creates a new route with the `_events` suffix appended to the original route's path.
    The new route handles SSE connections and manages the async results from the original route.

    If the route is not marked as an async route, an exception will be thrown.

.EXAMPLE
    Add-PodeRoute -PassThru -Method Get -Path '/events' -ScriptBlock {
        return @{'message' = 'Done' }
    } | Set-PodeAsyncRoute -ResponseContentType 'application/json' -MaxRunspaces 2 -PassThru  |
        Add-PodeAsyncRouteSse -SseGroup 'Test events'

    This example demonstrates creating a new GET route at the path '/events' and setting it as an async route with a maximum of 2 runspaces. The async route is enabled for Server-Sent Events (SSE) and is grouped under 'Test events'.
    The `Add-PodeAsyncRouteSse` function is then used to add an SSE route to the async route, ensuring that updates from the server are pushed to the client.
#>
function Add-PodeAsyncRouteSse {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        $Route,

        [Parameter()]
        [switch]
        $PassThru,

        [Parameter()]
        [string]
        $SseGroup,

        [Parameter()]
        [switch]
        $SendResult
    )

    Begin {
        # Initialize an array to store piped-in routes
        $pipelineValue = @()

        # Define the SSE script block to handle client-server communication over SSE
        $sseScriptBlock = {
            param($SseGroup, $SendResult)
            $id = $WebEvent.Query['Id']  # Capture the async operation ID from the query string

            # Determine the SSE group to use, fallback to the route path if none specified
            if ([string]::IsNullOrEmpty($SseGroup)) {
                ConvertTo-PodeSseConnection -Name $webEvent.Route.Path -Scope Local -Group $SseGroup -AsyncRouteTaskId $id
            }
            else {
                ConvertTo-PodeSseConnection -Name $webEvent.Route.Path -Scope Local -AsyncRouteTaskId $id
            }

            # Check if the process for the async route exists
            if (!$PodeContext.AsyncRoutes.Processes.ContainsKey($id)) {
                try {
                    # Throw an exception if the process is not found
                    throw ($PodeLocale.asyncIdDoesNotExistExceptionMessage -f $id)
                }
                catch {
                    # Log the error and exit
                    $_ | Write-PodeErrorLog
                    return
                }
            }
            $process = $PodeContext.AsyncRoutes.Processes[$Id]  # Retrieve the async process by ID

            # Initialize an SSE dictionary for the event
            $webEventSse = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($key in $WebEvent['Sse'].Keys) {
                $webEventSse[$key] = $WebEvent.Sse[$key]  # Copy SSE data
            }
            $process.WebEvent['Sse'] = $webEventSse  # Store the SSE data in the process object

            # Set the initial state of the SSE process to 'Waiting'
            $process['Sse']['State'] = 'Waiting'

            # Wait until the async runspace is completed
            while (!$process['Runspace'].Handler.IsCompleted) {
                start-sleep 1
            }

            try {
                # Handle the completion of the async operation based on its state
                switch ($process['State']) {
                    'Failed' {
                        # Send an SSE event if the process failed
                        $null = Send-PodeSseEvent -FromEvent -Data @{ State = $process['State']; Error = $process['Error'] } -EventType 'pode.taskCompleted'
                    }
                    'Completed' {
                        # Send the result or a generic completion message if successful
                        if ($process['Result'] -and $SendResult) {
                            $null = Send-PodeSseEvent -FromEvent -Data @{ State = $process['State']; Result = $process['Result'] } -EventType 'pode.taskCompleted'
                        }
                        else {
                            $null = Send-PodeSseEvent -FromEvent -Data @{ State = 'Completed' } -EventType 'pode.taskCompleted'
                        }
                    }
                    'Aborted' {
                        # Handle aborted async operations
                        $null = Send-PodeSseEvent -FromEvent -Data @{ State = $process['State']; Error = $process['Error'] } -EventType 'pode.taskCompleted'
                    }
                }
                # Mark the SSE process state as completed
                $process['Sse']['State'] = 'Completed'
                start-sleep 1
            }
            catch {
                # Log any errors encountered and set the state to 'Failed'
                $_ | Write-PodeErrorLog
                $process['Sse']['State'] = 'Failed'
            }
        }
    }

    process {
        # Collect the piped-in route(s)
        $pipelineValue += $_
    }

    End {
        # If multiple routes are piped in, assign them to $Route
        if ($pipelineValue.Count -gt 1) {
            $Route = $pipelineValue
        }

        # Throw an error if Route is null
        if ($null -eq $Route) {
            throw ($PodeLocale.routeParameterCannotBeNullExceptionMessage)
        }

        foreach ($r in $Route) {
            # Ensure the route is marked as an Async Route
            if (! $r.IsAsync) {
                throw ($PodeLocale.routeNotMarkedAsAsyncExceptionMessage -f $r.Path)  # Throw error if not async
            }

            # Create the SSE route with the '_events' suffix
            $sseRoute = Add-PodeRoute -PassThru -method Get -Path "$($r.Path)_events" -ArgumentList $SseGroup, $SendResult.IsPresent `
                -ScriptBlock $sseScriptBlock  # The new route handles SSE

            # Store the SSE route information in the async route context
            $r.Async['Sse'] = @{
                Group = $SseGroup
                Name  = "$($r.Path)_events"
                Route = $sseRoute
            }
        }

        # Return the route object if PassThru is specified
        if ($PassThru) {
            return $Route
        }
    }
}

<#
.SYNOPSIS
    Retrieves asynchronous Pode route operations based on specified query conditions.

.DESCRIPTION
    The   Get-PodeAsyncRouteOperationByFilter function acts as a public interface for searching asynchronous Pode route operations.
    It utilizes the Search-PodeAsyncRouteTask function to perform the search based on the specified query conditions.

.PARAMETER Filter
    A hashtable containing the query conditions. Each key in the hashtable represents a field to search on,
    and the value is another hashtable containing 'op' (operator) and 'value' (comparison value).

.PARAMETER Raw
    If specified, returns the raw [System.Collections.Concurrent.ConcurrentDictionary[string, object]] without any formatting.

.EXAMPLE
    $filter = @{
        'State' = @{ 'op' = 'EQ'; 'value' = 'Running' }
        'CreationTime' = @{ 'op' = 'GT'; 'value' = (Get-Date).AddHours(-1) }
    }
    $results =   Get-PodeAsyncRouteOperationByFilter -Filter $filter

    This example retrieves route operations that are in the 'Running' state and were created within the last hour.

.OUTPUTS
    Returns an array of hashtables or [System.Collections.Concurrent.ConcurrentDictionary[string, object]] representing the matched route operations.
#>
function   Get-PodeAsyncRouteOperationByFilter {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]
        $Filter,

        [switch]
        $Raw
    )
    $async = Search-PodeAsyncRouteTask -Query $Filter
    if ($async -is [System.Object[]]) {
        $result = @()
        foreach ($item in $async) {
            $result += Export-PodeAsyncRouteInfo -Raw:$Raw -Async $item
        }
    }
    else {
        $result = Export-PodeAsyncRouteInfo -Raw:$Raw -Async $async
    }
    return $result
}

<#
.SYNOPSIS
    Retrieves and filters async routes from Pode's async route context.

.DESCRIPTION
    The `Get-PodeAsyncRouteOperation` function allows you to filter Pode async routes based on the `Id` and `AsyncRouteId` properties.
    If either `Id` or `AsyncRouteId` is not specified (or `$null`), those fields will not be used for filtering.
    The filtered results can be optionally exported in raw format using the `-Raw` switch.

.PARAMETER Id
    The unique identifier of the async route to filter on.
    If not specified or `$null`, this parameter is ignored.

.PARAMETER AsyncRouteId
    The name of the async route to filter on.
    If not specified or `$null`, this parameter is ignored.

.PARAMETER Raw
    A switch that, if specified, exports the results in raw format.

.EXAMPLE
    Get-PodeAsyncRouteOperation -Id "12345" -Raw

    Retrieves the async route with the Id "12345" and exports it in raw format.

.EXAMPLE
    Get-PodeAsyncRouteOperation -Name "RouteName"

    Retrieves the async routes with the name "RouteName".
#>

function Get-PodeAsyncRouteOperation {
    param (
        [Parameter()]
        [string]
        $Id,

        [Parameter()]
        [string]
        $AsyncRouteId,

        [Parameter()]
        [switch]
        $Raw
    )

    # Filter the async routes based on Id and AsyncRouteId
    if (![string]::IsNullOrEmpty($Id)) {
        $result = $PodeContext.AsyncRoutes.Processes[$Id]
    }
    elseif (! [string]::IsNullOrEmpty($AsyncRouteId)) {
        foreach ($key in $PodeContext.AsyncRoutes.Processes.Keys) {
            if ($PodeContext.AsyncRoutes.Processes[$key]['AsyncRouteId'] -ieq $AsyncRouteId) {
                $result = $PodeContext.AsyncRoutes.Processes[$key]
                break
            }
        }
    }
    else {
        $result = $PodeContext.AsyncRoutes.Processes
    }

    if ($null -eq $result) {
        return $null
    }

    # If the -Raw switch is specified, return the filtered results directly
    if ($Raw) {
        return $result
    }

    if ([string]::IsNullOrEmpty($Id) -and [string]::IsNullOrEmpty($AsyncRouteId)) {
        # Otherwise, process each item in the filtered results through Export-PodeAsyncRouteInfo
        $export = @()
        foreach ($item in $result.Values) {
            $export += Export-PodeAsyncRouteInfo  -Async $item
        }
    }
    else {
        $export = Export-PodeAsyncRouteInfo  -Async $result
    }
    # Return the processed export result
    return $export
}


<#
.SYNOPSIS
    Aborts a specific asynchronous Pode route operation by its Id.

.DESCRIPTION
    The Stop-PodeAsyncRouteOperation function stops an asynchronous Pode route operation based on the provided Id.
    It sets the operation's state to 'Aborted', records an error message, and marks the completion time.
    The function then disposes of the associated runspace pipeline and calls Complete-PodeAsyncRouteOperation to finalize the operation.
    If the operation does not exist, it throws an exception with an appropriate error message.

.PARAMETER Id
    A string representing the Id (typically a UUID) of the asynchronous route operation to abort. This parameter is mandatory.

.PARAMETER Raw
    If specified, returns the raw [System.Collections.Concurrent.ConcurrentDictionary[string, object]] without any formatting.

.EXAMPLE
    $operationId = '123e4567-e89b-12d3-a456-426614174000'
    $operationDetails = Stop-PodeAsyncRouteOperation -Id $operationId

    This example aborts the asynchronous route operation with the Id '123e4567-e89b-12d3-a456-426614174000' and retrieves the updated operation details.

.OUTPUTS
    Returns a hashtable representing the detailed information of the aborted asynchronous route operation.
#>
function Stop-PodeAsyncRouteOperation {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Id,

        [switch]
        $Raw
    )
    if ($PodeContext.AsyncRoutes.Processes.ContainsKey($Id )) {
        $async = $PodeContext.AsyncRoutes.Processes[$Id]
        $async['State'] = 'Aborted'
        $async['Error'] = 'Aborted by System'
        $async['CompletedTime'] = [datetime]::UtcNow
        $async['Runspace'].Pipeline.Dispose()
        Complete-PodeAsyncRouteOperation -AsyncProcess $async
        return  Export-PodeAsyncRouteInfo -Async $async -Raw:$Raw
    }
    throw ($PodeLocale.asyncRouteOperationDoesNotExistExceptionMessage -f $Id)
}

<#
.SYNOPSIS
    Checks if a specific asynchronous Pode route operation exists by its Id.

.DESCRIPTION
    The Test-PodeAsyncRouteOperation function checks the Pode context to determine if an asynchronous route operation with the specified Id exists.
    It returns a boolean value indicating whether the operation is present in the Pode context.

.PARAMETER Id
    A string representing the Id (typically a UUID) of the asynchronous route operation to check. This parameter is mandatory.

.EXAMPLE
    $operationId = '123e4567-e89b-12d3-a456-426614174000'
    $exists = Test-PodeAsyncRouteOperation -Id $operationId

    This example checks if the asynchronous route operation with the Id '123e4567-e89b-12d3-a456-426614174000' exists and returns true or false.

.OUTPUTS
    Returns a boolean value:
    - $true if the asynchronous route operation exists.
    - $false if the asynchronous route operation does not exist.
#>
function Test-PodeAsyncRouteOperation {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Id
    )
    return ($PodeContext.AsyncRoutes.Processes.ContainsKey($Id ))
}


<#
.SYNOPSIS
    Manages the progress of an asynchronous task within Pode routes.

.DESCRIPTION
    This function updates the progress of an asynchronous task in Pode. It supports different parameter sets:
    - StartEnd: Defines progress between a start and end value.
    - Tick: Increments the progress by a predefined tick value.
    - TimeBased: Updates progress based on a specified duration and interval.
    - SetValue: Allows setting the progress to a specific value.

.PARAMETER Start
    The start value for progress calculation (used in StartEnd parameter set).

.PARAMETER End
    The end value for progress calculation (used in StartEnd parameter set).

.PARAMETER Steps
    The number of steps between the start and end values (used in StartEnd parameter set).

.PARAMETER MaxProgress
    The maximum progress value (default is 100).

.PARAMETER Tick
    A switch to increment the progress by the predefined tick value.

.PARAMETER UseDecimalProgress
    A switch to use decimal values for progress.

.PARAMETER IntervalSeconds
    The interval in seconds for time-based progress updates (default is 5 seconds).

.PARAMETER DurationSeconds
    The total duration in seconds for time-based progress updates.

.PARAMETER Value
    The value to set the progress to (used in SetValue parameter set).

.EXAMPLE
    Set-PodeAsyncRouteProgress -Start 0 -End 100 -Steps 10 -MaxProgress 100

.EXAMPLE
    Set-PodeAsyncRouteProgress -Tick

.EXAMPLE
    Set-PodeAsyncRouteProgress -IntervalSeconds 5 -DurationSeconds 300 -MaxProgress 100

.EXAMPLE
    Set-PodeAsyncRouteProgress -Value 50

.NOTES
    This function can only be used inside an Async Route Scriptblock in Pode.
#>
function Set-PodeAsyncRouteProgress {
    [CmdletBinding(DefaultParameterSetName = 'StartEnd')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'StartEnd')]
        [double] $Start,

        [Parameter(Mandatory = $true, ParameterSetName = 'StartEnd')]
        [double] $End,

        [Parameter(ParameterSetName = 'StartEnd')]
        [double] $Steps = 1,

        [Parameter(ParameterSetName = 'TimeBased')]
        [Parameter(ParameterSetName = 'StartEnd')]
        [ValidateRange(1, 100)]
        [double] $MaxProgress = 100,

        [Parameter(Mandatory = $true, ParameterSetName = 'Tick')]
        [switch] $Tick,

        [Parameter(ParameterSetName = 'TimeBased')]
        [Parameter(ParameterSetName = 'StartEnd')]
        [Parameter(ParameterSetName = 'SetValue')]
        [switch] $UseDecimalProgress,

        [Parameter(ParameterSetName = 'TimeBased')]
        [int] $IntervalSeconds = 5,

        [Parameter(Mandatory = $true, ParameterSetName = 'TimeBased')]
        [int] $DurationSeconds,

        [Parameter(Mandatory = $true, ParameterSetName = 'SetValue')]
        [double] $Value
    )

    # Ensure the function is used inside an async route
    if (!$___async___id___) {
        # Throw an error if not in an async route context
        throw $PodeLocale.setPodeAsyncProgressExceptionMessage
    }
    # Retrieve the async process using the task ID
    $process = $PodeContext.AsyncRoutes.Processes[$___async___id___]

    # Initialize progress if not set yet and not using 'Tick' or 'SetValue' modes
    if ($PSCmdlet.ParameterSetName -ne 'Tick' -and $PSCmdlet.ParameterSetName -ne 'SetValue') {
        if (!$process.ContainsKey('Progress')) {
            # Initialize progress to 0, using a decimal or integer based on the presence of the switch
            if ($UseDecimalProgress.IsPresent) {
                $process['Progress'] = [double] 0
            }
            else {
                $process['Progress'] = [int] 0
            }
        }

        # Throw an error if MaxProgress is less than the current progress
        if ($MaxProgress -le $process['Progress']) {
            throw $PodeLocale.progressLimitLowerThanCurrentExceptionMessage
        }
    }

    # Handle progress updates based on the parameter set
    switch ($PSCmdlet.ParameterSetName) {
        'StartEnd' {
            # Calculate total ticks and tick-to-progress ratio
            $totalTicks = [math]::ceiling(($End - $Start) / $Steps)
            if ($process['Progress'] -is [double]) {
                $process['TickToProgress'] = ($MaxProgress - $process['Progress']) / $totalTicks
            }
            else {
                $process['TickToProgress'] = [Math]::Floor(($MaxProgress - $process['Progress']) / $totalTicks)
            }
        }
        'Tick' {
            # Increment progress by the TickToProgress value
            $process['Progress'] = $process['Progress'] + $process['TickToProgress']

            # Ensure progress does not exceed MaxProgress
            if ($process['Progress'] -ge $MaxProgress) {
                if ($process['Progress'] -is [double]) {
                    $process['Progress'] = $MaxProgress - 0.01
                }
                else {
                    $process['Progress'] = $MaxProgress - 1
                }
            }
        }
        'TimeBased' {
            # Calculate the total number of ticks and the progress increment per tick
            $totalTicks = [math]::ceiling($DurationSeconds / $IntervalSeconds)
            if ($process['Progress'] -is [double]) {
                $process['TickToProgress'] = ($MaxProgress - $process['Progress']) / $totalTicks
            }
            else {
                $process['TickToProgress'] = [Math]::Floor(($MaxProgress - $process['Progress']) / $totalTicks)
            }

            # Initialize a timer for time-based progress updates
            $process['eventName'] = "TimerEvent_$___async___id___"
            $process['Timer'] = [System.Timers.Timer]::new()
            $process['Timer'].Interval = $IntervalSeconds * 1000
            # Register an event for the timer to handle periodic progress updates
            $null = Register-ObjectEvent -InputObject $process['Timer'] -EventName Elapsed -SourceIdentifier  $process['eventName'] `
                -MessageData @{AsyncResult = $process; MaxProgress = $MaxProgress } -Action {
                $process = $Event.MessageData.AsyncResult
                $MaxProgress = $Event.MessageData.MaxProgress
                # Increment progress by the TickToProgress value
                $process['Progress'] = $process['Progress'] + $process['TickToProgress']

                # Check if progress exceeds MaxProgress and stop the timer if so
                if ($process['Progress'] -gt $MaxProgress) {
                    # Close and dispose of the timer when max progress is reached
                    Close-PodeAsyncRouteTimer -Operation  $process

                    if ($process['Progress'] -is [double]) {
                        $process['Progress'] = $MaxProgress - 0.01
                    }
                    else {
                        $process['Progress'] = $MaxProgress - 1
                    }
                }

                # If SSE is available, send the current progress via SSE
                if ($process.ContainsKey('Sse')) {
                    $null = Send-PodeSseEvent -FromEvent -Data $process['Progress'] -EventType 'pode.progress'
                }
            }
            # Enable the timer to start the progress updates
            $process['Timer'].Enabled = $true
        }
        'SetValue' {
            # Directly set the progress value, using decimal or integer based on the context
            if ($UseDecimalProgress.IsPresent -or ($Value % 1 -ne 0)) {
                $process['Progress'] = $Value
            }
            else {
                $process['Progress'] = [int]$Value
            }
        }
    }

    # If SSE is enabled, send progress updates via SSE
    if ($WebEvent.Sse) {
        $null = Send-PodeSseEvent -FromEvent -Data $process['Progress'] -EventType 'pode.progress'
    }
}

<#
.SYNOPSIS
    Retrieves the current progress of an asynchronous route in Pode.

.DESCRIPTION
    The `Get-PodeAsyncRouteProgress` function returns the current progress of an asynchronous route in Pode.
    It retrieves the progress based on the asynchronous route ID (`$___async___id___`).
    If called outside of an asynchronous route script block, an error is thrown.

.EXAMPLE
    # Example usage inside an async route scriptblock
    Add-PodeRoute -PassThru -Method Get '/process' {
        # Perform some work and update progress
        Set-PodeAsyncCounter -Value 40
        # Retrieve the current progress
        $progress = Get-PodeAsyncRouteProgress
        Write-PodeHost "Current Progress: $progress"
    } |Set-PodeAsyncRoute -ResponseContentType 'application/json'

    .NOTES
    This function should only be used inside an asynchronous route scriptblock.

#>
function Get-PodeAsyncRouteProgress {
    if ($___async___id___) {
        return $PodeContext.AsyncRoutes.Processes[$___async___id___]['Progress']
    }
    else {
        throw $PodeLocale.setPodeAsyncProgressExceptionMessage
    }
}


<#
.SYNOPSIS
    Sets the schema names for asynchronous Pode route operations.

.DESCRIPTION
    The Set-PodeAsyncRouteOASchemaName function is designed to configure schema names for asynchronous Pode route operations in OpenAPI documentation.
    It stores the specified type names and parameter names for OpenAPI documentation in the Pode context server's OpenAPI definitions.

.PARAMETER OATypeName
    The type name for OpenAPI documentation. The default is 'AsyncRouteTask'. This parameter is only used
    if the route is included in OpenAPI documentation.

.PARAMETER TaskIdName
    The name of the parameter that contains the task Id. The default is 'id'.

.PARAMETER QueryRequestName
    The name of the Pode task query request in the OpenAPI schema. Defaults to 'AsyncRouteTaskQuery'.

.PARAMETER QueryParameterName
    The name of the query parameter in the OpenAPI schema. Defaults to 'AsyncRouteTaskQueryParameter'.

.PARAMETER OADefinitionTag
    The tags associated with the OpenAPI definitions that need to be updated.
#>
function Set-PodeAsyncRouteOASchemaName {
    param(
        [string]
        $OATypeName,

        [Parameter()]
        [string]
        $TaskIdName,

        [Parameter()]
        [string]
        $QueryRequestName,

        [Parameter()]
        [string]
        $QueryParameterName,

        [Parameter()]
        [string[]]
        $OADefinitionTag
    )
    # Validates the provided OpenAPI definition tags using a custom function.
    $DefinitionTag = Test-PodeOADefinitionTag -Tag $OADefinitionTag

    # Iterates over each valid OpenAPI definition tag.
    foreach ($tag in $DefinitionTag) {

        # If $OATypeName is not provided, fetch it from the corresponding OpenAPI definition's hidden components.
        if (! $OATypeName) {
            $OATypeName = $PodeContext.Server.OpenApi.Definitions[$tag].hiddenComponents.AsyncRoute.OATypeName
        }

        # If $TaskIdName is not provided, fetch it from the corresponding OpenAPI definition's hidden components.
        if (! $TaskIdName) {
            $TaskIdName = $PodeContext.Server.OpenApi.Definitions[$tag].hiddenComponents.AsyncRoute.TaskIdName
        }

        # If $QueryRequestName is not provided, fetch it from the corresponding OpenAPI definition's hidden components.
        if (!$QueryRequestName) {
            $QueryRequestName = $PodeContext.Server.OpenApi.Definitions[$tag].hiddenComponents.AsyncRoute.QueryRequestName
        }

        # If $QueryParameterName is not provided, fetch it from the corresponding OpenAPI definition's hidden components.
        if (!$QueryParameterName) {
            $QueryParameterName = $PodeContext.Server.OpenApi.Definitions[$tag].hiddenComponents.AsyncRoute.QueryParameterName
        }

        # Update the hiddenComponents.AsyncRoute property of the OpenAPI definition
        # with the schema details fetched or provided, by calling Get-PodeAsyncRouteOASchemaNameInternal function.
        $PodeContext.Server.OpenApi.Definitions[$tag].hiddenComponents.AsyncRoute = Get-PodeAsyncRouteOASchemaNameInternal `
            -OATypeName $OATypeName -TaskIdName $TaskIdName `
            -QueryRequestName $QueryRequestName -QueryParameterName $QueryParameterName
    }
}

<#
.SYNOPSIS
    Sets the field name that uniquely identifies a user for async routes in Pode.

.DESCRIPTION
    The `Set-PodeAsyncRouteUserIdentifierField` function allows you to specify a custom field name
    that represents the user identifier in async routes within Pode. This field name is stored in the Pode context
    and is used throughout the application to identify users in async operations.

.PARAMETER UserIdentifierField
    The name of the field that uniquely identifies a user. This parameter is mandatory.
    By default, the user identifier field is 'Id'.

.EXAMPLE
    Set-PodeAsyncRouteUserIdentifierField -UserIdentifierField 'UserId'

    This example sets the user identifier field to 'UserId', overriding the default 'Id'.

.NOTES
    The user identifier field is stored in `$PodeContext.AsyncRoutes.UserFieldIdentifier`. The default value is 'Id'.
#>
function Set-PodeAsyncRouteUserIdentifierField {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $UserIdentifierField
    )
    $PodeContext.AsyncRoutes.UserFieldIdentifier = $UserIdentifierField
}

<#
.SYNOPSIS
    Retrieves the field name that uniquely identifies a user for async routes in Pode.

.DESCRIPTION
    The `Get-PodeAsyncRouteUserIdentifierField` function returns the current field name
    used to uniquely identify users in async routes within Pode. This field name is stored in the Pode context.

.PARAMETER UserIdentifierField
    The name of the field that uniquely identifies a user. This parameter is mandatory.
    By default, the user identifier field is 'Id'.

.EXAMPLE
    $userField = Get-PodeAsyncRouteUserIdentifierField

    This example retrieves the current user identifier field, which by default is 'Id'.

.NOTES
    The user identifier field is retrieved from `$PodeContext.AsyncRoutes.UserFieldIdentifier`. The default value is 'Id'.
#>
function Get-PodeAsyncRouteUserIdentifierField {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $UserIdentifierField
    )
    return $PodeContext.AsyncRoutes.UserFieldIdentifier
}