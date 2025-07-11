
# Security

All async route operations are subject to Pode security, ensuring that any task operation complies with defined authentication and authorization rules.

> **⚠ Important:**
> All security checks are performed using the user identifier field specified by the `Set-PodeAsyncRouteUserIdentifierField` function. If this field is not explicitly set, the default field `Id` is used.

#### Permissions
 You can specify read and write permissions for each route. This can include specific users, groups, roles, and scopes.
  - **Read Access**: Define which users, groups, roles, and scopes have read access. This means that the authenticated user that fits the permission can query the task status.
  - **Write Access**: Define which users, groups, roles, and scopes have write access. This means that the authenticated user that fits the permission can stop the task.

#### Permission Object Structure

The permission object defines who can perform read or write operations on an async route. The object `Permission` has this structure:

```powershell
@{
    Read  = @{
        Groups = @()
        Roles  = @()
        Scopes = @()
        Users  = @()
    }
    Write = @{
        Groups = @()
        Roles  = @()
        Scopes = @()
        Users  = @()
    }
}
```

- **Read**: Controls who can query the status of the async route task.
- **Write**: Controls who can stop the async route task.

An async route task generated by a route without any specified permissions will have read and write permissions granted to anyone, including anonymous users.

By default, the owner has read and write privileges on the async route task.

#### Example Usage

```powershell
New-PodeAuthScheme -Basic -Realm 'Pode Example Page' | Add-PodeAuth -Name 'Validate' -Sessionless -ScriptBlock {
    param($username, $password)

    # here you'd check a real user storage, this is just for example
    if ($username -eq 'morty' -and $password -eq 'pickle') {
        return @{
            User = @{
                Username = 'morty'
                ID       = 'M0R7Y302'
                Name     = 'Morty'
                Type     = 'Human'
                Groups   = @('Support')
            }
        }
    }
    elseif ($username -eq 'mindy' -and $password -eq 'pickle') {
        return @{
            User = @{
                Username = 'mindy'
                ID       = 'MINY321'
                Name     = 'Mindy'
                Type     = 'Alien'
                Groups   = @('Developer')
            }
        }

        return @{ Message = 'Invalid details supplied' }
    }
}

Add-PodeRoute -PassThru -Method Put -Path '/asyncState' -Authentication 'Validate' -Group 'Support' -ScriptBlock {
    $data = Get-PodeState -Name 'data'
    Write-PodeHost 'data:'
    Write-PodeHost $data -Explode -ShowType
    Start-Sleep $data.sleepTime
    return @{ InnerValue = $data.Message }
} | Set-PodeAsyncRoute -PassThru \`
    -ResponseContentType 'application/json', 'application/yaml' -Timeout 300 |
    Set-PodeAsyncRoutePermission -Type Read -Groups 'Developer'
```

#### Explanation

1. **Authentication Scheme**: The `New-PodeAuthScheme` creates a basic authentication scheme, and `Add-PodeAuth` adds the authentication named `Validate` with a script block that validates the user credentials.
    - If the credentials match, the user information is returned.
    - If the credentials do not match, an error message is returned.

2. **Route Definition**: The `Add-PodeRoute` defines a route at `/asyncState` that requires authentication using the `Validate` scheme and is restricted to users in the `Support` group.
    - The route retrieves some state data and writes it to the host, simulates some work by sleeping, and then returns the inner value of the state data.

3. **Setting Async Route**: The `Set-PodeAsyncRoute` processes the route to make it asynchronous.
    - `-ResponseContentType` specifies the response formats as JSON and YAML.
    - `-Timeout 300` sets a timeout of 300 seconds for the async route task.
4. **Setting Async Route Task Permissions**: The `Set-PodeAsyncRoutePermission` sets the read permission for users in the `Developer` group.

    - By default only users in the `Developer` group can query the status of the task, and only users with write access can stop the task.
    - The owner has read and write privileges on the async route task.

This setup ensures that the route is secured with authentication, and permissions are properly managed to control who can query or stop the async route task.