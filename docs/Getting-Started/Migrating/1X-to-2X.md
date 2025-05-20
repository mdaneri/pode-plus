# From v1.X to v2.X

This is a brief guide on migrating from Pode v1.X to Pode v2.X.

In Pode v2.X the Server got the biggest overhaul with the dropping of HttpListener.

## Server

If you were previously specifying `-Type Pode` on your [`Start-PodeServer`](../../../Functions/Core/Start-PodeServer), then you no longer need to - all servers now default to using Pode's new .NET Core socket listener.

Furthermore, the `-Type` parameter has been renamed to `-ServerlessType`.

### Configuration

Settings that use to be under `Server > Pode` are now just under `Server`. For example, SSL protocols have moved from:

```powershell
@{
    Server = @{
        Pode=  @{
            Ssl= @{
                Protocols = @('TLS', 'TLS11', 'TLS12')
            }
        }
    }
}
```

to:

```powershell
@{
    Server = @{
        Ssl= @{
            Protocols = @('TLS', 'TLS11', 'TLS12')
        }
    }
}
```

## Web Event

Originally the Web Event object was the first parameter supplied to the ScriptBlocks of Routes, Middleware, and Endware. These already all had access to the main `$WebEvent` object, including Authentication, without the need to supply it as a parameter.

In 2.0, this first event parameter has been dropped, and you should now use the main `$WebEvent` object.

So from the following:
```powershell
Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
    param($e)
    Write-PodeJsonResponse -Value @{ Result = $e.Data['value']}
}
```

To this:
```powershell
Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
    Write-PodeJsonResponse -Value @{ Result = $WebEvent.Data['value']}
}
```

This also applies to Middleware, Endware, and Authentication.

## Endpoints

With the dropping of HttpListener, the `-Certificate` parameter is now the old `-CertificateFile` parameter. The `-RawCertificate` parameter has been renamed, and it now called `-X509Certificate`.

The `-CertificateThumbprint` parameter remains the same, and only works on Windows.
The `-Certificate` parameter is now the `-CertificateName` parameter, and also only works on Windows.

There is a new `-Hostname` parameter to specify a hostname for your endpoint. Using `-Address` still works for ease, and the IP for the hostname by default is `127.0.0.1`. If you used a host file/DNS entry for your hostname address, then supplying `-LookupHostname` will source the IP for your hostname appropriately.

## Authentication

Authentication underwent a hefty change in 2.0, with `Get-PodeAuthMiddleware` being removed.

First, `New-PodeAuthType` has been renamed to [`New-PodeAuthScheme`](../../../Functions/Authentication/New-PodeAuthScheme) - with its `-Scheme` parameter also being renamed to `-Type`.

The old `-AutoLogin` (now just `-Login`), and `-Logout` switches, from `Get-PodeAuthMiddleware`, have been moved onto the [`Add-PodeRoute`](../../../Functions/Routes/Add-PodeRoute) function. The [`Add-PodeRoute`](../../../Functions/Routes/Add-PodeRoute) function now also has a new `-Authentication` parameter, which accepts the name supplied to [`Add-PodeAuth`](../../../Functions/Authentication/Add-PodeAuth); this will automatically setup authentication middleware for that route.

The old `-Sessionless`, `-FailureUrl`, `-FailureMessage` and `-SuccessUrl` parameters, from `Get-PodeAuthMiddleware`, have all been moved onto the [`Add-PodeAuth`](../../../Functions/Authentication/Add-PodeAuth) function.

The old `-EnableFlash` switch has been removed (it's just enabled by default if sessions are enabled).

There's also a new [`Add-PodeAuthMiddleware`](../../../Functions/Authentication/Add-PodeAuthMiddleware) function, which will let you setup global authentication middleware.

Furthermore, the OpenAPI functions for `Set-PodeOAAuth` and `Set-PodeOAGlobalAuth` have been removed. The new [`Add-PodeAuthMiddleware`](../../../Functions/Authentication/Add-PodeAuthMiddleware) function and `-Authentication` parameter on [`Add-PodeRoute`](../../../Functions/Routes/Add-PodeRoute) set these up for you automatically in OpenAPI.

On `Add-PodeAuth`, `Add-PodeAuthWindowsAd`, and `Add-PodeAuthUserFile` the `-Type` parameter has been renamed to `-Scheme`. If you have always piped `New-PodeAuthScheme` (formally `New-PodeAuthType`) into them, then this won't affect you.

## Endpoint and Protocol

On the following functions:

* `Add-PodeRoute`
* `Add-PodeStaticRoute`
* `Get-PodeRoute`
* `Get-PodeStaticRoute`
* `Remove-PodeRoute`
* `Remove-PodeStaticRoute`

The `-Endpoint` and `-Protocol` parameters have been removed in favour of `-EndpointName`.

Further to this, if no `-Name` is supplied to [`Add-PodeEndpoint`](../../../Functions/Core/Add-PodeEndpoint) then a random GUID is used instead. To get the name back you can use `-PassThru` for the endpoint to be returned.

## Scoping and Auto-Importing

The 2.0 release sees a big change to some scoping issues in Pode, around modules/snapins/functions and variables. For more information, see the new page on [Scoping](../../../Tutorials/Scoping).

### Modules/Snapins

You can now use the normal `Import-Module`, or `Add-PSSnapin`, and Pode will automatically import all loaded modules/snapins into its runspaces:

```powershell
Import-Module SomeModule

Start-PodeServer -ScriptBlock {
    Add-PodeEndpoint -Address localhost -Port 9000 -Protocol Http

    Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
        Use-SomeModuleFunction
    }
}
```

[`Import-PodeModule`](../../../Functions/Utilities/Import-PodeModule) still exists, as it supports the use of local modules in `ps_modules`. The only difference is that the `-Now` switch has been removed, and you can now use `Import-PodeModule` outside of the [`Start-PodeServer`](../../../Functions/Core/Start-PodeServer) block.

[`Import-PodeSnapin`](../../../Functions/Utilities/Import-PodeSnapin) also still exists, and has the same differences as `Import-PodeModule` above.

To disable the auto-import, you can do so via the `server.psd1` configuration file. You can also set auto-imported modules to only used exported ones via [`Export-PodeModule`](../../../Functions/AutoImport/Export-PodeModule)/[`Export-PodeSnapin`](../../../Functions/AutoImport/Export-PodeSnapin).

```powershell
@{
    Server = @{
        AutoImport = @{
            Modules = @{
                Enable = $false
                ExportOnly = $true
            }
            Snapins = @{
                Enable = $false
                ExportOnly = $true
            }
        }
    }
}
```

### Functions

Local functions are now automatically imported into Pode's runspaces! This makes it a little simpler to use quick functions in Pode:

```powershell
function Write-HelloResponse
{
    Write-PodeJsonResponse -Value @{ Message = 'Hello!' }
}

Start-PodeServer -ScriptBlock {
    function Write-ByeResponse
    {
        Write-PodeJsonResponse -Value @{ Message = 'Bye!' }
    }

    Add-PodeEndpoint -Address localhost -Port 9000 -Protocol Http

    Add-PodeRoute -Method Get -Path '/hello' -ScriptBlock {
        Write-HelloResponse
    }

    Add-PodeRoute -Method Get -Path '/bye' -ScriptBlock {
        Write-ByeResponse
    }
}
```

If you store Routes/etc in other files, you can also have local functions in these files as well. However, for Pode to import them you must use [`Use-PodeScript`](../../../Functions/Utilities/Use-PodeScript) to dot-source the scripts - this will trigger Pode to scan the file for functions.

To disable the auto-import, you can do so via the `server.psd1` configuration file. You can also set auto-imported modules to only used exported ones via [`Export-PodeFunction`](../../../Functions/AutoImport/Export-PodeFunction).

```powershell
@{
    Server = @{
        AutoImport = @{
            Functions = @{
                Enable = $false
                ExportOnly = $true
            }
        }
    }
}
```

### Variables

You can now define local variables, and use the `$using:` syntax in almost all `-ScriptBlock` parameters, like:

* Routes
* Middleware
* Authentication
* Logging
* Endware
* Timers
* Schedules
* Handlers

This allows you to do something like:

```powershell
$outer_msg = 'Hello, there'

Start-PodeServer -ScriptBlock {
    Add-PodeEndpoint -Address localhost -Port 9000 -Protocol Http

    $inner_msg = 'General Kenobi'

    Add-PodeRoute -Method Get -Path '/random' -ScriptBlock {
        Write-PodeJsonResponse -Value @{ Message = "$($using:outer_msg) ... $($using:inner_msg)" }
    }
}
```

For more information, see the new page on [Scoping](../../../Tutorials/Scoping).

## Test Functions

If you're using any of the following:

* `Test-IsEmpty`
* `Test-IsUnix`
* `Test-IsWindows`
* `Test-IsPSCore`

these have been updated to:

* `Test-PodeIsEmpty`
* `Test-PodeIsUnix`
* `Test-PodeIsWindows`
* `Test-PodeIsPSCore`
