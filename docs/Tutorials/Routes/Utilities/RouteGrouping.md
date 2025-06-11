# Route Grouping

Instead of adding multiple Routes all with the same path, middleware, authentication and other values, you can instead create these Routes in a **Route Group**. This lets you specify a shared base path, middleware, authentication, etc. for multiple Routes.

There are Route groupings for normal Routes, Static Routes, and Signal Routes.

## Routes

You can add a new Route Group using [`Add-PodeRouteGroup`](../../../../Functions/Routes/Add-PodeRouteGroup), and passing any shared details, plus either a `-Routes` scriptblock or a `-FilePath` parameter for the routes to be created within the grouping's scope.

### Defining Routes Inline

For example, the below will add 3 Routes which all share a `/api` base path, some Basic authentication, and some other middleware:

```powershell
$mid = New-PodeMiddleware -ScriptBlock {
    'some middleware being run' | Out-Default
}

Add-PodeRouteGroup -Path '/api' -Authentication Basic -Middleware $mid -Routes {
    Add-PodeRoute -Method Get -Path '/route1' -ScriptBlock {
        Write-PodeJsonResponse -Value @{ ID = 1 }
    }

    Add-PodeRoute -Method Get -Path '/route2' -ScriptBlock {
        Write-PodeJsonResponse -Value @{ ID = 2 }
    }

    Add-PodeRoute -Method Get -Path '/route3' -ScriptBlock {
        Write-PodeJsonResponse -Value @{ ID = 3 }
    }
}
```

When run, you'll have 3 Routes that all require Basic authentication at `/api/route1`, `/api/route2`, and `/api/route3`.

You can still add custom `-Middleware` to the Routes, and they'll be appended to the shared Middleware from the Group. Other parameters, such as `-ContentType` and `-EndpointName`, if supplied, will override the values passed into the Group.

You can also embed groups within groups. The following is the same as the above, except this time the last 2 Routes will be at `/api/inner/route2` and `/api/inner/route3`:

```powershell
$mid = New-PodeMiddleware -ScriptBlock {
    'some middleware being run' | Out-Default
}

Add-PodeRouteGroup -Path '/api' -Authentication Basic -Middleware $mid -Routes {
    Add-PodeRoute -Method Get -Path '/route1' -ScriptBlock {
        Write-PodeJsonResponse -Value @{ ID = 1 }
    }

    Add-PodeRouteGroup -Path '/inner' -Routes {
        Add-PodeRoute -Method Get -Path '/route2' -ScriptBlock {
            Write-PodeJsonResponse -Value @{ ID = 2 }
        }

        Add-PodeRoute -Method Get -Path '/route3' -ScriptBlock {
            Write-PodeJsonResponse -Value @{ ID = 3 }
        }
    }
}
```

### Defining Routes from a File

You can now use the `-FilePath` parameter as an alternative to the `-Routes` scriptblock. This allows you to define your routes in an external `.ps1` file and reference it, keeping your route definitions modular and maintainable.

```powershell
Add-PodeRouteGroup -Path '/api' -Authentication Basic -Middleware $mid -FilePath './routes/api-routes.ps1'
```

Your external `api-routes.ps1` file should contain the same commands you would put inside the `-Routes` scriptblock, for example:

```powershell
# ./routes/api-routes.ps1
Add-PodeRoute -Method Get -Path '/route1' -ScriptBlock {
    Write-PodeJsonResponse -Value @{ ID = 1 }
}
Add-PodeRoute -Method Get -Path '/route2' -ScriptBlock {
    Write-PodeJsonResponse -Value @{ ID = 2 }
}
Add-PodeRoute -Method Get -Path '/route3' -ScriptBlock {
    Write-PodeJsonResponse -Value @{ ID = 3 }
}
```

The file will be executed in the context of the route group, inheriting all shared parameters such as `-Path`, `-Middleware`, and `-Authentication`.

You can use `-FilePath` **or** `-Routes` (but not both at the same time).

---

## Static Routes

The groups for Static Routes work in the same manner as normal Routes, but you'll use [`Add-PodeStaticRouteGroup`](../../../../Functions/Routes/Add-PodeStaticRouteGroup) instead. Both `-Routes` and `-FilePath` are supported:

```powershell
Add-PodeStaticRouteGroup -Path '/assets' -Source './content/assets' -Routes {
    Add-PodeStaticRoute -Path '/images' -Source '/images'
    Add-PodeStaticRoute -Path '/videos' -Source '/videos'
}
```

Or from an external file:

```powershell
Add-PodeStaticRouteGroup -Path '/assets' -Source './content/assets' -FilePath './routes/static-assets.ps1'
```

---

## Signal Routes

Groupings for Signal Routes also work in the same manner, but you'll use [`Add-PodeSignalRouteGroup`](../../../../Functions/Routes/Add-PodeSignalRouteGroup):

```powershell
Add-PodeSignalRouteGroup -Path '/ws' -Routes {
    Add-PodeSignalRoute -Path '/messages1' -ScriptBlock {
        Send-PodeSignal -Value $SignalEvent.Data.Message
    }
    Add-PodeSignalRoute -Path '/messages2' -ScriptBlock {
        Send-PodeSignal -Value $SignalEvent.Data.Message
    }
}
```

Or using a file:

```powershell
Add-PodeSignalRouteGroup -Path '/ws' -FilePath './routes/signal-routes.ps1'
```

---

## Notes

* `-Routes` and `-FilePath` are mutually exclusive: only one may be used per group.
* Any route/group definitions in the referenced file will be evaluated within the scope of the group, inheriting shared parameters and base path.
* Nested route groups can use either inline or file-based definitions.
* If both `-Routes` and `-FilePath` are supplied, an error will be thrown.
