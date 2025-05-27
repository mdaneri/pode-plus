# Body Payloads

The following is an example of using data from a request's payload—i.e., the data in the body of a POST request. To retrieve values from the payload, you can use the `.Data` property on the `$WebEvent` variable in a route's logic.

Alternatively, you can use the `Get-PodeBodyData` function to retrieve the body data, with additional support for deserialization and raw content access.

Depending on the Content-Type supplied, Pode has built-in body-parsing logic for JSON, XML, CSV, and Form data.

This example will get the `userId` and "find" the user, returning the user's data:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Post -Path '/users' -ScriptBlock {
        # get the user
        $user = Get-DummyUser -UserId $WebEvent.Data.userId

        # return the user
        Write-PodeJsonResponse -Value @{
            Username = $user.username
            Age = $user.age
        }
    }
}
```

The following request will invoke the above route:

```powershell
Invoke-WebRequest -Uri 'http://localhost:8080/users' -Method Post -Body '{ "userId": 12345 }' -ContentType 'application/json'
```

!!! important
The `ContentType` is required as it informs Pode on how to parse the request's payload. For example, if the content type is `application/json`, Pode will attempt to parse the body of the request as JSON—converting it to a hashtable.

!!! important
On PowerShell 5, referencing JSON data on `$WebEvent.Data` must be done as `$WebEvent.Data.userId`. This also works in PowerShell 6+, but you can also use `$WebEvent.Data['userId']` on PowerShell 6+.

---

### Using Get-PodeBodyData

Alternatively, you can use the `Get-PodeBodyData` function to retrieve the body data. This function works similarly to the `.Data` property on `$WebEvent`, but offers additional options for raw access and deserialization.

Here is the same example using `Get-PodeBodyData`:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Post -Path '/users' -ScriptBlock {
        # get the body data
        $body = Get-PodeBodyData

        # get the user
        $user = Get-DummyUser -UserId $body.userId

        # return the user
        Write-PodeJsonResponse -Value @{
            Username = $user.username
            Age = $user.age
        }
    }
}
```

---

### Using Raw Body Content

If you need the raw, unprocessed body data exactly as it was received (such as when working with a non-standard payload), you can use the `-Raw` switch:

```powershell
$rawBody = Get-PodeBodyData -Raw
```

This returns the raw string payload from the request, without any deserialization or parsing.

---

### Deserialization with Get-PodeBodyData

Typically, the request body is encoded in JSON, XML, or YAML, but if needed, the `Get-PodeBodyData` function can deserialize data using styles designed for query-like encodings. This is especially useful for requests using `application/x-www-form-urlencoded` or `multipart/form-data`.

To enable deserialization, use the `-Deserialize` switch along with the following options:

* **`-NoExplode`**: Prevents automatic expansion of comma-separated values into arrays. Useful when values should be treated as raw strings.
* **`-Style`**: Defines the deserialization style (`'Simple'`, `'Label'`, `'Matrix'`, `'Form'`, `'SpaceDelimited'`, `'PipeDelimited'`, `'DeepObject'`). The default style is `'Form'`.
* **`-ParameterName`**: Specifies the key name to return from the deserialized result. The default is `'id'`.

---

### Example with Deserialization

This example demonstrates deserialization of body data using specific styles and options:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Post -Path '/items' -ScriptBlock {
        # retrieve and deserialize the body data
        $body = Get-PodeBodyData -Deserialize -Style 'Matrix' -NoExplode

        # get the item based on the deserialized data
        $item = Get-DummyItem -ItemId $body.id

        # return the item details
        Write-PodeJsonResponse -Value @{
            Name = $item.name
            Quantity = $item.quantity
        }
    }
}
```

In this example, `Get-PodeBodyData` is used to deserialize the body data with the `'Matrix'` style and prevent array expansion (`-NoExplode`). This approach provides flexible and precise handling of incoming body data, enhancing the capability of your Pode routes to manage complex payloads.
