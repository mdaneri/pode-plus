# Cookies

The following is an example of using values supplied in a request's cookies. To retrieve values from the cookies, you can use the `Cookies` property from the `$WebEvent` variable.

Alternatively, you can use the `Get-PodeCookie` function to retrieve cookie data, with additional support for deserialization, signature validation, and raw access.

This example will get the `SessionId` cookie and use it to authenticate the user, returning a success message:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/authenticate' -ScriptBlock {
        # get the session ID from the cookie
        $sessionId = $WebEvent.Cookies['SessionId']

        # authenticate the session
        $isAuthenticated = Authenticate-Session -SessionId $sessionId

        # return the result
        Write-PodeJsonResponse -Value @{
            Authenticated = $isAuthenticated
        }
    }
}
```

The following request will invoke the above route:

```powershell
Invoke-WebRequest -Uri 'http://localhost:8080/authenticate' -Method Get -Headers @{ Cookie = 'SessionId=abc123' }
```

---

## Using `Get-PodeCookie`

Alternatively, you can use the `Get-PodeCookie` function to retrieve the cookie data. This function works similarly to accessing `$WebEvent.Cookies`, but provides extended functionality, such as:

* Signature verification with a secret
* Raw access to the underlying .NET cookie object
* Deserialization of structured cookie values

Here is the same example using `Get-PodeCookie`:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/authenticate' -ScriptBlock {
        # get the session ID from the cookie
        $sessionId = Get-PodeCookie -Name 'SessionId'

        # authenticate the session
        $isAuthenticated = Authenticate-Session -SessionId $sessionId

        # return the result
        Write-PodeJsonResponse -Value @{
            Authenticated = $isAuthenticated
        }
    }
}
```

---

### Using Raw Cookie Access

If you need the raw `.NET` `Cookie` object for direct inspection or manipulation, you can use the `-Raw` switch:

```powershell
$cookie = Get-PodeCookie -Name 'AuthToken' -Raw
```

This bypasses any parsing or decoding and returns the raw cookie as-is.

---

### Signed Cookies with Secrets

If a cookie has been signed, you can use the `-Secret` parameter to unsign and verify its value:

```powershell
$views = Get-PodeCookie -Name 'Views' -Secret 'hunter2'
```

To strengthen the verification using client metadata (like IP and UserAgent), you can also use `-Strict`:

```powershell
$views = Get-PodeCookie -Name 'Views' -Secret 'hunter2' -Strict
```

---

### Deserialization with `Get-PodeCookie`

The `Get-PodeCookie` function supports deserialization of structured cookie values. This is especially useful when a cookie contains a serialized object, array, or key-value structure.

To enable deserialization, use the `-Deserialize` switch with these options:

* **`-NoExplode`**: Prevents automatic expansion of comma-separated values into arrays.
* **`-Deserialize`**: Enables interpretation of the cookie’s value using query-style parsing rules. The style used is `'Form'` by default.

---

#### Supported Deserialization Styles

| Style  | Explode | URI Template | Primitive Value (id = 5) | Array (id = \[3, 4, 5]) | Object (id = {"role": "admin", "firstName": "Alex"}) |
| ------ | ------- | ------------ | ------------------------ | ----------------------- | ---------------------------------------------------- |
| form\* | true\*  |              | Cookie: id=5             |                         |                                                      |
| form   | false   | id={id}      | Cookie: id=5             | Cookie: id=3,4,5        | Cookie: id=role,admin,firstName,Alex                 |

\* Default serialization method

---

### Example with Deserialization

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/deserialize-cookie' -ScriptBlock {
        # retrieve and deserialize the 'Session' cookie
        $sessionData = Get-PodeCookie -Name 'Session' -Deserialize -NoExplode

        # return the processed cookie data
        Write-PodeJsonResponse -Value @{
            SessionData = $sessionData
        }
    }
}
```

In this example, `Get-PodeCookie` is used to deserialize the `Session` cookie. The `-NoExplode` flag ensures that any arrays are not split, preserving their original format.

---

For more details on serialization formats, see [RFC6570](https://tools.ietf.org/html/rfc6570).

For related functionality, see the [Headers documentation](Cookies.md).
