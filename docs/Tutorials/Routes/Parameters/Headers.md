# Headers

The following is an example of using values supplied in a request's headers. To retrieve values from the headers, you can use the `Headers` property from the `$WebEvent.Request` variable.

Alternatively, you can use the `Get-PodeHeader` function to retrieve header data, with support for deserialization, raw access, and secure value validation using secrets.

This example will get the `Authorization` header and validate the token, returning a success message:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/validate' -ScriptBlock {
        # get the token
        $token = $WebEvent.Request.Headers['Authorization']

        # validate the token
        $isValid = Test-PodeJwt -Payload $token

        # return the result
        Write-PodeJsonResponse -Value @{
            Success = $isValid
        }
    }
}
```

The following request will invoke the above route:

```powershell
Invoke-WebRequest -Uri 'http://localhost:8080/validate' -Method Get -Headers @{ Authorization = 'Bearer some_token' }
```

---

## Using `Get-PodeHeader`

You can use the `Get-PodeHeader` function as an alternative to `$WebEvent.Request.Headers`, with additional capabilities like deserialization, secret validation, and raw value access.

Here is the same example using `Get-PodeHeader`:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/validate' -ScriptBlock {
        # get the token
        $token = Get-PodeHeader -Name 'Authorization'

        # validate the token
        $isValid = Test-PodeJwt -Payload $token

        # return the result
        Write-PodeJsonResponse -Value @{
            Success = $isValid
        }
    }
}
```

---

### Using Raw Header Value

To retrieve the exact string as it was received in the request (without any decoding or processing), use the `-Raw` switch:

```powershell
$rawValue = Get-PodeHeader -Name 'X-Custom' -Raw
```

This is useful when headers contain encoded or opaque data that shouldn't be altered.

---

### Verifying Signed Headers

If your application uses signed headers to validate their integrity, you can unsign the value with a shared secret:

```powershell
$token = Get-PodeHeader -Name 'X-Signed' -Secret 'MySecret'
```

To add extra verification based on the client’s UserAgent and IP address, use the `-Strict` switch:

```powershell
$token = Get-PodeHeader -Name 'X-Signed' -Secret 'MySecret' -Strict
```

---

### Deserialization with `Get-PodeHeader`

The `Get-PodeHeader` function can deserialize serialized header values for structured handling. This is useful when headers carry encoded key-value pairs, arrays, or objects.

Use the `-Deserialize` switch along with:

* **`-Explode`**: Expands comma-separated values into arrays. Disable this for raw strings.
* Deserialization style is fixed to `'Simple'` for headers and uses the header's name as the parameter key.

---

#### Supported Deserialization Styles

| Style    | Explode | URI Template | Primitive Value (X-MyHeader = 5) | Array (X-MyHeader = \[3, 4, 5]) | Object (X-MyHeader = {"role": "admin", "firstName": "Alex"}) |
| -------- | ------- | ------------ | -------------------------------- | ------------------------------- | ------------------------------------------------------------ |
| simple\* | false\* | {id}         | X-MyHeader: 5                    | X-MyHeader: 3,4,5               | X-MyHeader: role,admin,firstName,Alex                        |
| simple   | true    | {id\*}       | X-MyHeader: 5                    | X-MyHeader: 3,4,5               | X-MyHeader: role=admin,firstName=Alex                        |

\* Default deserialization style for headers

---

### Example with Deserialization

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/deserialize' -ScriptBlock {
        # retrieve and deserialize the 'X-SerializedHeader' header
        $headerData = Get-PodeHeader -Name 'X-SerializedHeader' -Deserialize -Explode

        # return the deserialized result
        Write-PodeJsonResponse -Value @{
            HeaderData = $headerData
        }
    }
}
```

In this example, `Get-PodeHeader` deserializes the `X-SerializedHeader` header using the `'Simple'` style. The `-Explode` flag ensures array-like values are expanded as needed.

---

For more about serialization styles, see [RFC6570](https://tools.ietf.org/html/rfc6570).

For more general details, refer to the [Headers Documentation](Headers.md).
