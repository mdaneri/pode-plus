# Paths

The following is an example of using values supplied on a request's URL using parameters. To retrieve values that match a request's URL parameters, you can use the `Parameters` property from the `$WebEvent` variable.

Alternatively, you can use the `Get-PodePathParameter` function to retrieve the parameter data, with support for deserialization and advanced formatting.

This example will get the `:userId` parameter and "find" a user, returning the user's data:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/users/:userId' -ScriptBlock {
        # get the user
        $user = Get-DummyUser -UserId $WebEvent.Parameters['userId']

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
Invoke-WebRequest -Uri 'http://localhost:8080/users/12345' -Method Get
```

---

## Using `Get-PodePathParameter`

You can use the `Get-PodePathParameter` function as an alternative to `$WebEvent.Parameters`. This function supports retrieval of URL path parameters and provides extended functionality for deserialization.

Here is the same example using `Get-PodePathParameter`:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/users/:userId' -ScriptBlock {
        # get the parameter data
        $userId = Get-PodePathParameter -Name 'userId'

        # get the user
        $user = Get-DummyUser -UserId $userId

        # return the user
        Write-PodeJsonResponse -Value @{
            Username = $user.username
            Age = $user.age
        }
    }
}
```

---

### Deserialization with `Get-PodePathParameter`

The `Get-PodePathParameter` function can deserialize parameter values using query-style syntax, which is useful when parameters contain structured or encoded data.

Use the `-Deserialize` switch along with:

* **`-Explode`**: Expands comma-separated values into arrays. Disable to treat them as strings.
* **`-Style`**: Sets the deserialization style. Valid options are `'Simple'`, `'Label'`, and `'Matrix'`. The default is `'Simple'`.
* **`-ParameterName`**: Specifies the key name to use when extracting a value from a deserialized object. Defaults to the value of `-Name`.

---

#### Supported Deserialization Styles

| Style    | Explode | URI Template   | Primitive Value (id = 5) | Array (id = \[3, 4, 5]) | Object (id = {"role": "admin", "firstName": "Alex"}) |
| -------- | ------- | -------------- | ------------------------ | ----------------------- | ---------------------------------------------------- |
| simple\* | false\* | /users/{id}    | /users/5                 | /users/3,4,5            | /users/role,admin,firstName,Alex                     |
| simple   | true    | /users/{id\*}  | /users/5                 | /users/3,4,5            | /users/role=admin,firstName=Alex                     |
| label    | false   | /users/{.id}   | /users/.5                | /users/.3,4,5           | /users/.role,admin,firstName,Alex                    |
| label    | true    | /users/{.id\*} | /users/.5                | /users/.3.4.5           | /users/.role=admin.firstName=Alex                    |
| matrix   | false   | /users/{;id}   | /users/;id=5             | /users/;id=3,4,5        | /users/;id=role,admin,firstName,Alex                 |
| matrix   | true    | /users/{;id\*} | /users/;id=5             | /users/;id=3;id=4;id=5  | /users/;role=admin;firstName=Alex                    |

\* Default serialization method

---

### Example with Deserialization

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/items/:itemId' -ScriptBlock {
        # retrieve and deserialize the 'itemId' parameter
        $itemId = Get-PodePathParameter -Name 'itemId' -Deserialize -Style 'Label' -Explode

        # get the item based on the deserialized data
        $item = Get-DummyItem -ItemId $itemId

        # return the item details
        Write-PodeJsonResponse -Value @{
            Name = $item.name
            Quantity = $item.quantity
        }
    }
}
```

In this example, the `itemId` is interpreted using the `'Label'` style with exploding enabled, allowing arrays and objects to be parsed correctly from the URL.

---

For further information regarding serialization, please refer to the [RFC6570](https://tools.ietf.org/html/rfc6570).
