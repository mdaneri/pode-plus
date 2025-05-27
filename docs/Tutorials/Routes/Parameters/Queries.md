# Queries

The following is an example of using data from a request's query string. To retrieve values from the query parameters, you can use the `Query` property on the `$WebEvent` variable in a route's logic.

Alternatively, you can use the `Get-PodeQueryParameter` function to retrieve query parameter data, with additional support for deserialization and raw access.

This example will return a user based on the `userId` supplied:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/users' -ScriptBlock {
        # get the user
        $user = Get-DummyUser -UserId $WebEvent.Query['userId']

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
Invoke-WebRequest -Uri 'http://localhost:8080/users?userId=12345' -Method Get
```

---

## Using `Get-PodeQueryParameter`

Alternatively, you can use the `Get-PodeQueryParameter` function to retrieve query data. This function works similarly to `$WebEvent.Query`, but also supports:

* Raw query string access
* Complex deserialization using common styles
* Safe handling of arrays and structured values

Here is the same example using `Get-PodeQueryParameter`:

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/users' -ScriptBlock {
        # get the query data
        $userId = Get-PodeQueryParameter -Name 'userId'

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

### Using Raw Query Access

To retrieve the raw, unparsed query string as received in the request, use the `-Raw` switch:

```powershell
$rawQuery = Get-PodeQueryParameter -Name 'userId' -Raw
```

This is useful when the raw query format needs to be inspected or processed manually.

---

### Deserialization with `Get-PodeQueryParameter`

The `Get-PodeQueryParameter` function can also deserialize structured or encoded values in query parameters. This is useful for filters, complex arrays, or object-like data passed in URLs.

To enable deserialization, use the `-Deserialize` switch along with:

* **`-NoExplode`**: Prevents expansion of comma-separated values into arrays.
* **`-Style`**: Deserialization style (`'Simple'`, `'Label'`, `'Matrix'`, `'Form'`, `'SpaceDelimited'`, `'PipeDelimited'`, `'DeepObject'`). Default is `'Form'`.
* **`-KeyName`**: Sets the key name to extract from deserialized objects. Default is `'id'`.

---

#### Supported Deserialization Styles

| Style          | Explode | URI Template  | Primitive Value (id = 5) | Array (id = \[3, 4, 5]) | Object (id = {"role": "admin", "firstName": "Alex"}) |
| -------------- | ------- | ------------- | ------------------------ | ----------------------- | ---------------------------------------------------- |
| form\*         | true\*  | /users{?id\*} | /users?id=5              | /users?id=3\&id=4\&id=5 | /users?role=admin\&firstName=Alex                    |
| form           | false   | /users{?id}   | /users?id=5              | /users?id=3,4,5         | /users?id=role,admin,firstName,Alex                  |
| spaceDelimited | true    | /users{?id\*} | –                        | /users?id=3\&id=4\&id=5 | –                                                    |
| spaceDelimited | false   | –             | –                        | /users?id=3%204%205     | –                                                    |
| pipeDelimited  | true    | /users{?id\*} | –                        | /users?id=3\&id=4\&id=5 | –                                                    |
| pipeDelimited  | false   | –             | –                        | /users?id=3\|4\|5       | –                                                    |
| deepObject     | true    | –             | –                        | –                       | /users?id\[role]=admin\&id\[firstName]=Alex          |

\* Default serialization method

---

### Example with Deserialization

```powershell
Start-PodeServer {
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    Add-PodeRoute -Method Get -Path '/items' -ScriptBlock {
        # retrieve and deserialize the 'filter' query parameter
        $filter = Get-PodeQueryParameter -Name 'filter' -Deserialize -Style 'SpaceDelimited' -NoExplode

        # get items based on the deserialized filter data
        $items = Get-DummyItems -Filter $filter

        # return the item details
        Write-PodeJsonResponse -Value $items
    }
}
```

In this example, the `filter` query parameter is deserialized using the `'SpaceDelimited'` style. The `-NoExplode` switch ensures the filter remains a string or nested object, rather than being expanded into an array.

---

For further information regarding serialization styles, see [RFC6570](https://tools.ietf.org/html/rfc6570).
