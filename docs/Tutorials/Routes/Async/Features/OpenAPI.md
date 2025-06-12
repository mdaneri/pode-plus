Certainly! Here is your **updated OpenAPI integration documentation** for async routes, reflecting the new unified `Set-PodeAsyncRouteOperation` function. All references to the old functions are removed, and usage now only shows the new merged pattern.

---

# OpenAPI Integration with Async Routes

Async routes configured via `Set-PodeAsyncRoute` and `Set-PodeAsyncRouteOperation` integrate seamlessly with Pode’s OpenAPI documentation. This enables you to automatically generate accurate API specifications for all async endpoints—whether you are retrieving task status, stopping a task, or querying for task information.

## Key Features

### Automatic Documentation Generation

When you configure async routes using `Set-PodeAsyncRouteOperation`, the associated OpenAPI documentation is created automatically. This documentation includes:

* **Route Details**: HTTP method, path, and operation summary for each async operation.
* **Response Types**: All supported content types (such as `application/json`, `application/yaml`, etc.) with proper schema references.
* **Callback Details**: If the async route is configured with a callback, it will be included in the OpenAPI definition.

### Customization Options

You can fully tailor your OpenAPI documentation:

* **Custom Schemas**: Use `Set-PodeAsyncRouteOASchemaName` to specify schema names (e.g., `OATypeName`, `TaskIdName`, `QueryRequestName`, `QueryParameterName`) for your async task documentation.
* **Route Metadata**: Add or update operation summaries, descriptions, tags, or other OpenAPI metadata using Pode’s OpenAPI helper functions, such as `Set-PodeOARouteInfo`.

### Piping for Documentation

To ensure the route is included in OpenAPI documentation, pipe your async route through `Set-PodeOARouteInfo`. This requirement applies to any async operation created using `Set-PodeAsyncRouteOperation`, including *Get* (status), *Stop*, and *Query* variants.

## Example Usage

The following examples demonstrate how to define async routes for different operations and customize their OpenAPI documentation:

```powershell
# Set a custom schema name for the async route task
Set-PodeAsyncRouteOASchemaName -OATypeName 'MyTask'

# Example 1: Async Query Route
Add-PodeRoute -Method Post -Path '/tasks' -Authentication 'MergedAuth' -Access 'MergedAccess' -Group 'Software' -PassThru |
    Set-PodeAsyncRouteOperation -Query -ResponseContentType 'application/json', 'application/yaml' -Payload Body -QueryContentType 'application/json', 'application/yaml' -PassThru |
    Set-PodeOARouteInfo -Summary 'Query Async Route Task Info'

# Example 2: Async Get (Status) Route
Add-PodeRoute -Method Get -Path '/task' -Authentication 'MergedAuth' -Access 'MergedAccess' -Group 'Software' -PassThru |
    Set-PodeAsyncRouteOperation -Get -ResponseContentType 'application/json', 'application/yaml' -In Path -PassThru |
    Set-PodeOARouteInfo -Summary 'Get Async Route Task Info'

# Example 3: Async Stop Route
Add-PodeRoute -Method Delete -Path '/task' -Authentication 'MergedAuth' -Access 'MergedAccess' -Group 'Software' -PassThru |
    Set-PodeAsyncRouteOperation -Stop -ResponseContentType 'application/json', 'application/yaml' -In Query -PassThru |
    Set-PodeOARouteInfo -Summary 'Stop Async Route Task'
```

### Resulting OpenAPI Documentation

The generated OpenAPI documentation for an async route might look like this:

```yaml
/tasks:
  post:
    summary: Query Async Route Task Info
    responses:
      200:
        description: Successful operation
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/MyTask'
          application/yaml:
            schema:
              $ref: '#/components/schemas/MyTask'

/task:
  get:
    summary: Get Async Route Task Info
    responses:
      200:
        description: Successful operation
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/MyTask'
          application/yaml:
            schema:
              $ref: '#/components/schemas/MyTask'
  delete:
    summary: Stop Async Route Task
    responses:
      200:
        description: Successful operation
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/MyTask'
          application/yaml:
            schema:
              $ref: '#/components/schemas/MyTask'

components:
  schemas:
    MyTask:
      type: object
      properties:
        User:
          type: string
          description: The async route task owner.
        CompletedTime:
          type: string
          description: The async route task completion time.
          example: 2024-07-02T20:59:23.2174712Z
          format: date-time
        State:
          type: string
          description: The async route task status.
          example: Running
          enum:
            - NotStarted
            - Running
            - Failed
            - Completed
        Result:
          type: object
          description: The result of the async route task.
          properties:
            InnerValue:
              type: string
              description: The inner value returned by the operation.
```

> **Note:**
> The `MyTask` schema above is just a sample. You can extend or customize it further using `Set-PodeAsyncRouteOASchemaName` or by providing custom schema properties as needed.

 