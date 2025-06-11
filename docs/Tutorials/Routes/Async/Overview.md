# Async Routes

## Overview

Pode supports **asynchronous routes** that run independently of the main request thread. This enables long-running tasks to execute in the background while instantly returning a task reference to the client. Asynchronous execution boosts responsiveness, scalability, and flexibility in your Pode applications.

### Key Benefits

* **Responsiveness**: Non-blocking operations improve system reactivity.
* **Scalability**: Runspace pools let you handle concurrent workloads efficiently.
* **Security**: Integrated authentication and permission models protect sensitive tasks.
* **Task Management**: Built-in support for task creation, status polling, cancellation, and callbacks.

---

## Creating an Async Route

Use `Set-PodeAsyncRoute` to configure an async route from an existing route.

### Requirements

* Must pipe from `Add-PodeRoute`.
* Script block must return data, not write it.
* Avoid `Write-PodeJsonResponse` inside the script block.

### Examples

#### Using `-ArgumentList`

```powershell
Add-PodeRoute -PassThru -Method Put -Path '/asyncParam' -ScriptBlock {
    param($sleepTime2, $Message)
    Start-Sleep $sleepTime2
    return @{ InnerValue = $Message }
} -ArgumentList @{sleepTime2 = 2; Message = 'Hi' } |
Set-PodeAsyncRoute -ResponseContentType 'application/json'
```

#### Using `$using`

```powershell
$delay = 5
$msg = 'from using'

Add-PodeRoute -PassThru -Method Put -Path '/asyncUsing' -ScriptBlock {
    Start-Sleep $using:delay
    return @{ InnerValue = $using:msg }
} | Set-PodeAsyncRoute
```

#### Using `$state`

```powershell
Set-PodeState -Name 'data' -Value @{ sleepTime = 5; Message = 'from state' }

Add-PodeRoute -PassThru -Method Put -Path '/asyncState' -ScriptBlock {
    Start-Sleep $state:data.sleepTime
    return @{ InnerValue = $state:data.Message }
} | Set-PodeAsyncRoute
```

---

## Async Task Object (`AsyncRouteTask`)

Returned from every async route, this object contains metadata and task state.

| Field              | Type    | Description                                |
| ------------------ | ------- | ------------------------------------------ |
| `Id`               | string  | Unique identifier                          |
| `State`            | string  | `NotStarted`, `Running`, `Completed`, etc. |
| `Cancellable`      | boolean | Can the task be forcefully stopped         |
| `CompletedTime`    | date    | Completion timestamp                       |
| `StartingTime`     | date    | Execution start timestamp                  |
| `CreationTime`     | date    | Time task was queued                       |
| `User`             | string  | Owner of the task                          |
| `Progress`         | number  | Completion percentage (optional)           |
| `CallbackSettings` | object  | Configured callback metadata               |
| `CallbackInfo`     | object  | Result of callback (if triggered)          |
| `Permission`       | object  | Read/Write access control                  |
| `Error`            | string  | Error message (if failed)                  |
| `Result`           | any     | Output from completed task (if applicable) |

---

## Task Management with `Set-PodeAsyncRouteOperation`

This single function enables all task-management endpoints: **Get**, **Stop**, and **Query**.

### Syntax Highlights

| Mode     | Description               | Method   | Default Path |
| -------- | ------------------------- | -------- | ------------ |
| `-Get`   | Retrieve status of a task | GET      | `/task`      |
| `-Stop`  | Cancel an async task      | DELETE   | `/task`      |
| `-Query` | Search tasks by filters   | GET/POST | `/tasks`     |

---

## Querying Tasks

You can query async tasks in 3 formats:

| Style             | Description                                            | Method | Example                                     |
| ----------------- | ------------------------------------------------------ | ------ | ------------------------------------------- |
| `QueryJson`       | Structured JSON body (`filter[field][op]=...`)         | POST   | `/tasks/query`                              |
| `QueryDeepObject` | DeepObject-style query parameters                      | GET    | `/tasks?filter[State][value]=Completed&...` |
| `Simple`          | Flat query string: `?State=Completed,Cancellable=True` | GET    | `/tasks`                                    |

> ✅ All query methods support filtering by `Id`, `State`, `CreationTime`, `User`, etc.

### Operators (for JSON and DeepObject only)

* `EQ`, `NE`, `GT`, `LT`, `GE`, `LE`, `LIKE`, `NOTLIKE`
* All conditions are joined by `AND`

> ⚠️ `Simple` query supports only `EQ` comparisons.

---

## Query Examples

### JSON Body Query

```powershell
$query = @{
    State = @{ op = 'EQ'; value = 'Completed' }
    Cancellable = @{ op = 'EQ'; value = $true }
}

Invoke-RestMethod -Uri "http://localhost:8080/tasks/query" `
    -Method Post `
    -Body ($query | ConvertTo-Json) `
    -ContentType "application/json"
```

### DeepObject Query

```powershell
Invoke-RestMethod -Uri "http://localhost:8080/tasks?filter[State][op]=EQ&filter[State][value]=Completed" -Method Get
```

### Simple Query

```powershell
Invoke-RestMethod -Uri "http://localhost:8080/tasks?State=Completed,Cancellable=True" -Method Get
```

---

## Additional Features

* **Timeouts**: Default is 600 minutes; set `-Timeout -1` to disable.
* **Runspaces**: Define with `-MinRunspaces` and `-MaxRunspaces`.
* **Callbacks**: Automatic execution of a POST/PUT to a target URL with result data.
* **SSE Support**: Enable real-time status broadcasting.
* **Custom ID Generator**: Supply a script block to `-IdGenerator`.
