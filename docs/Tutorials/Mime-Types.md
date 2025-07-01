# Working with MIME Types

Pode provides a set of functions to manage MIME type mappings for file extensions, allowing you to customize how files are served and recognized by your web applications. This tutorial explains how to use these functions to add, update, remove, and query MIME types.

## Overview

Pode uses a global MIME type registry, which maps file extensions (like `.json`, `.pdf`) to their corresponding MIME types (like `application/json`, `application/pdf`). You can manage this registry at runtime using the following functions:

- `Add-PodeMimeType`
- `Set-PodeMimeType`
- `Remove-PodeMimeType`
- `Get-PodeMimeType`
- `Test-PodeMimeType`
- `Import-PodeMimeTypeFromFile`

---

## Adding a New MIME Type

Use `Add-PodeMimeType` to add a new mapping. This function will throw an error if the extension already exists.

```powershell
Add-PodeMimeType -Extension '.custom' -MimeType 'application/x-custom'
```

If you try to add an extension that already exists, an exception will be thrown.

---

## Updating or Creating a MIME Type

Use `Set-PodeMimeType` to add or update a mapping. If the extension exists, it will be updated; if not, it will be created.

```powershell
Set-PodeMimeType -Extension '.json' -MimeType 'application/vnd.api+json'
```

---

## Removing a MIME Type

Use `Remove-PodeMimeType` to remove a mapping. This function does not return a value, but you can check if the mapping still exists using `Test-PodeMimeType`.

```powershell
Remove-PodeMimeType -Extension '.custom'

if (-not (Test-PodeMimeType -Extension '.custom')) {
    Write-Host 'MIME type removed successfully.'
}
```

---

## Getting a MIME Type

Use `Get-PodeMimeType` to retrieve the MIME type for a given extension. If the extension is not found, it returns `application/octet-stream` by default, or you can specify a custom default.

```powershell
$mime = Get-PodeMimeType -Extension '.json'
$mime = Get-PodeMimeType -Extension '.unknown' -DefaultMimeType 'text/plain'
```

---

## Testing for a MIME Type

Use `Test-PodeMimeType` to check if a mapping exists for an extension.

```powershell
if (Test-PodeMimeType -Extension '.json') {
    Write-Host 'JSON is supported.'
}
```

---

## Importing MIME Types from a File

You can bulk-load MIME type mappings from a file (in Apache `mime.types` format) using `Import-PodeMimeTypeFromFile`:

```powershell
Import-PodeMimeTypeFromFile -Path './custom-mime.types'
```

Each line in the file should be in the format:

``` text
application/x-custom custom1 custom2
text/markdown md markdown
```

---

## Best Practices

- Use `Add-PodeMimeType` only for new extensions. Use `Set-PodeMimeType` for updates or to ensure a mapping exists.
- Always check for existence with `Test-PodeMimeType` before removing or adding mappings if you want to avoid errors.
- Use `Import-PodeMimeTypeFromFile` to quickly add many custom types at once.
