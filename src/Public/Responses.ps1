using namespace Pode

<#
.SYNOPSIS
Attaches a file onto the Response for downloading.

.DESCRIPTION
Attaches a file from the "/public", and static Routes, onto the Response for downloading.
If the supplied path is not in the Static Routes but is a literal/relative path, then this file is used instead.

.PARAMETER Path
The Path to a static file relative to the "/public" directory, or a static Route.
If the supplied Path doesn't match any custom static Route, then Pode will look in the "/public" directory.
Failing this, if the file path exists as a literal/relative file, then this file is used as a fall back.

.PARAMETER ContentType
Manually specify the content type of the response rather than inferring it from the attachment's file extension.
The supplied value must match the valid ContentType format, e.g. application/json

.PARAMETER EndpointName
Optional EndpointName that the static route was creating under.

.PARAMETER FileBrowser
If the path is a folder, instead of returning 404, will return A browsable content of the directory.

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.PARAMETER Inline
If supplied, the file will be displayed inline in the browser, rather than downloaded as a file.

.EXAMPLE
Set-PodeResponseAttachment -Path 'downloads/installer.exe'

.EXAMPLE
Set-PodeResponseAttachment -Path './image.png'

.EXAMPLE
Set-PodeResponseAttachment -Path 'c:/content/accounts.xlsx'

.EXAMPLE
Set-PodeResponseAttachment -Path './data.txt' -ContentType 'application/json'

.EXAMPLE
Set-PodeResponseAttachment -Path '/assets/data.txt' -EndpointName 'Example'

.EXAMPLE
Set-PodeResponseAttachment -Path './[metadata].json'

.EXAMPLE
Set-PodeResponseAttachment -Path './`[metadata`].json' -NoEscape
#>
function Set-PodeResponseAttachment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        $Path,

        [ValidatePattern('^\w+\/[\w\.\+-]+$')]
        [string]
        $ContentType,

        [Parameter()]
        [string]
        $EndpointName,

        [switch]
        $FileBrowser,

        [switch]
        $NoEscape,

        [Parameter()]
        [switch]
        $Inline
    )
    begin {
        $pipelineItemCount = 0
    }

    process {
        $pipelineItemCount++
    }

    end {
        if ($pipelineItemCount -gt 1) {
            throw ($PodeLocale.fnDoesNotAcceptArrayAsPipelineInputExceptionMessage -f $($MyInvocation.MyCommand.Name))
        }

        # already sent? skip
        if ($WebEvent.Response.Sent) {
            return
        }

        # escape the path if needed
        $Path = Protect-PodePath -Path $Path -NoEscape:$NoEscape

        # only attach files from public/static-route directories when path is relative
        $route = (Find-PodeStaticRoute -Path $Path -CheckPublic -EndpointName $EndpointName -NoEscape)
        if ($route) {
            $_path = $route.Content.Source
        }
        else {
            $_path = Get-PodeRelativePath -Path $Path -JoinRoot
        }
        # if the path is a directory, then return a browsable directory response
        Write-PodeFileResponseInternal -Path $_path -ContentType $ContentType -FileBrowser:$fileBrowser -NoEscape -Download:(!$Inline.IsPresent)
    }
}


<#
.SYNOPSIS
Writes a String or a Byte[] to the Response.

.DESCRIPTION
Writes a String or a Byte[] to the Response, as some specified content type. This value can also be cached.

.PARAMETER Value
A String value to write.

.PARAMETER Bytes
An array of Bytes to write.

.PARAMETER ContentType
The content type of the data being written.

.PARAMETER MaxAge
The maximum age to cache the value on the browser, in seconds.

.PARAMETER StatusCode
The status code to set against the response.

.PARAMETER Cache
Should the value be cached by browsers, or not?

.PARAMETER Download
If supplied, the content will be downloaded as a file, rather than displayed in the browser.

.PARAMETER FileName
The name of the file to download or to visualize in the browser.

.PARAMETER ETag
An optional ETag value to be set in the response headers. If not provided, it will be generated based on the content.

.EXAMPLE
Write-PodeTextResponse -Value 'Leeeeeerrrooooy Jeeeenkiiins!'

.EXAMPLE
Write-PodeTextResponse -Value '{"name": "Rick"}' -ContentType 'application/json'

.EXAMPLE
Write-PodeTextResponse -Bytes (Get-Content -Path ./some/image.png -Raw -AsByteStream) -Cache -MaxAge 1800

.EXAMPLE
Write-PodeTextResponse -Value 'Untitled Text Response' -StatusCode 418
#>
function Write-PodeTextResponse {
    [CmdletBinding(DefaultParameterSetName = 'String')]
    param (
        [Parameter(ParameterSetName = 'String', ValueFromPipeline = $true, Position = 0)]
        [string]
        $Value,

        [Parameter(ParameterSetName = 'Bytes')]
        [byte[]]
        $Bytes,

        [Parameter()]
        [string]
        $ContentType = 'text/plain',

        [Parameter()]
        [int]
        $MaxAge = 3600,

        [Parameter()]
        [int]
        $StatusCode = 200,

        [Parameter()]
        [switch]
        $Download,

        [Parameter()]
        [string]
        $FileName,

        [Parameter()]
        [switch]
        $Cache,

        [Parameter()]
        [string]
        $ETag
    )

    begin {
        # Initialize an array to hold piped-in values
        $pipelineValue = @()
    }

    process {
        # Add the current piped-in value to the array
        $pipelineValue += $_
    }

    end {
        # Set Value to the array of values
        if ($pipelineValue.Count -gt 1) {
            $Value = $pipelineValue -join "`n"
        }

        # set the status code of the response, but only if it's not 200 (to prevent overriding)
        if ($StatusCode -ne 200) {
            Set-PodeResponseStatus -Code $StatusCode -NoErrorPage
        }

        # if there's nothing to write, return
        if ($PSCmdlet.ParameterSetName -ieq 'string') {

            if ( [string]::IsNullOrEmpty($Value)) {
                return
            }
            $Bytes = $PodeContext.Server.Encoding.GetBytes($Value)
        }
        elseif ( ($null -eq $Bytes) -or ($Bytes.Length -eq 0)) {
            return
        }
        try {
            # if the response stream isn't writeable or already sent, return
            $res = $WebEvent.Response
            if (($null -eq $res) -or ($WebEvent.Streamed -and (($null -eq $res.OutputStream) -or !$res.OutputStream.CanWrite -or $res.Sent))) {
                return
            }

            $testualMimeType = [Pode.PodeMimeTypes]::IsTextualMimeType($ContentType)

            if ($testualMimeType) {
                if ($Download) {
                    # If the content type is binary, set it to application/octet-stream
                    # This is useful for files that should be downloaded rather than displayed
                    $ContentType = 'application/octet-stream'
                }
                elseif ($ContentType -notcontains '; charset=') {
                    # If the content type is textual, ensure it has a charset
                    $ContentType += "; charset=$($PodeContext.Server.Encoding.WebName)"
                }
            }
            # set the content type of the response
            $WebEvent.Response.ContentType = $ContentType

            # set the compression type based on the Accept-Encoding header and the content length
            $compression = if ($null -ne $webEvent.Ranges -and $webEvent.Ranges.Count -eq 0) {
                [pode.podecompressiontype]::none
            }
            else {
                Set-PodeCompressionType -Length $Bytes.Count -AcceptEncoding $WebEvent.AcceptEncoding -TestualMimeType $testualMimeType
            }

            # set the cache header if requested
            if (Set-PodeCacheHeader -WebEventCache $WebEvent.Cache -Cache:$Cache -MaxAge $MaxAge -ETag $ETag) {
                Set-PodeResponseStatus -Code 304
                return
            }

            # if we're serverless, set the string as the body
            if (!$WebEvent.Streamed) {
                $res.Body = $Bytes
                return
            }
            if ($WebEvent.Method -eq 'Get') {

                if ($null -ne $WebEvent.Ranges) {
                    $WebEvent.Response.WriteBody($Bytes, [long[]] $WebEvent.Ranges, $compression)
                    return
                }
                elseif (![string]::IsNullOrEmpty($FileName)) {
                    if ($Download) {
                        # Set the content disposition to attachment for downloading
                        # This will prompt the browser to download the file instead of displaying it
                        # If Download is false, it will be treated as inline
                        Set-PodeHeader -Name 'Content-Disposition' -Value "attachment; filename=""$($FileName)"""
                    }
                    else {
                        # Set the content disposition to inline for viewing in the browser
                        # This is useful for images, PDFs, etc., that can be displayed directly
                        # If Download is true, it will be treated as an attachment
                        Set-PodeHeader -Name 'Content-Disposition' -Value "inline; filename=""$($FileName)"""
                    }
                }
            }
            if ($compression -ne [pode.podecompressiontype]::none) {
                Set-PodeHeader -Name 'Content-Encoding' -Value $compression.toString()
            }
            # write the content to the response stream
            $WebEvent.Response.WriteBody($Bytes, $compression)
        }
        catch {
            if (Test-PodeValidNetworkFailure -Exception $_.Exception) {
                return
            }
            $_ | Write-PodeErrorLog
            throw
        }

    }
}

<#
.SYNOPSIS
Renders the content of a static, or dynamic, file on the Response.

.DESCRIPTION
Renders the content of a static, or dynamic, file on the Response.
You can set browser's to cache the content, and also override the file's content type.

.PARAMETER Path
The path to a file.

.PARAMETER FileInfo
A FileSystemInfo object to use instead of the path.

.PARAMETER Data
A HashTable of dynamic data to supply to a dynamic file.

.PARAMETER ContentType
The content type of the file's contents - this overrides the file's extension.

.PARAMETER MaxAge
The maximum age to cache the file's content on the browser, in seconds.

.PARAMETER StatusCode
The status code to set against the response.

.PARAMETER Cache
Should the file's content be cached by browsers, or not?

.PARAMETER FileBrowser
If the path is a folder, instead of returning 404, will return A browsable content of the directory.

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.EXAMPLE
Write-PodeFileResponse -Path 'C:/Files/Stuff.txt'

.EXAMPLE
Write-PodeFileResponse -Path 'C:/Files/Stuff.txt' -Cache -MaxAge 1800

.EXAMPLE
Write-PodeFileResponse -Path 'C:/Files/Stuff.txt' -ContentType 'application/json'

.EXAMPLE
Write-PodeFileResponse -Path 'C:/Views/Index.pode' -Data @{ Counter = 2 }

.EXAMPLE
Write-PodeFileResponse -Path 'C:/Files/Stuff.txt' -StatusCode 201

.EXAMPLE
Write-PodeFileResponse -Path 'C:/Files/' -FileBrowser

.EXAMPLE
Set-PodeResponseAttachment -Path './[metadata].json'

.EXAMPLE
Set-PodeResponseAttachment -Path './`[metadata`].json' -NoEscape
#>
function Write-PodeFileResponse {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'Path')]
        [string]
        $Path,

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'FileInfo')]
        [System.IO.FileSystemInfo]
        $FileInfo,

        [Parameter()]
        $Data = @{},

        [Parameter()]
        [string]
        $ContentType = $null,

        [Parameter()]
        [int]
        $MaxAge = 3600,

        [Parameter()]
        [int]
        $StatusCode = 200,

        [switch]
        $Cache,

        [switch]
        $FileBrowser,

        [switch]
        $NoEscape
    )

    begin {
        $pipelineItemCount = 0
    }

    process {
        $pipelineItemCount++
    }

    end {
        if ($pipelineItemCount -gt 1) {
            throw ($PodeLocale.fnDoesNotAcceptArrayAsPipelineInputExceptionMessage -f $($MyInvocation.MyCommand.Name))
        }

        $params = @{
            Data        = $Data
            ContentType = $ContentType
            MaxAge      = $MaxAge
            StatusCode  = $StatusCode
            Cache       = $Cache
            FileBrowser = $FileBrowser
        }

        # path or file info?
        if ($null -eq $FileInfo) {
            # escape the path if needed, and resolve
            $Path = Protect-PodePath -Path $Path -NoEscape:$NoEscape
            $params.Path = Get-PodeRelativePath -Path $Path -JoinRoot
        }
        else {
            $params.FileInfo = $FileInfo
        }

        # call internal File function
        Write-PodeFileResponseInternal @params
    }
}

<#
.SYNOPSIS
Serves a directory listing as a web page.

.DESCRIPTION
The Write-PodeDirectoryResponse function generates an HTML response that lists the contents of a specified directory,
allowing for browsing of files and directories. It supports both Windows and Unix-like environments by adjusting the
display of file attributes accordingly. If the path is a directory, it generates a browsable HTML view; otherwise, it
serves the file directly.

.PARAMETER Path
The path to the directory that should be displayed. This path is resolved and used to generate a list of contents.

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.EXAMPLE
Write-PodeDirectoryResponse -Path './static'

Generates and serves an HTML page that lists the contents of the './static' directory, allowing users to click through files and directories.
#>
function Write-PodeDirectoryResponse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [string]
        $Path,

        [switch]
        $NoEscape
    )

    begin {
        $pipelineItemCount = 0
    }

    process {
        $pipelineItemCount++
    }

    end {
        if ($pipelineItemCount -gt 1) {
            throw ($PodeLocale.fnDoesNotAcceptArrayAsPipelineInputExceptionMessage -f $($MyInvocation.MyCommand.Name))
        }

        # escape the path if needed
        $Path = Protect-PodePath -Path $Path -NoEscape:$NoEscape

        # resolve for relative path
        $RelativePath = Get-PodeRelativePath -Path $Path -JoinRoot

        if (Test-Path -Path $RelativePath -PathType Container) {
            Write-PodeDirectoryResponseInternal -Path $RelativePath -NoEscape
        }
        else {
            Set-PodeResponseStatus -Code 404
        }
    }
}

<#
.SYNOPSIS
Writes CSV data to the Response.

.DESCRIPTION
Writes CSV data to the Response, setting the content type accordingly.

.PARAMETER Value
A String, PSObject, or HashTable value.

.PARAMETER Path
The path to a CSV file.

.PARAMETER StatusCode
The status code to set against the response.

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.PARAMETER ETag
An optional ETag value to be set in the response headers. If not provided, it will be generated based on the content.

.EXAMPLE
Write-PodeCsvResponse -Value "Name`nRick"

.EXAMPLE
Write-PodeCsvResponse -Value @{ Name = 'Rick' }

.EXAMPLE
Write-PodeCsvResponse -Path 'E:/Files/Names.csv'

.EXAMPLE
Set-PodeResponseAttachment -Path './[metadata].csv'

.EXAMPLE
Set-PodeResponseAttachment -Path './`[metadata`].csv' -NoEscape
#>
function Write-PodeCsvResponse {
    [CmdletBinding(DefaultParameterSetName = 'Value')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Value', ValueFromPipeline = $true, Position = 0)]
        $Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $Path,

        [Parameter()]
        [int]
        $StatusCode = 200,

        [Parameter(ParameterSetName = 'File')]
        [switch]
        $NoEscape,

        [Parameter()]
        [string]
        $ETag
    )

    begin {
        $pipelineValue = @()
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Value') {
            $pipelineValue += $_
        }
    }

    end {
        switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
            'file' {
                if (Test-PodePath $Path) {
                    $Value = Get-PodeFileContent -Path $Path -NoEscape:$NoEscape
                }
            }

            'value' {
                if ($pipelineValue.Count -gt 1) {
                    $Value = $pipelineValue
                }

                if ($Value -isnot [string]) {
                    $Value = Resolve-PodeObjectArray -Property $Value

                    if (Test-PodeIsPSCore) {
                        $Value = ($Value | ConvertTo-Csv -Delimiter ',' -IncludeTypeInformation:$false)
                    }
                    else {
                        $Value = ($Value | ConvertTo-Csv -Delimiter ',' -NoTypeInformation)
                    }

                    $Value = ($Value -join ([environment]::NewLine))
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($Value)) {
            $Value = [string]::Empty
        }

        Write-PodeTextResponse -Value $Value -ContentType 'text/csv' -StatusCode $StatusCode -ETag $ETag
    }
}

<#
.SYNOPSIS
Writes HTML data to the Response.

.DESCRIPTION
Writes HTML data to the Response, setting the content type accordingly.

.PARAMETER Value
A String, PSObject, or HashTable value.

.PARAMETER Path
The path to a HTML file.

.PARAMETER StatusCode
The status code to set against the response.

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.PARAMETER ETag
An optional ETag value to be set in the response headers. If not provided, it will be generated based on the content.

.EXAMPLE
Write-PodeHtmlResponse -Value "Raw HTML can be placed here"

.EXAMPLE
Write-PodeHtmlResponse -Value @{ Message = 'Hello, all!' }

.EXAMPLE
Write-PodeHtmlResponse -Path 'E:/Site/About.html'

.EXAMPLE
Set-PodeResponseAttachment -Path './[metadata].html'

.EXAMPLE
Set-PodeResponseAttachment -Path './`[metadata`].html' -NoEscape
#>
function Write-PodeHtmlResponse {
    [CmdletBinding(DefaultParameterSetName = 'Value')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Value', ValueFromPipeline = $true, Position = 0)]
        $Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $Path,

        [Parameter()]
        [int]
        $StatusCode = 200,

        [Parameter(ParameterSetName = 'File')]
        [switch]
        $NoEscape,

        [Parameter()]
        [string]
        $ETag
    )

    begin {
        $pipelineValue = @()
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Value') {
            $pipelineValue += $_
        }
    }

    end {
        switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
            'file' {
                if (Test-PodePath $Path) {
                    $Value = Get-PodeFileContent -Path $Path -NoEscape:$NoEscape
                }
            }

            'value' {
                if ($pipelineValue.Count -gt 1) {
                    $Value = $pipelineValue
                }
                if ($Value -isnot [string]) {
                    $Value = ($Value | ConvertTo-Html)
                    $Value = ($Value -join ([environment]::NewLine))
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($Value)) {
            $Value = [string]::Empty
        }

        Write-PodeTextResponse -Value $Value -ContentType 'text/html' -StatusCode $StatusCode -ETag $ETag
    }
}


<#
.SYNOPSIS
Writes Markdown data to the Response.

.DESCRIPTION
Writes Markdown data to the Response, with the option to render it as HTML.

.PARAMETER Value
A String value.

.PARAMETER Path
The path to a Markdown file.

.PARAMETER StatusCode
The status code to set against the response.

.PARAMETER AsHtml
If supplied, the Markdown will be converted to HTML. (This is only supported in PS7+)

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.PARAMETER ETag
An optional ETag value to be set in the response headers. If not provided, and cache is enabled, it will be generated based on the content.

.EXAMPLE
Write-PodeMarkdownResponse -Value '# Hello, world!' -AsHtml

.EXAMPLE
Write-PodeMarkdownResponse -Path 'E:/Site/About.md'

.EXAMPLE
Set-PodeResponseAttachment -Path './[metadata].md'

.EXAMPLE
Set-PodeResponseAttachment -Path './`[metadata`].md' -NoEscape
#>
function Write-PodeMarkdownResponse {
    [CmdletBinding(DefaultParameterSetName = 'Value')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Value', ValueFromPipeline = $true, Position = 0)]
        $Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $Path,

        [Parameter()]
        [int]
        $StatusCode = 200,

        [switch]
        $AsHtml,

        [Parameter(ParameterSetName = 'File')]
        [switch]
        $NoEscape,

        [Parameter()]
        [string]
        $ETag
    )
    begin {
        $pipelineItemCount = 0
    }

    process {
        $pipelineItemCount++
    }

    end {
        if ($pipelineItemCount -gt 1) {
            throw ($PodeLocale.fnDoesNotAcceptArrayAsPipelineInputExceptionMessage -f $($MyInvocation.MyCommand.Name))
        }
        switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
            'file' {
                if (Test-PodePath $Path) {
                    $Value = Get-PodeFileContent -Path $Path -NoEscape:$NoEscape
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($Value)) {
            $Value = [string]::Empty
        }

        $mimeType = 'text/markdown'

        if ($AsHtml) {
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $mimeType = 'text/html'
                $Value = ($Value | ConvertFrom-Markdown).Html
            }
        }

        Write-PodeTextResponse -Value $Value -ContentType $mimeType -StatusCode $StatusCode -ETag $ETag
    }
}

<#
.SYNOPSIS
Writes JSON data to the Response.

.DESCRIPTION
Writes JSON data to the Response, setting the content type accordingly.

.PARAMETER Value
A String, PSObject, or HashTable value. For non-string values, they will be converted to JSON.

.PARAMETER Path
The path to a JSON file.

.PARAMETER ContentType
Because JSON content has not yet an official content type. one custom can be specified here (Default: 'application/json' )
https://www.rfc-editor.org/rfc/rfc8259

.PARAMETER Depth
The Depth to generate the JSON document - the larger this value the worse performance gets.

.PARAMETER StatusCode
The status code to set against the response.

.PARAMETER NoCompress
The JSON document is not compressed (Human readable form)

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.PARAMETER ETag
An optional ETag value to be set in the response headers. If not provided, and cache is enabled, it will be generated based on the content.

.EXAMPLE
Write-PodeJsonResponse -Value '{"name": "Rick"}'

.EXAMPLE
Write-PodeJsonResponse -Value @{ Name = 'Rick' } -StatusCode 201

.EXAMPLE
Write-PodeJsonResponse -Path 'E:/Files/Names.json'

.EXAMPLE
Set-PodeResponseAttachment -Path './[metadata].json'

.EXAMPLE
Set-PodeResponseAttachment -Path './`[metadata`].json' -NoEscape
#>
function Write-PodeJsonResponse {
    [CmdletBinding(DefaultParameterSetName = 'Value')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Value', ValueFromPipeline = $true, Position = 0)]
        [AllowNull()]
        $Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $Path,

        [Parameter()]
        [ValidatePattern('^\w+\/[\w\.\+-]+$')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ContentType = 'application/json',

        [Parameter(ParameterSetName = 'Value')]
        [ValidateRange(0, 100)]
        [int]
        $Depth = 10,

        [Parameter()]
        [int]
        $StatusCode = 200,

        [Parameter(ParameterSetName = 'Value')]
        [switch]
        $NoCompress,

        [Parameter(ParameterSetName = 'File')]
        [switch]
        $NoEscape,

        [Parameter()]
        [string]
        $ETag
    )

    begin {
        $pipelineValue = @()
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Value') {
            $pipelineValue += $_
        }
    }

    end {
        switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
            'file' {
                if (Test-PodePath $Path) {
                    $Value = Get-PodeFileContent -Path $Path -NoEscape:$NoEscape
                }
                if ([string]::IsNullOrWhiteSpace($Value)) {
                    $Value = '{}'
                }
            }

            'value' {
                if ($pipelineValue.Count -gt 1) {
                    $Value = $pipelineValue
                }
                if ($Value -isnot [string]) {
                    $Value = (ConvertTo-Json -InputObject $Value -Depth $Depth -Compress:(!$NoCompress))
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($Value)) {
            $Value = '{}'
        }

        Write-PodeTextResponse -Value $Value -ContentType $ContentType -StatusCode $StatusCode -ETag $ETag
    }
}


<#
.SYNOPSIS
Writes XML data to the Response.

.DESCRIPTION
Writes XML data to the Response, setting the content type accordingly.

.PARAMETER Value
A String, PSObject, or HashTable value.

.PARAMETER Path
The path to an XML file.

.PARAMETER ContentType
Because XML content has not yet an official content type. one custom can be specified here (Default: 'application/xml' )
https://www.rfc-editor.org/rfc/rfc3023

.PARAMETER Depth
The Depth to generate the XML document - the larger this value the worse performance gets.

.PARAMETER StatusCode
The status code to set against the response.

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.PARAMETER ETag
An optional ETag value to be set in the response headers. If not provided, and cache is enabled, it will be generated based on the content.

.EXAMPLE
Write-PodeXmlResponse -Value '<root><name>Rick</name></root>'

.EXAMPLE
Write-PodeXmlResponse -Value @{ Name = 'Rick' } -StatusCode 201

.EXAMPLE
@(@{ Name = 'Rick' }, @{ Name = 'Don' }) | Write-PodeXmlResponse

.EXAMPLE
$users = @([PSCustomObject]@{
                Name = 'Rick'
            }, [PSCustomObject]@{
                Name = 'Don'
            }
        )
Write-PodeXmlResponse -Value $users

.EXAMPLE
@([PSCustomObject]@{
        Name = 'Rick'
    }, [PSCustomObject]@{
        Name = 'Don'
    }
) | Write-PodeXmlResponse

.EXAMPLE
Write-PodeXmlResponse -Path 'E:/Files/Names.xml'

.EXAMPLE
Set-PodeResponseAttachment -Path './[metadata].xml'

.EXAMPLE
Set-PodeResponseAttachment -Path './`[metadata`].xml' -NoEscape
#>
function Write-PodeXmlResponse {
    [CmdletBinding(DefaultParameterSetName = 'Value')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Value', ValueFromPipeline = $true, Position = 0)]
        [AllowNull()]
        $Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $Path,

        [Parameter(ParameterSetName = 'Value')]
        [ValidateRange(0, 100)]
        [int]
        $Depth = 10,

        [Parameter()]
        [ValidatePattern('^\w+\/[\w\.\+-]+$')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ContentType = 'application/xml',

        [Parameter()]
        [int]
        $StatusCode = 200,

        [Parameter(ParameterSetName = 'File')]
        [switch]
        $NoEscape,

        [Parameter()]
        [string]
        $ETag
    )

    begin {
        $pipelineValue = @()
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Value' -and $_) {
            $pipelineValue += $_
        }
    }

    end {

        switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
            'file' {
                if (Test-PodePath $Path) {
                    $Value = Get-PodeFileContent -Path $Path -NoEscape:$NoEscape
                }
            }

            'value' {
                if ($pipelineValue.Count -gt 1) {
                    $Value = $pipelineValue
                }

                if ($Value -isnot [string]) {
                    $Value = Resolve-PodeObjectArray -Property $Value | ConvertTo-Xml -Depth $Depth -As String -NoTypeInformation
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($Value)) {
            $Value = [string]::Empty
        }

        Write-PodeTextResponse -Value $Value -ContentType $ContentType -StatusCode $StatusCode -ETag $ETag
    }
}

<#
.SYNOPSIS
Writes YAML data to the Response.

.DESCRIPTION
Writes YAML data to the Response, setting the content type accordingly.

.PARAMETER Value
A String, PSObject, or HashTable value. For non-string values, they will be converted to YAML.

.PARAMETER Path
The path to a YAML file.

.PARAMETER ContentType
Because YAML content has not yet an official content type. one custom can be specified here (Default: 'application/yaml' )
https://www.rfc-editor.org/rfc/rfc9512

.PARAMETER Depth
The Depth to generate the YAML document - the larger this value the worse performance gets.

.PARAMETER StatusCode
The status code to set against the response.

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.PARAMETER ETag
An optional ETag value to be set in the response headers. If not provided, and cache is enabled, it will be generated based on the content.

.EXAMPLE
Write-PodeYamlResponse -Value 'name: "Rick"'

.EXAMPLE
Write-PodeYamlResponse -Value @{ Name = 'Rick' } -StatusCode 201

.EXAMPLE
Write-PodeYamlResponse -Path 'E:/Files/Names.yaml'

.EXAMPLE
Set-PodeResponseAttachment -Path './[metadata].yaml'

.EXAMPLE
Set-PodeResponseAttachment -Path './`[metadata`].yaml' -NoEscape
#>
function Write-PodeYamlResponse {
    [CmdletBinding(DefaultParameterSetName = 'Value')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Value', ValueFromPipeline = $true, Position = 0)]
        [AllowNull()]
        $Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        $Path,

        [Parameter()]
        [ValidatePattern('^\w+\/[\w\.\+-]+$')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ContentType = 'application/yaml',


        [Parameter(ParameterSetName = 'Value')]
        [ValidateRange(0, 100)]
        [int]
        $Depth = 10,

        [Parameter()]
        [int]
        $StatusCode = 200,

        [Parameter(ParameterSetName = 'File')]
        [switch]
        $NoEscape,

        [Parameter()]
        [string]
        $ETag
    )

    begin {
        $pipelineValue = @()
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Value') {
            $pipelineValue += $_
        }
    }

    end {

        switch ($PSCmdlet.ParameterSetName.ToLowerInvariant()) {
            'file' {
                if (Test-PodePath $Path) {
                    $Value = Get-PodeFileContent -Path $Path -NoEscape:$NoEscape
                }
            }

            'value' {
                if ($pipelineValue.Count -gt 1) {
                    $Value = $pipelineValue
                }

                if ($Value -isnot [string]) {
                    $Value = ConvertTo-PodeYaml -InputObject $Value -Depth $Depth

                }
            }
        }
        if ([string]::IsNullOrWhiteSpace($Value)) {
            $Value = '[]'
        }

        Write-PodeTextResponse -Value $Value -ContentType $ContentType -StatusCode $StatusCode -ETag $ETag
    }
}



<#
.SYNOPSIS
Renders a dynamic, or static, View on the Response.

.DESCRIPTION
Renders a dynamic, or static, View on the Response; allowing for dynamic data to be supplied.

.PARAMETER Path
The path to a View, relative to the "/views" directory. (Extension is optional).

.PARAMETER Data
Any dynamic data to supply to a dynamic View.

.PARAMETER StatusCode
The status code to set against the response.

.PARAMETER Folder
If supplied, a custom views folder will be used.

.PARAMETER FlashMessages
Automatically supply all Flash messages in the current session to the View.

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.EXAMPLE
Write-PodeViewResponse -Path 'index'

.EXAMPLE
Write-PodeViewResponse -Path 'accounts/profile_page' -Data @{ Username = 'Morty' }

.EXAMPLE
Write-PodeViewResponse -Path 'login' -FlashMessages
#>
function Write-PodeViewResponse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        $Path,

        [Parameter()]
        [hashtable]
        $Data = @{},

        [Parameter()]
        [int]
        $StatusCode = 200,

        [Parameter()]
        [string]
        $Folder,

        [switch]
        $FlashMessages,

        [Parameter(ParameterSetName = 'File')]
        [switch]
        $NoEscape
    )

    begin {
        $pipelineItemCount = 0
    }

    process {
        $pipelineItemCount++
    }

    end {
        if ($pipelineItemCount -gt 1) {
            throw ($PodeLocale.fnDoesNotAcceptArrayAsPipelineInputExceptionMessage -f $($MyInvocation.MyCommand.Name))
        }
        # default data if null
        if ($null -eq $Data) {
            $Data = @{}
        }

        # add path to data as "pagename" - unless key already exists
        if (!$Data.ContainsKey('pagename')) {
            $Data['pagename'] = $Path
        }

        # load all flash messages if needed
        if ($FlashMessages -and ($null -ne $WebEvent.Session.Data.Flash)) {
            $Data['flash'] = @{}

            foreach ($name in (Get-PodeFlashMessageNames)) {
                $Data.flash[$name] = (Get-PodeFlashMessage -Name $name)
            }
        }
        elseif ($null -eq $Data['flash']) {
            $Data['flash'] = @{}
        }

        # add view engine extension
        $ext = Get-PodeFileExtension -Path $Path
        if ([string]::IsNullOrWhiteSpace($ext)) {
            $Path += ".$($PodeContext.Server.ViewEngine.Extension)"
        }

        # only look in the view directories
        $viewFolder = $PodeContext.Server.InbuiltDrives['views']
        if (![string]::IsNullOrWhiteSpace($Folder)) {
            $viewFolder = $PodeContext.Server.Views[$Folder]
        }

        $Path = [System.IO.Path]::Combine($viewFolder, $Path)

        # escape the path if needed
        $Path = Protect-PodePath -Path $Path -NoEscape:$NoEscape

        # test the file path, and set status accordingly
        $fileInfo = Test-PodePath -Path $Path -ReturnItem
        if ($null -eq $fileInfo) {
            return
        }

        # run any engine logic and render it
        $engine = Get-PodeViewEngineType -Path $Path
        $value = Get-PodeFileContentUsingViewEngine -FileInfo $fileInfo -Data $Data

        switch ($engine.ToLowerInvariant()) {
            'md' {
                Write-PodeMarkdownResponse -Value $value -StatusCode $StatusCode -AsHtml
            }

            default {
                Write-PodeHtmlResponse -Value $value -StatusCode $StatusCode
            }
        }
    }
}


<#
.SYNOPSIS
Sets the Status Code of the Response, and controls rendering error pages.

.DESCRIPTION
Sets the Status Code of the Response, and controls rendering error pages.

.PARAMETER Code
The Status Code to set on the Response.

.PARAMETER Description
An optional Status Description.

.PARAMETER Exception
An exception to use when detailing error information on error pages.

.PARAMETER ContentType
The content type of the error page to use.

.PARAMETER NoErrorPage
Don't render an error page when the Status Code is 400+.

.EXAMPLE
Set-PodeResponseStatus -Code 404

.EXAMPLE
Set-PodeResponseStatus -Code 500 -Exception $_.Exception

.EXAMPLE
Set-PodeResponseStatus -Code 500 -Exception $_.Exception -ContentType 'application/json'
#>
function Set-PodeResponseStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]
        $Code,

        [Parameter()]
        [string]
        $Description,

        [Parameter()]
        $Exception,

        [Parameter()]
        [string]
        $ContentType = $null,

        [switch]
        $NoErrorPage
    )

    # already sent? skip
    if ($WebEvent.Response.Sent) {
        return
    }

    # set the code
    $WebEvent.Response.StatusCode = $Code

    # set an appropriate description (mapping if supplied is blank)
    if ([string]::IsNullOrWhiteSpace($Description)) {
        $Description = (Get-PodeStatusDescription -StatusCode $Code)
    }

    if (!$PodeContext.Server.IsServerless -and ![string]::IsNullOrWhiteSpace($Description)) {
        $WebEvent.Response.StatusDescription = $Description
    }

    # if the status code is >=400 then attempt to load error page
    if (!$NoErrorPage -and ($Code -ge 400)) {
        Show-PodeErrorPage -Code $Code -Description $Description -Exception $Exception -ContentType $ContentType
    }
}

<#
.SYNOPSIS
Redirecting a user to a new URL.

.DESCRIPTION
Redirecting a user to a new URL, or the same URL as the Request but a different Protocol - or other components.

.PARAMETER Url
Redirect the user to a new URL, or a relative path.

.PARAMETER EndpointName
The Name of an Endpoint to redirect to.

.PARAMETER Port
Change the port of the current Request before redirecting.

.PARAMETER Protocol
Change the protocol of the current Request before redirecting.

.PARAMETER Address
Change the domain address of the current Request before redirecting.

.PARAMETER Moved
Set the Status Code as "301 Moved", rather than "302 Redirect".

.EXAMPLE
Move-PodeResponseUrl -Url 'https://google.com'

.EXAMPLE
Move-PodeResponseUrl -Url '/about'

.EXAMPLE
Move-PodeResponseUrl -Protocol HTTPS

.EXAMPLE
Move-PodeResponseUrl -Port 9000 -Moved
#>
function Move-PodeResponseUrl {
    [CmdletBinding(DefaultParameterSetName = 'Url')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Url')]
        [string]
        $Url,

        [Parameter(ParameterSetName = 'Endpoint')]
        [string]
        $EndpointName,

        [Parameter(ParameterSetName = 'Components')]
        [int]
        $Port = 0,

        [Parameter(ParameterSetName = 'Components')]
        [ValidateSet('', 'Http', 'Https')]
        [string]
        $Protocol,

        [Parameter(ParameterSetName = 'Components')]
        [string]
        $Address,

        [switch]
        $Moved
    )

    # build the url
    if ($PSCmdlet.ParameterSetName -ieq 'components') {
        $uri = $WebEvent.Request.Url

        # set the protocol
        $Protocol = $Protocol.ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($Protocol)) {
            $Protocol = $uri.Scheme
        }

        # set the domain
        if ([string]::IsNullOrWhiteSpace($Address)) {
            $Address = $uri.Host
        }

        # set the port
        if ($Port -le 0) {
            $Port = $uri.Port
        }

        $PortStr = [string]::Empty
        if (@(80, 443) -notcontains $Port) {
            $PortStr = ":$($Port)"
        }

        # combine to form the url
        $Url = "$($Protocol)://$($Address)$($PortStr)$($uri.PathAndQuery)"
    }

    # build the url from an endpoint
    elseif ($PSCmdlet.ParameterSetName -ieq 'endpoint') {
        $endpoint = Get-PodeEndpointByName -Name $EndpointName -ThrowError

        # set the port
        $PortStr = [string]::Empty
        if (@(80, 443) -notcontains $endpoint.Port) {
            $PortStr = ":$($endpoint.Port)"
        }

        $Url = "$($endpoint.Protocol)://$($endpoint.FriendlyName)$($PortStr)$($WebEvent.Request.Url.PathAndQuery)"
    }

    Set-PodeHeader -Name 'Location' -Value $Url

    if ($Moved) {
        Set-PodeResponseStatus -Code 301 -Description 'Moved'
    }
    else {
        Set-PodeResponseStatus -Code 302 -Description 'Redirect'
    }
}

<#
.SYNOPSIS
Writes data to a TCP socket stream.

.DESCRIPTION
Writes data to a TCP socket stream.

.PARAMETER Message
The message to write

.EXAMPLE
Write-PodeTcpClient -Message '250 OK'
#>
function Write-PodeTcpClient {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $Message
    )
    begin {
        # Initialize an array to hold piped-in values
        $pipelineValue = @()
    }

    process {
        # Add the current piped-in value to the array
        $pipelineValue += $_
    }

    end {
        # Set Route to the array of values
        if ($pipelineValue.Count -gt 1) {
            $Message = $pipelineValue -join "`n"
        }
        $TcpEvent.Response.WriteLine($Message, $true)
    }
}

<#
.SYNOPSIS
Reads data from a TCP socket stream.

.DESCRIPTION
Reads data from a TCP socket stream.

.PARAMETER Timeout
An optional Timeout in milliseconds.

.PARAMETER CheckBytes
An optional array of bytes to check at the end of a receievd data stream, to determine if the data is complete.

.PARAMETER CRLFMessageEnd
If supplied, the CheckBytes will be set to 13 and 10 to make sure a message ends with CR and LF.

.EXAMPLE
$data = Read-PodeTcpClient

.EXAMPLE
$data = Read-PodeTcpClient -CRLFMessageEnd
#>
function Read-PodeTcpClient {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [OutputType([string])]
    param(
        [Parameter()]
        [int]
        $Timeout = 0,

        [Parameter(ParameterSetName = 'CheckBytes')]
        [byte[]]
        $CheckBytes = $null,

        [Parameter(ParameterSetName = 'CRLF')]
        [switch]
        $CRLFMessageEnd
    )

    $cBytes = $CheckBytes
    if ($CRLFMessageEnd) {
        $cBytes = [byte[]]@(13, 10)
    }

    return (Wait-PodeTask -Task $TcpEvent.Request.Read($cBytes, $PodeContext.Tokens.Cancellation.Token) -Timeout $Timeout)
}

<#
.SYNOPSIS
Close an open TCP client connection

.DESCRIPTION
Close an open TCP client connection

.EXAMPLE
Close-PodeTcpClient
#>
function Close-PodeTcpClient {
    [CmdletBinding()]
    param()

    $TcpEvent.Request.Close()
}

<#
.SYNOPSIS
Saves any uploaded files on the Request to the File System.

.DESCRIPTION
Saves any uploaded files on the Request to the File System.

.PARAMETER Key
The name of the key within the $WebEvent's Data HashTable that stores the file names.

.PARAMETER Path
The path to save files. If this is a directory then the file name of the uploaded file will be used, but if this is a file path then that name is used instead.
If the Request has multiple files in, and you specify a file path, then all files will be saved to that one file path - overwriting each other.

.PARAMETER FileName
An optional FileName to save a specific files if multiple files were supplied in the Request. By default, every file is saved.

.EXAMPLE
Save-PodeRequestFile -Key 'avatar'

.EXAMPLE
Save-PodeRequestFile -Key 'avatar' -Path 'F:/Images'

.EXAMPLE
Save-PodeRequestFile -Key 'avatar' -Path 'F:/Images' -FileName 'icon.png'
#>
function Save-PodeRequestFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Key,

        [Parameter()]
        [string]
        $Path = '.',

        [Parameter()]
        [string[]]
        $FileName
    )

    # if path is '.', replace with server root
    $Path = Get-PodeRelativePath -Path $Path -JoinRoot

    # ensure the parameter name exists in data
    if (!(Test-PodeRequestFile -Key $Key)) {
        # A parameter called was not supplied in the request or has no data available
        throw ($PodeLocale.parameterNotSuppliedInRequestExceptionMessage -f $Key)
    }

    # get the file names
    $files = @($WebEvent.Data[$Key])
    if (($null -ne $FileName) -and ($FileName.Length -gt 0)) {
        $files = @(foreach ($file in $files) {
                if ($FileName -icontains $file) {
                    $file
                }
            })
    }

    # ensure the file data exists
    foreach ($file in $files) {
        if (!$WebEvent.Files.ContainsKey($file)) {
            # No data for file was uploaded in the request
            throw ($PodeLocale.noDataForFileUploadedExceptionMessage -f $file)
        }
    }

    # save the files
    foreach ($file in $files) {
        # if the path is a directory, add the filename
        $filePath = $Path
        if (Test-Path -Path $filePath -PathType Container) {
            $filePath = [System.IO.Path]::Combine($filePath, $file)
        }

        # save the file
        $WebEvent.Files[$file].Save($filePath)
    }
}

<#
.SYNOPSIS
Test to see if the Request contains the key for any uploaded files.

.DESCRIPTION
Test to see if the Request contains the key for any uploaded files.

.PARAMETER Key
The name of the key within the $WebEvent's Data HashTable that stores the file names.

.PARAMETER FileName
An optional FileName to test for a specific file within the list of uploaded files.

.EXAMPLE
Test-PodeRequestFile -Key 'avatar'

.EXAMPLE
Test-PodeRequestFile -Key 'avatar' -FileName 'icon.png'
#>
function Test-PodeRequestFile {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Key,

        [Parameter()]
        [string]
        $FileName
    )

    # ensure the parameter name exists in data
    if (!$WebEvent.Data.ContainsKey($Key)) {
        return $false
    }

    # ensure it has filenames
    if ([string]::IsNullOrEmpty($WebEvent.Data[$Key])) {
        return $false
    }

    # do we have any specific files?
    if (![string]::IsNullOrEmpty($FileName)) {
        return (@($WebEvent.Data[$Key]) -icontains $FileName)
    }

    # we have files
    return $true
}

<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER Type
The type name of the view engine (inbuilt types are: Pode and HTML).

.PARAMETER ScriptBlock
A ScriptBlock for specifying custom view engine rendering rules.

.PARAMETER Extension
A custom extension for the engine's files.

.EXAMPLE
Set-PodeViewEngine -Type HTML

.EXAMPLE
Set-PodeViewEngine -Type Markdown

.EXAMPLE
Set-PodeViewEngine -Type PSHTML -Extension PS1 -ScriptBlock { param($path, $data) /* logic */ }
#>
function Set-PodeViewEngine {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Type,

        [Parameter()]
        [scriptblock]
        $ScriptBlock = $null,

        [Parameter()]
        [string]
        $Extension
    )

    # truncate markdown
    if ($Type -ieq 'Markdown') {
        $Type = 'md'
    }

    # override extension with type
    if ([string]::IsNullOrWhiteSpace($Extension)) {
        $Extension = $Type
    }

    # check if the scriptblock has any using vars
    if ($null -ne $ScriptBlock) {
        $ScriptBlock, $usingVars = Convert-PodeScopedVariables -ScriptBlock $ScriptBlock -PSSession $PSCmdlet.SessionState
    }

    # setup view engine config
    $PodeContext.Server.ViewEngine.Type = $Type.ToLowerInvariant()
    $PodeContext.Server.ViewEngine.Extension = $Extension.ToLowerInvariant()
    $PodeContext.Server.ViewEngine.ScriptBlock = $ScriptBlock
    $PodeContext.Server.ViewEngine.UsingVariables = $usingVars
    $PodeContext.Server.ViewEngine.IsDynamic = (@('html', 'md') -inotcontains $Type)
}

<#
.SYNOPSIS
Includes the contents of a partial View into another dynamic View.

.DESCRIPTION
Includes the contents of a partial View into another dynamic View. The partial View can be static or dynamic.

.PARAMETER Path
The path to a partial View, relative to the "/views" directory. (Extension is optional).

.PARAMETER Data
Any dynamic data to supply to a dynamic partial View.

.PARAMETER Folder
If supplied, a custom views folder will be used.

.PARAMETER NoEscape
If supplied, the path will not be escaped. This is useful for paths that contain expected wildcards, or are already escaped.

.EXAMPLE
Use-PodePartialView -Path 'shared/footer'
#>
function Use-PodePartialView {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]
        $Path,

        [Parameter()]
        $Data = @{},

        [Parameter()]
        [string]
        $Folder,

        [Parameter(ParameterSetName = 'File')]
        [switch]
        $NoEscape
    )

    begin {
        $pipelineItemCount = 0
    }

    process {
        $pipelineItemCount++
    }

    end {
        if ($pipelineItemCount -gt 1) {
            throw ($PodeLocale.fnDoesNotAcceptArrayAsPipelineInputExceptionMessage -f $($MyInvocation.MyCommand.Name))
        }

        # default data if null
        if ($null -eq $Data) {
            $Data = @{}
        }

        # add view engine extension
        $ext = Get-PodeFileExtension -Path $Path
        if ([string]::IsNullOrWhiteSpace($ext)) {
            $Path += ".$($PodeContext.Server.ViewEngine.Extension)"
        }

        # only look in the view directory
        $viewFolder = $PodeContext.Server.InbuiltDrives['views']
        if (![string]::IsNullOrWhiteSpace($Folder)) {
            $viewFolder = $PodeContext.Server.Views[$Folder]
        }

        $Path = [System.IO.Path]::Combine($viewFolder, $Path)

        # escape the path if needed
        $Path = Protect-PodePath -Path $Path -NoEscape:$NoEscape

        # test the file path, and set status accordingly
        $fileInfo = Test-PodePath -Path $Path -ReturnItem -NoStatus
        if ($null -eq $fileInfo) {
            # The Views path does not exist
            throw ($PodeLocale.viewsPathDoesNotExistExceptionMessage -f $Path)
        }

        # run any engine logic
        return (Get-PodeFileContentUsingViewEngine -FileInfo $fileInfo -Data $Data)
    }
}

<#
.SYNOPSIS
Broadcasts a message to connected WebSocket clients.

.DESCRIPTION
Broadcasts a message to all, or some, connected WebSocket clients. You can specify a path to send messages to, or a specific ClientId.

.PARAMETER Value
A String, PSObject, or HashTable value. For non-string values, they will be converted to JSON.

.PARAMETER Path
The Path of connected clients to send the message.

.PARAMETER ClientId
A specific ClientId of a connected client to send a message. Not currently used.

.PARAMETER Depth
The Depth to generate the JSON document - the larger this value the worse performance gets.

.PARAMETER Mode
The Mode to broadcast a message: Auto, Broadcast, Direct. (Default: Auto)

.PARAMETER IgnoreEvent
If supplied, if a SignalEvent is available it's data, such as path/clientId, will be ignored.

.EXAMPLE
Send-PodeSignal -Value @{ Message = 'Hello, world!' }

.EXAMPLE
Send-PodeSignal -Value @{ Data = @(123, 100, 101) } -Path '/response-charts'
#>
function Send-PodeSignal {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0 )]
        $Value,

        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [string]
        $ClientId,

        [Parameter()]
        [int]
        $Depth = 10,

        [Parameter()]
        [ValidateSet('Auto', 'Broadcast', 'Direct')]
        [string]
        $Mode = 'Auto',

        [switch]
        $IgnoreEvent
    )
    begin {
        $pipelineItemCount = 0
    }

    process {
        $pipelineItemCount++
    }

    end {
        if ($pipelineItemCount -gt 1) {
            throw ($PodeLocale.fnDoesNotAcceptArrayAsPipelineInputExceptionMessage -f $($MyInvocation.MyCommand.Name))
        }

        # error if not configured
        if (!$PodeContext.Server.Signals.Enabled) {
            # WebSockets have not been configured to send signal messages
            throw ($PodeLocale.websocketsNotConfiguredForSignalMessagesExceptionMessage)
        }

        # do nothing if no value
        if (($null -eq $Value) -or ([string]::IsNullOrEmpty($Value))) {
            return
        }

        # jsonify the value
        if ($Value -isnot [string]) {
            if ($Depth -le 0) {
                $Value = (ConvertTo-Json -InputObject $Value -Compress)
            }
            else {
                $Value = (ConvertTo-Json -InputObject $Value -Depth $Depth -Compress)
            }
        }

        # check signal event
        if (!$IgnoreEvent -and ($null -ne $SignalEvent)) {
            if ([string]::IsNullOrWhiteSpace($Path)) {
                $Path = $SignalEvent.Data.Path
            }

            if ([string]::IsNullOrWhiteSpace($ClientId)) {
                $ClientId = $SignalEvent.Data.ClientId
            }

            if (($Mode -ieq 'Auto') -and ($SignalEvent.Data.Direct -or ($SignalEvent.ClientId -ieq $SignalEvent.Data.ClientId))) {
                $Mode = 'Direct'
            }
        }

        # broadcast or direct?
        if ($Mode -iin @('Auto', 'Broadcast')) {
            $PodeContext.Server.Signals.Listener.AddServerSignal($Value, $Path, $ClientId)
        }
        else {
            $SignalEvent.Response.Write($Value)
        }
    }
}

<#
.SYNOPSIS
Add a custom path that contains additional views.

.DESCRIPTION
Add a custom path that contains additional views.

.PARAMETER Name
The Name of the views folder.

.PARAMETER Source
The literal, or relative, path to the directory that contains views.

.EXAMPLE
Add-PodeViewFolder -Name 'assets' -Source './assets'
#>
function Add-PodeViewFolder {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [string]
        $Source
    )

    # ensure the folder doesn't already exist
    if ($PodeContext.Server.Views.ContainsKey($Name)) {
        # The Views folder name already exists
        throw ($PodeLocale.viewsFolderNameAlreadyExistsExceptionMessage -f $Name)
    }

    # ensure the path exists at server root
    $Source = Get-PodeRelativePath -Path $Source -JoinRoot
    if (!(Test-PodePath -Path $Source -NoStatus)) {
        # The Views path does not exist
        throw ($PodeLocale.viewsPathDoesNotExistExceptionMessage -f $Source)
    }

    # setup a temp drive for the path
    $Source = New-PodePSDrive -Path $Source

    # add the route(s)
    Write-Verbose "Adding View Folder: [$($Name)] $($Source)"
    $PodeContext.Server.Views[$Name] = $Source
}

<#
.SYNOPSIS
Pre-emptively send an HTTP response back to the client. This can be dangerous, so only use this function if you know what you're doing.

.DESCRIPTION
Pre-emptively send an HTTP response back to the client. This can be dangerous, so only use this function if you know what you're doing.

.EXAMPLE
Send-PodeResponse
#>
function Send-PodeResponse {
    [CmdletBinding()]
    param()

    if ($null -ne $WebEvent.Response) {
        $null = Wait-PodeTask -Task $WebEvent.Response.Send()
    }
}