<#
.SYNOPSIS
    Retrieves a specific parameter value from the current Pode web event.

.DESCRIPTION
    The `Get-PodePathParameter` function extracts and returns the value of a specified parameter
    from the current Pode web event. This function can access parameters passed in the URL path, query string,
    or body of a web request, making it useful in web applications to dynamically handle incoming data.

    The function supports deserialization of parameter values when the `-Deserialize` switch is used.
    This allows for interpreting serialized data structures, like arrays or complex objects, from the web request.

.PARAMETER Name
    The name of the parameter to retrieve. This parameter is mandatory.

.PARAMETER Deserialize
    Specifies that the parameter value should be deserialized. When this switch is used, the value will be interpreted
    based on the provided style and other deserialization options.

.PARAMETER Explode
    Specifies whether to explode arrays when deserializing the parameter value. This is useful when parameters contain
    comma-separated values. Applicable only when the `-Deserialize` switch is used.

.PARAMETER Style
    Defines the deserialization style to use when interpreting the parameter value. Valid options are 'Simple', 'Label',
    and 'Matrix'. The default is 'Simple'. Applicable only when the `-Deserialize` switch is used.

.PARAMETER ParameterName
    Specifies the key name to use when deserializing the parameter value. The default value is 'id'.
    This option is useful for mapping the parameter data accurately during deserialization. Applicable only
    when the `-Deserialize` switch is used.

.EXAMPLE
    Get-PodePathParameter -Name 'action'
    Returns the value of the 'action' parameter from the current web event.

.EXAMPLE
    Get-PodePathParameter -Name 'item' -Deserialize -Style 'Label' -Explode
    Retrieves and deserializes the value of the 'item' parameter using the 'Label' style and exploding arrays.

.EXAMPLE
    Get-PodePathParameter -Name 'id' -Deserialize -KeyName 'userId'
    Deserializes the 'id' parameter using the key name 'userId'.

.NOTES
    This function should be used within a route's script block in a Pode server.
    The `-Deserialize` switch enables more advanced handling of complex data structures.
#>
function Get-PodePathParameter {
    [CmdletBinding(DefaultParameterSetName = 'BuiltIn' )]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Deserialize')]
        [Parameter(Mandatory, ParameterSetName = 'BuiltIn')]
        [string]
        $Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'Deserialize')]
        [switch]
        $Deserialize,

        [Parameter(ParameterSetName = 'Deserialize')]
        [switch]
        $Explode,

        [Parameter(ParameterSetName = 'Deserialize')]
        [ValidateSet('Simple', 'Label', 'Matrix')]
        [string]
        $Style = 'Simple',

        [Parameter(ParameterSetName = 'Deserialize')]
        [string]
        $ParameterName

    )
    if ($WebEvent) {
        if ($Deserialize.IsPresent) {
            if ([string]::IsNullOrWhiteSpace($ParameterName)) {
                $ParameterName = $Name
            }
            $raw = $WebEvent.Parameters[$Name]
            if ([string]::IsNullOrEmpty($raw)) {
                return $null
            }

            $parsed = ConvertFrom-PodeSerializedString -SerializedInput $raw -Style $Style -Explode:$Explode -ParameterName $ParameterName

            if ($parsed -is [System.Collections.IDictionary] -and $parsed.ContainsKey($ParameterName)) {
                return $parsed[$ParameterName]
            }

            return $parsed
        }
        return $WebEvent.Parameters[$Name]
    }
}

<#
.SYNOPSIS
    Retrieves the body data from the current Pode web event.

.DESCRIPTION
    The `Get-PodeBodyData` function extracts and returns the body data of the current Pode web event.
    This function is designed to access the main content sent in web requests, including methods such as PUT, POST, or any other HTTP methods that support a request body.
    It also supports deserialization of the body data, allowing for the interpretation of serialized content.

.PARAMETER Deserialize
    Specifies that the body data should be deserialized. When this switch is used, the body data will be interpreted
    based on the provided style and other deserialization options.

.PARAMETER NoExplode
    Prevents deserialization from exploding arrays in the body data. This is useful when handling parameters that
    contain comma-separated values and when array expansion is not desired. Applicable only when the `-Deserialize`
    switch is used.

.PARAMETER Style
    Defines the deserialization style to use when interpreting the body data. Valid options are 'Simple', 'Label',
    'Matrix', 'Form', 'SpaceDelimited', 'PipeDelimited', and 'DeepObject'. The default is 'Form'. Applicable only
    when the `-Deserialize` switch is used.

.PARAMETER ParameterName
    Specifies the key name to use when deserializing the body data. The default value is 'id'. This option is useful
    for mapping the body data accurately during deserialization. Applicable only when the `-Deserialize` switch is used.

.PARAMETER Raw
    If specified, the function will return the raw body data as it was received in the web request, without any deserialization or processing.

.EXAMPLE
    Get-PodeBodyData
    Returns the body data of the current web event.

.EXAMPLE
    Get-PodeBodyData -Deserialize -Style 'Matrix'
    Retrieves and deserializes the body data using the 'Matrix' style.

.EXAMPLE
    Get-PodeBodyData -Deserialize -NoExplode
    Deserializes the body data without exploding arrays.

.NOTES
    This function should be used within a route's script block in a Pode server. The `-Deserialize` switch enables
    advanced handling of complex body data structures.
#>
function Get-PodeBodyData {
    [CmdletBinding(DefaultParameterSetName = 'BuiltIn' )]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Deserialize')]
        [switch]
        $Deserialize,

        [Parameter(ParameterSetName = 'Deserialize')]
        [switch]
        $NoExplode,

        [Parameter(ParameterSetName = 'Deserialize')]
        [ValidateSet('Simple', 'Label', 'Matrix', 'Form', 'SpaceDelimited', 'PipeDelimited', 'DeepObject')]
        [string]
        $Style = 'Form',

        [Parameter(ParameterSetName = 'Deserialize')]
        [string]
        $ParameterName = 'id',

        [Parameter(ParameterSetName = 'BuiltIn')]
        [switch]
        $Raw
    )
    if ($WebEvent) {
        if ($Deserialize.IsPresent) {
            $all = ConvertFrom-PodeSerializedString -SerializedInput $WebEvent.Raw.Body -Style $Style -Explode:(!$NoExplode) -ParameterName $ParameterName

            if ($null -eq $all) {
                return $null
            }

            # For array-style bodies like id=1&id=2&id=3
            if ($all -is [System.Collections.IEnumerable] -and -not ($all -is [string])) {
                return $all
            }

            return $all[$ParameterName]
        }
        # If Raw is specified, return the raw body data
        if ($Raw) {
            return $WebEvent.Raw.Body
        }
        return $WebEvent.Data
    }
}



<#
.SYNOPSIS
    Retrieves a specific query parameter value from the current Pode web event.

.DESCRIPTION
    The `Get-PodeQueryParameter` function extracts and returns the value of a specified query parameter
    from the current Pode web event. This function is designed to access query parameters passed in the URL of a web request,
    enabling the handling of incoming data in web applications.

    The function supports deserialization of query parameter values when the `-Deserialize` switch is used,
    allowing for interpretation of complex data structures from the query string.

.PARAMETER Name
    The name of the query parameter to retrieve. This parameter is mandatory.

.PARAMETER Deserialize
    Specifies that the query parameter value should be deserialized. When this switch is used, the value will be
    interpreted based on the provided style and other deserialization options.

.PARAMETER NoExplode
    Prevents deserialization from exploding arrays in the query parameter value. This is useful when handling
    parameters that contain comma-separated values and when array expansion is not desired. Applicable only when
    the `-Deserialize` switch is used.

.PARAMETER Style
    Defines the deserialization style to use when interpreting the query parameter value. Valid options are 'Simple',
    'Label', 'Matrix', 'Form', 'SpaceDelimited', 'PipeDelimited', and 'DeepObject'. The default is 'Form'.
    Applicable only when the `-Deserialize` switch is used.

.PARAMETER ParameterName
    Specifies the key name to use when deserializing the query parameter value. The default value is 'id'.
    This option is useful for mapping the query parameter data accurately during deserialization. Applicable only
    when the `-Deserialize` switch is used.

.PARAMETER Raw
    If specified, the function will return the raw query string as it was received in the web request, without any deserialization or processing.

.EXAMPLE
    Get-PodeQueryParameter -Name 'userId'
    Returns the value of the 'userId' query parameter from the current web event.

.EXAMPLE
    Get-PodeQueryParameter -Name 'filter' -Deserialize -Style 'SpaceDelimited'
    Retrieves and deserializes the value of the 'filter' query parameter, using the 'SpaceDelimited' style.

.EXAMPLE
    Get-PodeQueryParameter -Name 'data' -Deserialize -NoExplode
    Deserializes the 'data' query parameter value without exploding arrays.

.NOTES
    This function should be used within a route's script block in a Pode server. The `-Deserialize` switch enables
    advanced handling of complex query parameter data structures.
#>
function Get-PodeQueryParameter {
    [CmdletBinding(DefaultParameterSetName = 'BuiltIn' )]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Deserialize')]
        [Parameter(Mandatory, ParameterSetName = 'BuiltIn')]
        [string]
        $Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'Deserialize')]
        [switch]
        $Deserialize,

        [Parameter(ParameterSetName = 'Deserialize')]
        [switch]
        $NoExplode,

        [Parameter(ParameterSetName = 'Deserialize')]
        [ValidateSet('Simple', 'Label', 'Matrix', 'Form', 'SpaceDelimited', 'PipeDelimited', 'DeepObject' )]
        [string]
        $Style = 'Form',

        [Parameter(ParameterSetName = 'Deserialize')]
        [string]
        $ParameterName = 'id',

        [Parameter(ParameterSetName = 'BuiltIn')]
        [switch]
        $Raw
    )
    if ($WebEvent) {
        if ($Deserialize.IsPresent) {
            $all = ConvertFrom-PodeSerializedString -SerializedInput $WebEvent.Raw.Query -Style $Style -Explode:(!$NoExplode) -ParameterName $ParameterName

            if ($null -eq $all) {
                return $null
            }

            # Handle arrays (e.g., SpaceDelimited/Explode)
            if ($all -is [System.Collections.IEnumerable] -and -not ($all -is [string])) {
                return $all
            }

            return $all[$Name]
        }
        if ($Raw) {
            return $WebEvent.Raw.Query
        }
        return $WebEvent.Query[$Name]
    }
}






<#
.SYNOPSIS
    Converts an object (hashtable or array) to a serialized string using a specified serialization style.

.DESCRIPTION
    The `ConvertTo-PodeSerializedString` function takes a hashtable or array and converts it into a serialized string
    according to the specified serialization style. It supports various styles such as 'Simple', 'Label', 'Matrix',
    'Form', 'SpaceDelimited', 'PipeDelimited', and 'DeepObject'.

    By default, parameter names and values are URL-encoded to ensure safe inclusion in URLs. You can disable URL encoding
    by using the `-NoUrlEncode` switch.

    An optional `-Explode` switch can be used to modify the serialization format for certain styles, altering how arrays
    and objects are represented in the serialized string.

.PARAMETER InputObject
    The object to be serialized. This can be a hashtable (or ordered dictionary) or an array. Supports pipeline input.

.PARAMETER Style
    The serialization style to use. Valid values are 'Simple', 'Label', 'Matrix', 'Form', 'SpaceDelimited',
    'PipeDelimited', and 'DeepObject'. Defaults to 'Simple'.

.PARAMETER Explode
    An optional switch to modify the serialization format for certain styles. When used, arrays and objects are
    serialized in an expanded form.

.PARAMETER NoUrlEncode
    An optional switch to disable URL encoding of the serialized output. By default, parameter names and values are
    URL-encoded individually. Use this switch if you require the output without URL encoding.

.PARAMETER ParameterName
    Specifies the name of the parameter to use in the serialized output. Defaults to 'id' if not specified.

.EXAMPLE
    $item = @{
        name = 'value'
        anotherName = 'anotherValue'
    }
    $serialized = ConvertTo-PodeSerializedString -InputObject $item -Style 'Form'
    Write-Output $serialized

    # Output:
    # ?id=name%2Cvalue%2CanotherName%2CanotherValue

.EXAMPLE
    $item = @{
        name = 'value'
        anotherName = 'anotherValue'
    }
    $serializedExplode = ConvertTo-PodeSerializedString -InputObject $item -Style 'DeepObject' -Explode
    Write-Output $serializedExplode

    # Output:
    # ?id[name]=value&id[anotherName]=anotherValue

.EXAMPLE
    $array = @('3', '4', '5')
    $serialized = ConvertTo-PodeSerializedString -InputObject $array -Style 'SpaceDelimited' -Explode
    Write-Output $serialized

    # Output:
    # ?id=3&id=4&id=5

.EXAMPLE
    $array = @('3', '4', '5')
    $serialized = ConvertTo-PodeSerializedString -InputObject $array -Style 'SpaceDelimited' -NoUrlEncode
    Write-Output $serialized

    # Output:
    # ?id=3 4 5

.EXAMPLE
    $item = @{
        'user name' = 'Alice & Bob'
        'role' = 'Admin/User'
    }
    $serialized = ConvertTo-PodeSerializedString -InputObject $item -Style 'Form' -ParameterName 'account' -NoUrlEncode
    Write-Output $serialized

    # Output:
    # ?account=user name,Alice & Bob,role,Admin/User

.NOTES
    - 'SpaceDelimited' and 'PipeDelimited' styles for hashtables are not implemented as they are not defined by RFC 6570.
    - The 'Form' style with 'Explode' for arrays is not implemented for the same reason.
    - The 'Explode' option for 'SpaceDelimited' and 'PipeDelimited' styles for arrays is implemented as per the OpenAPI Specification.

    Additional information regarding serialization:
    - OpenAPI Specification Serialization: https://swagger.io/docs/specification/serialization/
    - RFC 6570 - URI Template: https://tools.ietf.org/html/rfc6570
#>
function ConvertTo-PodeSerializedString {
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, Position = 0)]
        [psobject[]]
        $InputObject,

        [Parameter()]
        [ValidateSet('Simple', 'Label', 'Matrix', 'Form', 'SpaceDelimited', 'PipeDelimited', 'DeepObject')]
        [string]
        $Style = 'Simple',

        [Parameter()]
        [switch]
        $Explode,

        [Parameter()]
        [switch]
        $NoUrlEncode,

        [Parameter()]
        [string]
        $ParameterName = 'id'  # Default parameter name
    )

    begin {
        # Initialize an array to collect pipeline input
        $pipelineValue = @()
    }

    process {
        # Collect each input object from the pipeline
        $pipelineValue += $_
    }

    end {
        # Determine if multiple objects were provided via pipeline
        if ($pipelineValue.Count -gt 1) {
            $inputObjects = $pipelineValue
        }
        else {
            $inputObjects = $InputObject
        }

        # Initialize an array to store the serialized strings
        $serializedArray = @()

        # return '' if the inputObjects is null
        if ($null -eq $inputObjects) {
            return ''
        }

        # Check if there are input objects to process
        if ( $inputObjects.Count -gt 0) {

            # Check if the first input object is a hashtable or ordered dictionary
            if ($inputObjects[0] -is [hashtable] -or $inputObjects[0] -is [System.Collections.Specialized.OrderedDictionary]) {

                # Process each hashtable item
                foreach ($item in $inputObjects) {
                    switch ($Style) {

                        'Simple' {
                            # Handle 'Simple' style for hashtables
                            if ($Explode) {
                                # Serialize each key-value pair with '=' and join with ','
                                $serializedArray += ( ($item.Keys | ForEach-Object {
                                            $key = $_
                                            $value = $item[$_]
                                            # URL-encode unless $NoUrlEncode is specified
                                            if (-not $NoUrlEncode) {
                                                $key = [uri]::EscapeDataString($key)
                                                $value = [uri]::EscapeDataString($value)
                                            }
                                            "$key=$value"
                                        }) -join ',' )
                            }
                            else {
                                # Serialize each key-value pair with ',' and join with ','
                                $serializedArray += ( ($item.Keys | ForEach-Object {
                                            $key = $_
                                            $value = $item[$_]
                                            if (-not $NoUrlEncode) {
                                                $key = [uri]::EscapeDataString($key)
                                                $value = [uri]::EscapeDataString($value)
                                            }
                                            "$key,$value"
                                        }) -join ',' )
                            }
                            break
                        }

                        'Label' {
                            # Handle 'Label' style for hashtables
                            if ($Explode) {
                                # Prepend '.' and serialize each key-value pair with '='
                                $serializedArray += '.' + ( ($item.Keys | ForEach-Object {
                                            $key = $_
                                            $value = $item[$_]
                                            if (-not $NoUrlEncode) {
                                                $key = [uri]::EscapeDataString($key)
                                                $value = [uri]::EscapeDataString($value)
                                            }
                                            "$key=$value"
                                        }) -join ',' )
                            }
                            else {
                                # Prepend '.' and serialize each key-value pair with ','
                                $serializedArray += '.' + ( ($item.Keys | ForEach-Object {
                                            $key = $_
                                            $value = $item[$_]
                                            if (-not $NoUrlEncode) {
                                                $key = [uri]::EscapeDataString($key)
                                                $value = [uri]::EscapeDataString($value)
                                            }
                                            "$key,$value"
                                        }) -join ',' )
                            }
                            break
                        }

                        'Matrix' {
                            # Handle 'Matrix' style for hashtables
                            if ($Explode) {
                                # Serialize each key-value pair with ';' prefix
                                $serializedArray += ( ($item.Keys | ForEach-Object {
                                            $key = $_
                                            $value = $item[$_]
                                            if (-not $NoUrlEncode) {
                                                $key = [uri]::EscapeDataString($key)
                                                $value = [uri]::EscapeDataString($value)
                                            }
                                            ";$key=$value"
                                        }) -join '' )
                            }
                            else {
                                # Serialize key-value pairs into a single parameter
                                $valueString = ( ($item.Keys | ForEach-Object {
                                            $key = $_
                                            $value = $item[$_]
                                            if (-not $NoUrlEncode) {
                                                $key = [uri]::EscapeDataString($key)
                                                $value = [uri]::EscapeDataString($value)
                                            }
                                            "$key,$value"
                                        }) -join ',' )
                                # Encode parameter name if necessary
                                if (-not $NoUrlEncode) {
                                    $parameterName = [uri]::EscapeDataString($ParameterName)
                                }
                                else {
                                    $parameterName = $ParameterName
                                }
                                $serializedArray += ";$parameterName=$valueString"
                            }
                            break
                        }

                        'Form' {
                            # Handle 'Form' style for hashtables
                            if ($Explode) {
                                # Serialize each key-value pair as query parameters
                                $serializedArray += '?' + ( ($item.Keys | ForEach-Object {
                                            $key = $_
                                            $value = $item[$_]
                                            if (-not $NoUrlEncode) {
                                                $key = [uri]::EscapeDataString($key)
                                                $value = [uri]::EscapeDataString($value)
                                            }
                                            "$key=$value"
                                        }) -join '&' )
                            }
                            else {
                                # Serialize key-value pairs into a single query parameter
                                $valueString = ( ($item.Keys | ForEach-Object {
                                            $key = $_
                                            $value = $item[$_]
                                            if (-not $NoUrlEncode) {
                                                $key = [uri]::EscapeDataString($key)
                                                $value = [uri]::EscapeDataString($value)
                                            }
                                            "$key,$value"
                                        }) -join ',' )
                                if (-not $NoUrlEncode) {
                                    $parameterName = [uri]::EscapeDataString($ParameterName)
                                }
                                else {
                                    $parameterName = $ParameterName
                                }
                                $serializedArray += "?$parameterName=$valueString"
                            }
                            break
                        }

                        'DeepObject' {
                            # Handle 'DeepObject' style for hashtables
                            # Encode parameter name once outside the loop
                            if (-not $NoUrlEncode) {
                                $parameterNameEncoded = [uri]::EscapeDataString($ParameterName)
                            }
                            else {
                                $parameterNameEncoded = $ParameterName
                            }
                            # Serialize each key-value pair using bracket notation
                            $serializedArray += '?' + ( ($item.Keys | ForEach-Object {
                                        $key = $_
                                        $value = $item[$_]
                                        if (-not $NoUrlEncode) {
                                            $key = [uri]::EscapeDataString($key)
                                            $value = [uri]::EscapeDataString($value)
                                        }
                                        "$parameterNameEncoded`[$key`]=$value"
                                    }) -join '&' )
                            break
                        }

                        # Styles not defined for hashtables
                        'SpaceDelimited' {
                            $serializedArray += ''
                            Write-Verbose "Serialization for objects using '$Style' style is not defined by RFC 6570."
                        }

                        'PipeDelimited' {
                            $serializedArray += ''
                            Write-Verbose "Serialization for objects using '$Style' style is not defined by RFC 6570."
                        }
                    }
                }
            }
            else {
                # Process input as an array
                switch ($Style) {

                    'Simple' {
                        # Handle 'Simple' style for arrays
                        # Both 'Explode' and non-'Explode' result in the same output
                        $serializedArray += ( ($inputObjects | ForEach-Object {
                                    $value = $_
                                    if (-not $NoUrlEncode) {
                                        $value = [uri]::EscapeDataString($value)
                                    }
                                    $value
                                }) -join ',' )
                        break
                    }

                    'Label' {
                        # Handle 'Label' style for arrays
                        $serializedArray += '.' + ( ($inputObjects | ForEach-Object {
                                    $value = $_
                                    if (-not $NoUrlEncode) {
                                        $value = [uri]::EscapeDataString($value)
                                    }
                                    $value
                                }) -join ',' )
                        break
                    }

                    'Matrix' {
                        # Handle 'Matrix' style for arrays
                        if (-not $NoUrlEncode) {
                            $parameterName = [uri]::EscapeDataString($ParameterName)
                        }
                        else {
                            $parameterName = $ParameterName
                        }
                        if ($Explode) {
                            # Serialize each value with parameter name
                            $serializedArray += ';' + ( ($inputObjects | ForEach-Object {
                                        $value = $_
                                        if (-not $NoUrlEncode) {
                                            $value = [uri]::EscapeDataString($value)
                                        }
                                        "$parameterName=$value"
                                    }) -join ';' )
                        }
                        else {
                            # Serialize values into a single parameter
                            $valueString = ( ($inputObjects | ForEach-Object {
                                        $value = $_
                                        if (-not $NoUrlEncode) {
                                            $value = [uri]::EscapeDataString($value)
                                        }
                                        $value
                                    }) -join ',' )
                            $serializedArray += ";$parameterName=$valueString"
                        }
                        break
                    }

                    'SpaceDelimited' {
                        # Handle 'SpaceDelimited' style for arrays
                        if (-not $NoUrlEncode) {
                            $parameterName = [uri]::EscapeDataString($ParameterName)
                        }
                        else {
                            $parameterName = $ParameterName
                        }
                        if ($Explode) {
                            # Serialize each value as a separate parameter
                            $valueStrings = $inputObjects | ForEach-Object {
                                $value = $_
                                if (-not $NoUrlEncode) {
                                    $value = [uri]::EscapeDataString($value)
                                }
                                "$parameterName=$value"
                            }
                            $serializedArray += '?' + ($valueStrings -join '&')
                        }
                        else {
                            # Join values with a space
                            $valueString = ($inputObjects -join ' ')
                            if (-not $NoUrlEncode) {
                                $valueString = [uri]::EscapeDataString($valueString)
                            }
                            $serializedArray += "?$parameterName=$valueString"
                        }
                        break
                    }

                    'PipeDelimited' {
                        # Handle 'PipeDelimited' style for arrays
                        if (-not $NoUrlEncode) {
                            $parameterName = [uri]::EscapeDataString($ParameterName)
                        }
                        else {
                            $parameterName = $ParameterName
                        }
                        if ($Explode) {
                            # Serialize each value as a separate parameter
                            $valueStrings = $inputObjects | ForEach-Object {
                                $value = $_
                                if (-not $NoUrlEncode) {
                                    $value = [uri]::EscapeDataString($value)
                                }
                                "$parameterName=$value"
                            }
                            $serializedArray += '?' + ($valueStrings -join '&')
                        }
                        else {
                            # Join values with a pipe '|'
                            $valueString = ($inputObjects -join '|')
                            if (-not $NoUrlEncode) {
                                $valueString = [uri]::EscapeDataString($valueString)
                            }
                            $serializedArray += "?$parameterName=$valueString"
                        }
                        break
                    }

                    'Form' {
                        # Handle 'Form' style for arrays
                        if (-not $NoUrlEncode) {
                            $parameterName = [uri]::EscapeDataString($ParameterName)
                        }
                        else {
                            $parameterName = $ParameterName
                        }
                        if ($Explode) {
                            # 'Explode' is not defined for arrays in 'Form' style
                            $serializedArray += ''
                            Write-Verbose "Serialization for array using '$Style' style with 'Explode' is not defined by RFC 6570."
                        }
                        else {
                            # Serialize values into a single parameter
                            $valueString = ( ($inputObjects | ForEach-Object {
                                        $value = $_
                                        if (-not $NoUrlEncode) {
                                            $value = [uri]::EscapeDataString($value)
                                        }
                                        $value
                                    }) -join ',' )
                            $serializedArray += "$parameterName=$valueString"
                        }
                        break
                    }

                    # 'DeepObject' is not defined for arrays
                    'DeepObject' {
                        $serializedArray += ''
                        Write-Verbose "Serialization for arrays using '$Style' style is not defined by RFC 6570."
                    }
                }
            }
        }

        # Return the serialized string(s)
        return $serializedArray
    }
}


<#
.SYNOPSIS
    Converts a serialized string back into its original data structure based on the specified serialization style.

.DESCRIPTION
    The `ConvertFrom-PodeSerializedString` function takes a serialized string and converts it back into its original data structure (e.g., hashtable, array).
    The function requires the serialization style to be specified via the `-Style` parameter.
    Supported styles are 'Simple', 'Label', 'Matrix', 'Query', 'Form', 'SpaceDelimited', 'PipeDelimited', and 'DeepObject'.
    The function also accepts an optional `-Explode` switch to indicate whether the string uses exploded serialization.
    The `-ParameterName` parameter can be used to specify the key name when processing certain styles, such as 'Matrix' and 'DeepObject'.

.PARAMETER SerializedInput
    The serialized string to be converted back into its original data structure.

.PARAMETER Style
    The serialization style to use for deserialization. Options are 'Simple', 'Label', 'Matrix', 'Query', 'Form', 'SpaceDelimited', 'PipeDelimited', and 'DeepObject'. The default is 'Form'.

.PARAMETER Explode
    Indicates whether the string uses exploded serialization (`-Explode`) or not (omit `-Explode`). This affects how arrays and objects are handled.

.PARAMETER ParameterName
    Specifies the key name to match when processing certain styles, such as 'Matrix' and 'DeepObject'. The default is 'id'.

.PARAMETER UrlDecode
    If specified, the function will decode the input string using URL decoding before processing it. This is useful
    for handling serialized inputs that include URL-encoded characters, such as `%20` for spaces.

.EXAMPLE
    # Simple style, explode = true
    $serialized = "name=value,anotherName=anotherValue"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Simple' -Explode
    Write-Output $result

.EXAMPLE
    # Simple style, explode = false
    $serialized = "name,value,anotherName,anotherValue"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Simple'
    Write-Output $result

.EXAMPLE
    # Label style, explode = true
    $serialized = ".name=value.anotherName=anotherValue"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Label' -Explode
    Write-Output $result

.EXAMPLE
    # Label style, explode = false
    $serialized = ".name,value,anotherName,anotherValue"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Label'
    Write-Output $result

.EXAMPLE
    # Matrix style, explode = true
    $serialized = ";name=value;anotherName=anotherValue"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Matrix' -Explode
    Write-Output $result

.EXAMPLE
    # Matrix style, explode = false
    $serialized = ";id=3,4,5"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Matrix' -ParameterName 'id'
    Write-Output $result

.EXAMPLE
    # Query style, explode = true
    $serialized = "?name=value&anotherName=anotherValue"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Query' -Explode
    Write-Output $result

.EXAMPLE
    # Query style, explode = false
    $serialized = "?name,value,anotherName,anotherValue"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Query'
    Write-Output $result

.EXAMPLE
    # Form style, explode = true
    $serialized = "?name=value&anotherName=anotherValue"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Form' -Explode
    Write-Output $result

.EXAMPLE
    # Form style, explode = false
    $serialized = "?name,value,anotherName,anotherValue"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'Form'
    Write-Output $result

.EXAMPLE
    # SpaceDelimited style, explode = true
    $serialized = "?id=3&id=4&id=5"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'SpaceDelimited' -Explode -ParameterName 'id'
    Write-Output $result

.EXAMPLE
    # SpaceDelimited style, explode = false
    $serialized = "?id=3%204%205"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'SpaceDelimited' -ParameterName 'id'
    Write-Output $result

.EXAMPLE
    # PipeDelimited style, explode = true
    $serialized = "?id=3&id=4&id=5"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'PipeDelimited' -Explode -ParameterName 'id'
    Write-Output $result

.EXAMPLE
    # PipeDelimited style, explode = false
    $serialized = "?id=3|4|5"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'PipeDelimited' -ParameterName 'id'
    Write-Output $result

.EXAMPLE
    # DeepObject style
    $serialized = "myId[role]=admin&myId[firstName]=Alex"
    $result = ConvertFrom-PodeSerializedString -SerializedInput $serialized -Style 'DeepObject' -ParameterName 'myId'
    Write-Output $result

.NOTES
    For more information on serialization styles, refer to:
    - https://swagger.io/docs/specification/serialization/
    - https://tools.ietf.org/html/rfc6570
#>

function ConvertFrom-PodeSerializedString {
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, Position = 0)]
        [string] $SerializedInput,

        [Parameter()]
        [ValidateSet('Simple', 'Label', 'Matrix', 'Query', 'Form', 'SpaceDelimited', 'PipeDelimited', 'DeepObject' )]
        [string]
        $Style = 'Form',

        [Parameter()]
        [switch]
        $Explode,

        [Parameter()]
        [string]
        $ParameterName = 'id', # Default key name if not specified

        [Parameter()]
        [switch]
        $UrlDecode
    )

    process {
        if ($UrlDecode) {
            $SerializedInput = [System.Web.HttpUtility]::UrlDecode($SerializedInput)
        }
        # Remove the leading question mark(?) from the serialized string
        $SerializedInput = $SerializedInput.TrimStart('?')
        # Main deserialization logic based on style
        switch ($Style) {
            'Simple' {
                # Check for header pattern and extract it if present
                if ($SerializedInput -match '^([a-zA-Z0-9_-]+):') {
                    # Extract the variable name and strip it from the serialized string
                    $headerName = $matches[1]
                    $SerializedInput = ($SerializedInput -replace "^$($headerName):", '').Trim()
                }

                $segments = $SerializedInput -split ','

                # If there's only one segment, return it directly
                if ($segments.Count -eq 1) {
                    $result = $segments[0]
                }
                else {
                    if ($Explode) {
                        # Handling explode=true case

                        # Check if the number of '=' is equal to the count of segments
                        if ((($SerializedInput -split '=').Count - 1) -eq $segments.Count) {
                            $obj = @{}
                            foreach ($pair in $segments) {
                                if ($pair.Contains('=')) {
                                    $key, $value = $pair -split '=', 2  # Split into exactly two parts
                                    $obj[$key] = $value
                                }
                            }
                            $result = $obj
                        }
                        else {
                            # Return as an array if the explode conditions don't match
                            $result = $segments
                        }
                    }
                    else {
                        # Handling explode=false case

                        # Check if it's likely an object by checking if the count of segments is even
                        if ($segments.Count % 2 -eq 0) {
                            # Try to parse as an object
                            $obj = @{}
                            for ($i = 0; $i -lt $segments.Count; $i += 2) {
                                $key = $segments[$i]
                                # Validate the key format
                                if ($key -match '^[a-zA-Z_][a-zA-Z0-9_]*$') {
                                    $obj[$key] = $segments[$i + 1]
                                }
                                else {
                                    # If the key is invalid, return the original segments as an array
                                    $result = $segments
                                }
                            }
                            # Return the object if all keys are valid
                            $result = $obj
                        }
                        else {
                            # If not an object, treat it as an array
                            $result = $segments
                        }
                    }
                }

                if ($headerName) {
                    return @{$headerName = $result }
                }
                else {
                    return $result
                }

            }
            'Label' {
                # Remove the leading dot (.) prefix from the serialized string
                $SerializedInput = $SerializedInput.TrimStart('.')

                # Split the string by dot
                $segments = $SerializedInput -split '\.'

                # Handle the explode=true case
                if ($Explode) {
                    # Handling explode=true: each segment is a key=value pair
                    $obj = @{}
                    foreach ($segment in $segments) {
                        if ($segment.Contains('=')) {
                            $key, $value = $segment -split '=', 2  # Split into exactly two parts
                            $obj[$key] = $value
                        }
                        else {
                            # If a segment does not contain '=', treat it as an array element
                            return $segments -split ','
                        }
                    }
                    return $obj
                }
                else {
                    # Handling explode=false: all segments form a combined structure
                    # Split the string by commas within each segment
                    $combinedSegments = ($SerializedInput -split ',')

                    # Check if it's likely an object by checking if the count is even
                    if ($combinedSegments.Count % 2 -eq 0) {
                        # Try to parse as an object
                        $obj = @{}
                        for ($i = 0; $i -lt $combinedSegments.Count; $i += 2) {
                            $key = $combinedSegments[$i]

                            # Validate if the key is a suitable key
                            if ($key -match '^[a-zA-Z_][a-zA-Z0-9_]*$') {
                                $value = $combinedSegments[$i + 1]
                                $obj[$key] = $value
                            }
                            else {
                                # If validation fails, return segments as array
                                return $combinedSegments
                            }
                        }
                        return $obj
                    }

                    # If not an object, return as an array
                    return $combinedSegments
                }
            }
            'Matrix' {
                # Handle the explode=true case
                if ($Explode) {
                    # Remove the leading semicolon (;) prefix from the serialized string
                    $SerializedInput = $SerializedInput.TrimStart(';')

                    # Split by semicolon to get segments
                    $segments = $SerializedInput -split ';'

                    # If each segment doesn't contain '=', treat it as an array
                    if ($segments -notmatch '=') {
                        # Return as an array of individual elements split by commas
                        return $segments -split ','
                    }

                    # Initialize an empty hashtable to store key-value pairs
                    $obj = @{}
                    $values = @()


                    foreach ($segment in $segments) {
                        if ($segment.Contains('=')) {
                            $key, $value = $segment -split '=', 2

                            # If the key matches the specified key name
                            if ($key -eq $ParameterName) {
                                $values += $value
                            }
                            else {
                                # If a key doesn't match, treat as a normal key-value pair in the hashtable
                                $obj[$key] = $value
                            }
                        }
                    }

                    # If all segments matched the specified key name, return the values as an array
                    if ($values.Count -eq $segments.Count) {
                        if ($values.Count -eq 1) {
                            return $values[0]
                        }
                        return $values
                    }

                    # Merge values back into the object if any key matches the KeyName
                    if ($values.Count -gt 0) {
                        $obj[$ParameterName] = if ($values.Count -eq 1) { $values[0] } else { $values }
                    }

                    # Return the hashtable if it contains any key-value pairs
                    if ($obj.Count -gt 0) {
                        return $obj
                    }
                    else {
                        return $values
                    }
                }
                else {
                    # Handling explode=false:

                    # Remove the leading semicolon (;) prefix from the serialized string
                    $SerializedInput = $SerializedInput.TrimStart(";$ParameterName=")

                    # Split by semicolon to get segments
                    $segments = $SerializedInput -split ','

                    # If there's only one segment, return it directly
                    if ($segments.Count -eq 1) {
                        return $segments[0]
                    }

                    # Check if it's likely an object by checking if the count of segments is even
                    if ($segments.Count % 2 -eq 0) {
                        # Try to parse as an object
                        $obj = @{}
                        for ($i = 0; $i -lt $segments.Count; $i += 2) {
                            $key = $segments[$i]
                            # Validate the key format
                            if ($key -match '^[a-zA-Z_][a-zA-Z0-9_]*$') {
                                $obj[$key] = $segments[$i + 1]
                            }
                            else {
                                # If the key is invalid, return the original segments as an array
                                return $segments
                            }
                        }
                        # Return the object if all keys are valid
                        return $obj
                    }

                    # If not an object, treat it as an array
                    return $segments
                }
            }

            'Form' {
                # Check for header pattern and extract it if present
                if ($SerializedInput -match '^([a-zA-Z0-9_-]+):') {
                    # Extract the variable name and strip it from the serialized string
                    $headerName = $matches[1]
                    $SerializedInput = ($SerializedInput -replace "^$($headerName):", '').Trim().TrimStart("$ParameterName=")
                }
                else {
                    if ($Explode) {
                        # Remove the leading semicolon (;) prefix from the serialized string
                        $SerializedInput = $SerializedInput.TrimStart('?')
                    }
                    else {
                        # Remove the leading semicolon (;) prefix from the serialized string
                        $SerializedInput = $SerializedInput.TrimStart("?$ParameterName=")
                    }
                }

                # Handle the explode=true case
                if ($Explode) {
                    # Split by semicolon to get segments
                    $segments = $SerializedInput -split '&'

                    # If each segment doesn't contain '=', treat it as an array
                    if ($segments -notmatch '=') {
                        # Return as an array of individual elements split by commas
                        $result = $segments -split ','
                    }
                    else {
                        # Initialize an empty hashtable to store key-value pairs
                        $obj = @{}
                        $values = @()

                        foreach ($segment in $segments) {
                            if ($segment.Contains('=')) {
                                $key, $value = $segment -split '=', 2

                                # If the key matches the specified key name
                                if ($key -eq $ParameterName) {
                                    $values += $value
                                }
                                else {
                                    # If a key doesn't match, treat as a normal key-value pair in the hashtable
                                    $obj[$key] = $value
                                }
                            }
                        }

                        # If all segments matched the specified key name, return the values as an array
                        if ($values.Count -eq $segments.Count) {
                            if ($values.Count -eq 1) {
                                $result = $values[0]
                            }
                            else {
                                $result = $values
                            }
                        }
                        else {

                            # Merge values back into the object if any key matches the KeyName
                            if ($values.Count -gt 0) {
                                $obj[$ParameterName] = if ($values.Count -eq 1) { $values[0] } else { $values }
                            }

                            # Return the hashtable if it contains any key-value pairs
                            if ($obj.Count -gt 0) {
                                return $obj
                            }
                            else {
                                return $values
                            }
                        }
                    }
                }
                else {
                    # Handling explode=false

                    # Split by semicolon to get segments
                    $segments = $SerializedInput -split ','

                    # If there's only one segment, return it directly
                    if ($segments.Count -eq 1) {
                        $result = $segments[0]
                    }
                    # Check if it's likely an object by checking if the count of segments is even
                    elseif ($segments.Count % 2 -eq 0) {
                        # Try to parse as an object
                        $obj = @{}
                        for ($i = 0; $i -lt $segments.Count; $i += 2) {
                            $key = $segments[$i]
                            # Validate the key format
                            if ($key -match '^[a-zA-Z_][a-zA-Z0-9_]*$') {
                                $obj[$key] = $segments[$i + 1]
                            }
                            else {
                                # If the key is invalid, return the original segments as an array
                                $result = $segments
                                break
                            }
                        }
                        if (!$result) {
                            # Return the object if all keys are valid
                            $result = $obj
                        }
                    }
                    else {
                        # If not an object, treat it as an array
                        $result = $segments
                    }

                }

                if ($headerName) {
                    return @{$headerName = $result }
                }
                else {
                    return $result
                }
            }

            'SpaceDelimited' {
                if ($Explode) {
                    # For explode=true, split by '&' to treat each value as a separate occurrence
                    $segments = $SerializedInput -split '&'

                    # Initialize an array to store values that match the specified KeyName
                    $values = @()
                    foreach ($segment in $segments) {
                        if ($segment.Contains('=')) {
                            $key, $value = $segment -split '=', 2
                            # Only add values where the key matches the specified KeyName
                            if ($key -eq $ParameterName) {
                                $values += $value
                            }
                        }
                    }
                    # Return the array of values that matched the KeyName
                    return $values
                }
                else {
                    # Remove the leading semicolon '?id=' prefix from the serialized string
                    $SerializedInput = $SerializedInput.TrimStart('?id=')
                    # For explode=false, split by space (%20) to handle the combined string format
                    return $SerializedInput -split ' '
                }
            }

            'PipeDelimited' {
                if ($Explode) {
                    $SerializedInput = $SerializedInput.TrimStart('?')
                    # For explode=true, split by '&' to treat each value as a separate occurrence
                    $segments = $SerializedInput -split '&'

                    # Initialize an array to store values that match the specified KeyName
                    $values = @()
                    foreach ($segment in $segments) {
                        if ($segment.Contains('=')) {
                            $key, $value = $segment -split '=', 2
                            # Only add values where the key matches the specified KeyName
                            if ($key -eq $ParameterName) {
                                $values += $value
                            }
                        }
                    }
                    # Return the array of values that matched the KeyName
                    return $values
                }
                else {
                    # Remove the leading '?id=' prefix from the serialized string
                    $SerializedInput = $SerializedInput.TrimStart('?id=')
                    # For explode=false, split by | to handle the combined string format
                    return $SerializedInput -split '\|'
                }
            }

            'DeepObject' {
                $SerializedInput = $SerializedInput.TrimStart('?')

                # Split the string by '&' to get each key-value pair
                $segments = $SerializedInput -split '&'

                # Initialize an empty hashtable to store the nested key-value pairs
                $obj = @{}
                foreach ($segment in $segments) {
                    if ($segment.Contains('=')) {
                        # Split each segment by '=' into key and value
                        $key, $value = $segment -split '=', 2

                        # Extract the main key and nested keys using regex
                        $allMatches = [regex]::Matches($key, '([^\[\]]+)')

                        # Extract the main key (first match) and remaining nested keys
                        $mainKey = $allMatches[0].Groups[1].Value
                        # Manually extract remaining nested keys as a list of strings
                        $nestedKeys = @()
                        for ($i = 1; $i -lt $allMatches.Count; $i++) {
                            $nestedKeys += $allMatches[$i].Groups[1].Value
                        }

                        # Only process the segment if the main key matches the specified KeyName
                        if ($mainKey -eq $ParameterName) {
                            # Initialize a reference to the root object
                            $current = $obj

                            # Iterate over the nested keys to build the structure
                            foreach ($nestedKey in $nestedKeys) {
                                # If this is the last key, assign the value
                                if ($nestedKey -eq $nestedKeys[-1]) {
                                    $current[$nestedKey] = $value
                                }
                                else {
                                    # Create a new hashtable if the nested key doesn't exist
                                    if (-not $current.ContainsKey($nestedKey)) {
                                        $current[$nestedKey] = @{}
                                    }
                                    # Move deeper into the nested structure
                                    $current = $current[$nestedKey]
                                }
                            }
                        }
                    }
                }

                # Return the constructed hashtable with nested keys and values
                return $obj
            }
        }
    }
}