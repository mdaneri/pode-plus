
<#
.SYNOPSIS
    Validates and verifies the authenticity of a JSON Web Token (JWT).

  .DESCRIPTION
    This function validates a JWT by:
    - Splitting and decoding the token.
    - Verifying the algorithm used.
    - Performing signature validation using HMAC, RSA, or ECDSA.
    - Supporting configurable verification modes.
    - Returning the payload if valid.

  .PARAMETER Token
    The JWT string to be validated in `header.payload.signature` format.

  .PARAMETER Algorithm
    Supported JWT signing algorithms: HS256, RS256, ES256, etc.

  .PARAMETER Secret
    SecureString key for HMAC algorithms.

  .PARAMETER X509Certificate
    X509Certificate2 object for RSA/ECDSA verification.

  .OUTPUTS
    Returns the JWT payload if the token is valid.

  .EXAMPLE
    Confirm-PodeJwt -Token $jwt -Algorithm RS256 -Certificate $cert

.NOTES
    - Throws an exception if the JWT is invalid, expired, or tampered with.
    - The function does not check the `exp`, `nbf`, or `iat` claims.
    - Use `Test-PodeJwt` separately to validate JWT claims.
#>
function Confirm-PodeJwt {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [ValidateSet('NONE', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512')]
        [string[]]$Algorithm,

        [Parameter()]
        [securestring]$Secret, # Required for HMAC

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $X509Certificate
    )

    # Split JWT into header, payload, and signature
    $parts = $Token -split '\.'
    if (($parts.Length -ne 3)) {
        throw ($PodeLocale.invalidJwtSuppliedExceptionMessage)
    }

    # Decode the JWT header
    $header = ConvertFrom-PodeJwtBase64Value -Value $parts[0]

    # Decode the JWT payload
    $payload = ConvertFrom-PodeJwtBase64Value -Value $parts[1]

    # Apply verification mode for algorithm enforcement
    if ($Algorithm -notcontains $header.alg) {
        throw ($PodeLocale.jwtAlgorithmMismatchExceptionMessage -f ($Algorithm -join ','), $header.alg)
    }

    $Algorithm = $header.alg

    # Handle none algorithm cases
    $isNoneAlg = ($header.alg -eq 'NONE')
    if ([string]::IsNullOrEmpty($Algorithm)) {
        throw ($PodeLocale.noAlgorithmInJwtHeaderExceptionMessage)
    }

    # Ensure secret/certificate presence when required
    if (($null -eq $Secret) -and ( $null -eq $X509Certificate) -and !$isNoneAlg) {
        # No JWT signature supplied for {0}
        throw  ($PodeLocale.noJwtSignatureForAlgorithmExceptionMessage -f $header.alg)
    }
    if ((( $null -ne $X509Certificate) -or ($null -ne $Secret)) -and $isNoneAlg) {
        # Expected no JWT signature to be supplied
        throw ($PodeLocale.expectedNoJwtSignatureSuppliedExceptionMessage)
    }

    if ((![string]::IsNullOrEmpty($parts[2]) -and $isNoneAlg)) {
        throw ($PodeLocale.invalidJwtSuppliedExceptionMessage)
    }

    if ($isNoneAlg) {
        return $payload
    }
    if ($null -ne $Secret) {
        # Convert Secret to bytes if provided
        $secretBytes = Convert-PodeSecureStringToByteArray -SecureString $Secret
    }

    if ($isNoneAlg -and ($null -ne $SecretBytes) -and ($SecretBytes.Length -gt 0)) {
        # Expected no JWT signature to be supplied
        throw ($PodeLocale.expectedNoJwtSignatureSuppliedExceptionMessage)
    }

    # Prepare data for signature verification
    $headerPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])")
    # Convert JWT signature from Base64 URL to Byte Array
    $fixedSignature = $parts[2].Replace('-', '+').Replace('_', '/')
    # Add proper Base64 padding
    switch ($fixedSignature.Length % 4) {
        1 { $fixedSignature = $fixedSignature.Substring(0, $fixedSignature.Length - 1); break }  # Remove invalid character
        2 { $fixedSignature += '=='; break }  # Add two padding characters
        3 { $fixedSignature += '='; break }   # Add one padding character
    }
    $signatureBytes = [Convert]::FromBase64String($fixedSignature)

    # Verify Signature

    # Handle HMAC signature verification
    if ($Algorithm -match '^HS(\d{3})$') {
        if ($null -eq $SecretBytes) {
            throw ($PodeLocale.missingKeyForAlgorithmExceptionMessage -f 'secret', 'HMAC', $Algorithm)
        }

        # Compute HMAC Signature
        $hmac = switch ($Algorithm) {
            'HS256' { [System.Security.Cryptography.HMACSHA256]::new($SecretBytes); break }
            'HS384' { [System.Security.Cryptography.HMACSHA384]::new($SecretBytes); break }
            'HS512' { [System.Security.Cryptography.HMACSHA512]::new($SecretBytes); break }
        }
        # Prepare JWT signing input
        $expectedSignatureBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"))
        $expectedSignature = [Convert]::ToBase64String($expectedSignatureBytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')

        # Compare signatures
        if ($expectedSignature -ne $parts[2]) {
            throw ($PodeLocale.invalidJwtSignatureSuppliedExceptionMessage)
        }
    }
    elseif ($Algorithm -match '^(RS|PS)(\d{3})$') {
        # Extract the RSA public key from the existing certificate object
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($X509Certificate)

        $hashAlgo = switch ($Algorithm) {
            'RS256' { [System.Security.Cryptography.HashAlgorithmName]::SHA256; break }
            'RS384' { [System.Security.Cryptography.HashAlgorithmName]::SHA384; break }
            'RS512' { [System.Security.Cryptography.HashAlgorithmName]::SHA512; break }
            'PS256' { [System.Security.Cryptography.HashAlgorithmName]::SHA256; break }
            'PS384' { [System.Security.Cryptography.HashAlgorithmName]::SHA384; break }
            'PS512' { [System.Security.Cryptography.HashAlgorithmName]::SHA512; break }
        }

        $rsaPadding = if ($Algorithm -match '^PS') {
            [System.Security.Cryptography.RSASignaturePadding]::Pss
        }
        else {
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        }
        if (!($rsa.VerifyData($headerPayloadBytes, $signatureBytes, $hashAlgo, $rsaPadding))) {
            throw ($PodeLocale.invalidJwtSignatureSuppliedExceptionMessage)
        }
    }
    elseif ($Algorithm -match '^ES(\d{3})$') {
        # Extract the ECSDA public key from the existing certificate object
        $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($X509Certificate)

        $hashAlgo = switch ($Algorithm) {
            'ES256' { [System.Security.Cryptography.HashAlgorithmName]::SHA256; break }
            'ES384' { [System.Security.Cryptography.HashAlgorithmName]::SHA384; break }
            'ES512' { [System.Security.Cryptography.HashAlgorithmName]::SHA512; break }
        }
        if (!($ecdsa.VerifyData($headerPayloadBytes, $signatureBytes, $hashAlgo))) {
            throw ($PodeLocale.invalidJwtSignatureSuppliedExceptionMessage)
        }
    }

    return $payload
}

function ConvertTo-PodeBase64UrlValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value,

        [switch]
        $NoConvert
    )

    if (!$NoConvert) {
        $Value = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Value))
    }

    return $Value.Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function ConvertFrom-PodeJwtBase64Value {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    # map chars
    $Value = $Value.Replace('-', '+').Replace('_', '/')
    # Add proper Base64 padding
    switch ($Value.Length % 4) {
        1 { $Value = $Value.Substring(0, $Value.Length - 1) }  # Remove invalid character
        2 { $Value += '==' }  # Add two padding characters
        3 { $Value += '=' }   # Add one padding character
    }
    # convert base64 to string
    try {
        $Value = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Value))
    }
    catch {
        # Invalid Base64 encoded value found in JWT
        throw ($PodeLocale.invalidBase64JwtExceptionMessage)
    }
    # return json
    try {
        return ($Value | ConvertFrom-Json)
    }
    catch {
        # Invalid JSON value found in JWT
        throw ($PodeLocale.invalidJsonJwtExceptionMessage)
    }
}

<#
.SYNOPSIS
    Computes a cryptographic hash using the specified algorithm.

.DESCRIPTION
    This function accepts a string and an algorithm name, computes the hash using the specified algorithm,
    and returns the hash as a lowercase hexadecimal string.

.PARAMETER Value
    The input string to be hashed.

.PARAMETER Algorithm
    The hashing algorithm to use (SHA-1, SHA-256, SHA-512, SHA-512/256).

.OUTPUTS
    [string] - The computed hash in hexadecimal format.

.NOTES
    Internal Pode function for authentication hashing.
#>
function ConvertTo-PodeDigestHash {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        $Value,

        [Parameter(Mandatory = $true)]
        [ValidateSet('MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'SHA-384', 'SHA-512/256')]
        [string]
        $Algorithm
    )

    # Select the appropriate hash algorithm
    $crypto = switch ($Algorithm) {
        'MD5' { [System.Security.Cryptography.MD5]::Create(); break }
        'SHA-1' { [System.Security.Cryptography.SHA1]::Create(); break }
        'SHA-256' { [System.Security.Cryptography.SHA256]::Create(); break }
        'SHA-384' { [System.Security.Cryptography.SHA384]::Create(); break }
        'SHA-512' { [System.Security.Cryptography.SHA512]::Create(); break }
        'SHA-512/256' {
            # Compute SHA-512 and truncate to 256 bits (first 32 bytes)
            $sha512 = [System.Security.Cryptography.SHA512]::Create()
            $fullHash = $sha512.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
            return [System.BitConverter]::ToString($fullHash[0..31]).Replace('-', '').ToLowerInvariant()
        }
    }

    return [System.BitConverter]::ToString($crypto.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))).Replace('-', '').ToLowerInvariant()
}

<#
.SYNOPSIS
    Determines the JWT signing algorithm based on the provided X.509 certificate.

.DESCRIPTION
    This function extracts the private key (RSA or ECDSA) from a given X.509 certificate (PFX) and determines the appropriate JSON Web Token (JWT) signing algorithm.
    For RSA keys, the function attempts to read the key size using the `KeySize` property. On Linux with .NET 9, this property is write-only, so a reflection-based workaround is used to retrieve the private `KeySizeValue` field.
    For ECDSA keys, the algorithm is selected directly based on the key size.

.PARAMETER X509Certificate
    A System.Security.Cryptography.X509Certificates.X509Certificate2 object representing the certificate (PFX) from which the private key is extracted.

.PARAMETER RsaPaddingScheme
    Specifies the RSA padding scheme to use. Acceptable values are 'Pkcs1V15' (default) and 'Pss'.

.EXAMPLE
    PS> Get-PodeJwtSigningAlgorithm -X509Certificate $myCert -RsaPaddingScheme 'Pkcs1V15'
    Determines and returns the appropriate JWT signing algorithm (e.g., 'RS256', 'RS384', 'RS512' for RSA or 'ES256', 'ES384', 'ES512' for ECDSA) based on the certificate's key.

.NOTES
    This function includes a reflection-based workaround for .NET 9 on Linux where the RSA `KeySize` property is write-only. Refer to https://github.com/dotnet/runtime/issues/112622 for more details.
#>
function Get-PodeJwtSigningAlgorithm {
    param (

        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $X509Certificate, # PFX

        [ValidateSet('Pkcs1V15', 'Pss')]
        [string]$RsaPaddingScheme = 'Pkcs1V15'  # Default to PKCS#1 v1.5 unless specified
    )
    # Extract Private Key (RSA or ECDSA)
    $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($X509Certificate)
    if ($null -ne $key) {
        Write-Verbose 'RSA Private Key detected.'
        try {
            $keySize = $key.KeySize
        }
        catch {
            # Exception is 'Cannot get property value because "KeySize" is a write-only property.'
            # Use reflection to access the private 'KeySizeValue' field
            $bindingFlags = [System.Reflection.BindingFlags] 'NonPublic, Instance'
            $keySizeField = $key.GetType().GetField('KeySizeValue', $bindingFlags)

            # Retrieve the value of the 'KeySizeValue' field this is a workaround of an issue with .net for Linux
            Write-Verbose "Keysize obtained by reflection  $($keySizeField.GetValue($key))"
            $keySize = $keySizeField.GetValue($key)
        }
        # Determine RSA key size
        switch ($keySize) {
            2048 { return $(if ($RsaPaddingScheme -eq 'Pkcs1V15') { 'RS256' } else { 'PS256' }) }
            3072 { return $(if ($RsaPaddingScheme -eq 'Pkcs1V15') { 'RS384' } else { 'PS384' }) }
            4096 { return $(if ($RsaPaddingScheme -eq 'Pkcs1V15') { 'RS512' } else { 'PS512' }) }
            default { throw ($PodeLocale.unknownAlgorithmWithKeySizeExceptionMessage -f 'RSA', $rsa.KeySize) }
        }
    }
    else {
        $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($X509Certificate)
        if ($null -ne $key) {
            Write-Verbose 'ECDSA Private Key detected.'

            # Determine ECDSA key size
            switch ($key.KeySize) {
                256 { return 'ES256' }
                384 { return 'ES384' }
                521 { return 'ES512' }  # JWT uses 521-bit, NOT 512-bit
                default { throw ($PodeLocale.unknownAlgorithmWithKeySizeExceptionMessage -f 'ECDSA' , $ecdsa.KeySize) }
            }
        }
        else {
            throw $PodeLocale.unknownAlgorithmOrInvalidPfxExceptionMessage
        }
    }
}




<#
.SYNOPSIS
    Generates a JSON Web Token (JWT) based on the specified headers, payload, and signing credentials.
.DESCRIPTION
    This function creates a JWT by combining a Base64URL-encoded header and payload. Depending on the
    configured parameters, it supports various signing algorithms, including HMAC- and certificate-based
    signatures. You can also omit a signature by specifying 'none'.

.PARAMETER Header
    Additional header values for the JWT. Defaults to an empty hashtable if not specified.

.PARAMETER Payload
    The required hashtable specifying the token’s claims.

.PARAMETER Algorithm
    A string representing the signing algorithm to be used. Accepts 'NONE', 'HS256', 'HS384', or 'HS512'.

.PARAMETER Secret
    Used in conjunction with HMAC signing. Can be either a byte array or a SecureString. Required if you
    select the 'SecretBytes' parameter set.

.PARAMETER X509Certificate
    An X509Certificate2 object used for RSA/ECDSA-based signing. Required if you select the 'CertRaw' parameter set.

.PARAMETER Certificate
    The path to a certificate file used for signing. Required if you select the 'CertFile' parameter set.

.PARAMETER PrivateKeyPath
    Optional path to an associated certificate key file.

.PARAMETER CertificatePassword
    An optional SecureString password for a certificate file.

.PARAMETER CertificateThumbprint
    A string thumbprint of a certificate in the local store. Required if you select the 'CertThumb' parameter set.

.PARAMETER CertificateName
    A string name of a certificate in the local store. Required if you select the 'CertName' parameter set.

.PARAMETER CertificateStoreName
    The store name to search for the specified certificate. Defaults to 'My'.

.PARAMETER CertificateStoreLocation
    The certificate store location for the specified certificate. Defaults to 'CurrentUser'.

.PARAMETER RsaPaddingScheme
    Specifies the RSA padding scheme to use. Accepts 'Pkcs1V15' or 'Pss'. Defaults to 'Pkcs1V15'.

.PARAMETER Authentication
    The name of a configured authentication method in Pode. Required if you select the 'AuthenticationMethod' parameter set.

.PARAMETER Expiration
    Time in seconds until the token expires. Defaults to 3600 (1 hour).

.PARAMETER NotBefore
    Time in seconds to offset the NotBefore claim. Defaults to 0 for immediate use.

.PARAMETER IssuedAt
    Time in seconds to offset the IssuedAt claim. Defaults to 0 for current time.

.PARAMETER Issuer
    Identifies the principal that issued the token.

.PARAMETER Subject
    Identifies the principal that is the subject of the token.

.PARAMETER Audience
    Specifies the recipients that the token is intended for.

.PARAMETER JwtId
    A unique identifier for the token.

.PARAMETER NoStandardClaims
    A switch that, if used, prevents automatically adding iat, nbf, exp, iss, sub, aud, and jti claims.

.PARAMETER Depth
    Define the default depth used to convert the payload to JSON (default 10)

.OUTPUTS
    System.String
    The resulting JWT string.


.EXAMPLE
    New-PodeJwt -Header [pscustomobject]@{ alg = 'none' } -Payload [pscustomobject]@{ sub = '123'; name = 'John' }

.EXAMPLE
    New-PodeJwt -Header [pscustomobject]@{ alg = 'HS256' } -Payload [pscustomobject]@{ sub = '123'; name = 'John' } -Secret 'abc'

.EXAMPLE
    New-PodeJwt -Header [pscustomobject]@{ alg = 'RS256' } -Payload [pscustomobject]@{ sub = '123' } -PrivateKey (Get-Content "private.pem" -Raw) -Issuer "auth.example.com" -Audience "myapi.example.com"
#>
function New-PodeJwt {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType([string])]
    param(
        [Parameter()]
        [pscustomobject]$Header,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Payload,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Secret')]
        [ValidateSet('NONE', 'HS256', 'HS384', 'HS512')]
        [string]$Algorithm,

        [Parameter(Mandatory = $true, ParameterSetName = 'Secret')]
        [byte[]]
        $Secret = $null,

        [Parameter(Mandatory = $true, ParameterSetName = 'CertRaw')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $X509Certificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'CertFile')]
        [string]
        $Certificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'CertFile')]
        [string]
        $PrivateKeyPath = $null,

        [Parameter(Mandatory = $false, ParameterSetName = 'CertFile')]
        [SecureString]
        $CertificatePassword,

        [Parameter(Mandatory = $true, ParameterSetName = 'CertThumb')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'CertName')]
        [string]
        $CertificateName,

        [Parameter(ParameterSetName = 'CertName')]
        [Parameter(ParameterSetName = 'CertThumb')]
        [System.Security.Cryptography.X509Certificates.StoreName]
        $CertificateStoreName = 'My',

        [Parameter(ParameterSetName = 'CertName')]
        [Parameter(ParameterSetName = 'CertThumb')]
        [System.Security.Cryptography.X509Certificates.StoreLocation]
        $CertificateStoreLocation = 'CurrentUser',

        [Parameter(Mandatory = $false, ParameterSetName = 'CertRaw')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertFile')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertThumb')]
        [ValidateSet('Pkcs1V15', 'Pss')]
        [string]
        $RsaPaddingScheme = 'Pkcs1V15',

        [Parameter(Mandatory = $true, ParameterSetName = 'AuthenticationMethod')]
        [string]
        $Authentication,

        [Parameter()]
        [int]
        $Expiration = 3600, # Default: 1 hour

        [Parameter()]
        [int]
        $NotBefore = 0, # Default: Immediate

        [Parameter()]
        [int]
        $IssuedAt = 0, # Default: Current time

        [Parameter()]
        [string]
        $Issuer,

        [Parameter()]
        [string]
        $Subject,

        [Parameter()]
        [string]
        $Audience,

        [Parameter()]
        [string]
        $JwtId,

        [Parameter()]
        [switch]
        $NoStandardClaims,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]
        $Depth = 10


    )
    if (!($Header.PSObject.Properties['alg'])) {
        $Header | Add-Member -MemberType NoteProperty -Name 'alg' -Value ''
    }

    # Determine actions based on parameter set
    switch ($PSCmdlet.ParameterSetName) {
        'CertFile' {
            if (!(Test-Path -Path $Certificate -PathType Leaf)) {
                throw ($PodeLocale.pathNotExistExceptionMessage -f $Certificate)
            }

            # Retrieve X509 certificate from a file
            $X509Certificate = Get-PodeCertificateByFile -Certificate $Certificate -SecurePassword $CertificatePassword -PrivateKeyPath $PrivateKeyPath
            break
        }

        'certthumb' {
            # Retrieve X509 certificate from store by thumbprint
            $X509Certificate = Get-PodeCertificateByThumbprint -Thumbprint $CertificateThumbprint -StoreName $CertificateStoreName -StoreLocation $CertificateStoreLocation
        }

        'certname' {
            # Retrieve X509 certificate from store by name
            $X509Certificate = Get-PodeCertificateByName -Name $CertificateName -StoreName $CertificateStoreName -StoreLocation $CertificateStoreLocation
        }

        'Secret' {
            # If algorithm was already set in the header, default to it if none provided
            if (!([string]::IsNullOrWhiteSpace($Header.alg))) {
                if ([string]::IsNullOrWhiteSpace($Algorithm)) {
                    $Algorithm = $Header.alg.ToUpper()
                }
            }

            # Validate that 'none' has no secret
            if (($Algorithm -ieq 'none')) {
                throw ($PodeLocale.noSecretExpectedForNoSignatureExceptionMessage)
            }

            # Convert secret to a byte array if needed
            if ($null -eq $Secret) {
                throw ($PodeLocale.missingKeyForAlgorithmExceptionMessage -f 'secret', 'HMAC', $Header.alg)
            }


            if ([string]::IsNullOrWhiteSpace($Algorithm)) {
                $Algorithm = 'HS256'
            }

            $Header.alg = $Algorithm.ToUpper()
            $params = @{
                Algorithm   = $Algorithm.ToUpper()
                SecretBytes = $Secret
            }
            break
        }

        'CertRaw' {
            # Validate that a raw certificate is present
            if ($null -eq $X509Certificate) {
                throw ($PodeLocale.missingKeyForAlgorithmExceptionMessage -f 'private', 'RSA/ECSDA', $Header.alg)
            }
            break
        }

        'AuthenticationMethod' {
            # Retrieve authentication details from Pode's context
            if ($PodeContext -and $PodeContext.Server.Authentications.Methods.ContainsKey($Authentication)) {
                # If 'none' was set in the header but is not supported by the method, throw
                if (($Header.alg -ieq 'none') -and $PodeContext.Server.Authentications.Methods.ContainsKey($Authentication).Algorithm -notcontains 'none') {
                    throw ($PodeLocale.noSecretExpectedForNoSignatureExceptionMessage)
                }
                $Header.alg = $PodeContext.Server.Authentications.Methods[$Authentication].Scheme.Arguments.Algorithm[0]
                $params = @{
                    Authentication = $Authentication
                }
            }
            else {
                throw ($PodeLocale.authenticationMethodDoesNotExistExceptionMessage)
            }
        }
    }

    # Configure the JWT header and parameters if using a certificate
    if ($null -ne $X509Certificate) {

        # Skip certificate validation if it has been explicitly provided as a variable.
        if ($PSCmdlet.ParameterSetName -ne 'CertRaw') {
            # Validate that the certificate:
            # 1. Is within its validity period.
            # 2. Has a valid certificate chain.
            # 3. Is explicitly authorized for the expected purpose (Code Signing).
            # 4. Meets strict Enhanced Key Usage (EKU) enforcement.
            $null = Test-PodeCertificate -Certificate $X509Certificate -ExpectedPurpose CodeSigning -Strict -ErrorAction Stop
        }

        $Header.alg = Get-PodeJwtSigningAlgorithm -X509Certificate $X509Certificate -RsaPaddingScheme $RsaPaddingScheme
        $params = @{
            X509Certificate  = $X509Certificate
            RsaPaddingScheme = $RsaPaddingScheme
        }
    }

    # Optionally add standard claims if not suppressed
    if (!$NoStandardClaims) {
        if (! $Header.PSObject.Properties['typ']) {
            $Header | Add-Member -MemberType NoteProperty -Name 'typ' -Value 'JWT'
        }
        else {
            $Header.typ = 'JWT'
        }

        # Current Unix time
        $currentUnix = [int][Math]::Floor(([DateTimeOffset]::new([DateTime]::UtcNow)).ToUnixTimeSeconds())

        if (! $Payload.PSObject.Properties['iat']) {
            $Payload | Add-Member -MemberType NoteProperty -Name 'iat' -Value $(if ($IssuedAt -gt 0) { $IssuedAt } else { $currentUnix })
        }
        if (! $Payload.PSObject.Properties['nbf']) {
            $Payload | Add-Member -MemberType NoteProperty -Name 'nbf' -Value ($currentUnix + $NotBefore)
        }
        if (! $Payload.PSObject.Properties['exp']) {
            $Payload | Add-Member -MemberType NoteProperty -Name 'exp' -Value ($currentUnix + $Expiration)
        }

        if (! $Payload.PSObject.Properties['iss']) {
            if ([string]::IsNullOrEmpty($Issuer)) {
                if ($null -ne $PodeContext) {
                    $Payload | Add-Member -MemberType NoteProperty -Name 'iss' -Value 'Pode'
                }
            }
            else {
                $Payload | Add-Member -MemberType NoteProperty -Name 'iss' -Value $Issuer
            }
        }

        if (! $Payload.PSObject.Properties['sub'] -and ![string]::IsNullOrEmpty($Subject)) {
            $Payload | Add-Member -MemberType NoteProperty -Name 'sub' -Value $Subject
        }

        if (! $Payload.PSObject.Properties['aud']) {
            if ([string]::IsNullOrEmpty($Audience)) {
                if (($null -ne $PodeContext) -and ($null -ne $PodeContext.Server.ApplicationName)) {
                    $Payload | Add-Member -MemberType NoteProperty -Name 'aud' -Value $PodeContext.Server.ApplicationName
                }
            }
            else {
                $Payload | Add-Member -MemberType NoteProperty -Name 'aud' -Value $Audience
            }
        }

        if (! $Payload.PSObject.Properties['jti'] ) {
            if ([string]::IsNullOrEmpty($JwtId)) {
                $Payload | Add-Member -MemberType NoteProperty -Name 'jti' -Value (New-PodeGuid)
            }
            else {
                $Payload | Add-Member -MemberType NoteProperty -Name 'jti' -Value $JwtId
            }
        }
    }

    # Encode header and payload as Base64URL
    $header64 = ConvertTo-PodeBase64UrlValue -Value ($Header | ConvertTo-Json -Compress)
    $payload64 = ConvertTo-PodeBase64UrlValue -Value ($Payload | ConvertTo-Json -Compress -Depth $Depth)

    # Combine header and payload
    $jwt = "$($header64).$($payload64)"

    # Generate signature if not 'none'
    $sig = if ($Header.alg -ne 'none') {
        $params['Token'] = $jwt
        New-PodeJwtSignature @params
    }
    else {
        [string]::Empty
    }

    # Concatenate signature to form the final JWT
    $jwt += ".$($sig)"
    return $jwt
}






<#
.SYNOPSIS
    Generates a JWT-compatible signature using a specified RFC 7518 signing algorithm.

.DESCRIPTION
    This function creates a JWT signature for a given token using the provided algorithm and secret key bytes.
    It ensures that a secret is supplied when required and throws an exception if constraints are violated.
    The signature is computed using HMAC (HS256, HS384, HS512), RSA (RS256, RS384, RS512, PS256, PS384, PS512), or ECDSA (ES256, ES384, ES512).

.PARAMETER Algorithm
    The signing algorithm. Supported values: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512.

.PARAMETER Token
    The JWT token to be signed.

.PARAMETER SecretBytes
    The secret key in byte array format used for signing the JWT using the HMAC algorithms.
    This parameter is optional when using the 'none' algorithm.

.PARAMETER X509Certificate
    The private key certificate for RSA or ECDSA algorithms.

.PARAMETER RsaPaddingScheme
    RSA padding scheme to use, default is `Pkcs1V15`.

.OUTPUTS
    [string] - The JWT signature as a base64url-encoded string.

.EXAMPLE
    $token = "header.payload"
    $key = [System.Text.Encoding]::UTF8.GetBytes("my-secret-key")
    $signature = New-PodeJwtSignature -Algorithm "HS256" -Token $token -SecretBytes $key

    This example generates a JWT signature using the HMAC SHA-256 algorithm.

.EXAMPLE
    $privateKey = Get-Content "private_key.pem" -Raw
    $signature = New-PodeJwtSignature -Algorithm RS256 -Token "header.payload" -X509Certificate $certificate

.NOTES
    This function is an internal Pode function and is subject to change.
#>
function New-PodeJwtSignature {
    [CmdletBinding(DefaultParameterSetName = 'SecretBytes')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'SecretBytes')]
        [Parameter(Mandatory = $true, ParameterSetName = 'SecretSecureString')]
        [ValidateSet('HS256', 'HS384', 'HS512')]
        [string]
        $Algorithm,

        [Parameter(Mandatory = $true)]
        [string]
        $Token,

        [Parameter(Mandatory = $true, ParameterSetName = 'SecretBytes')]
        [byte[]]
        $SecretBytes,

        [Parameter(Mandatory = $true, ParameterSetName = 'SecretSecureString')]
        [securestring]
        $Secret,

        [Parameter( Mandatory = $true, ParameterSetName = 'X509Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $X509Certificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'X509Certificate')]
        [ValidateSet('Pkcs1V15', 'Pss')]
        [string]
        $RsaPaddingScheme = 'Pkcs1V15',

        [Parameter(Mandatory = $true, ParameterSetName = 'AuthenticationMethod')]
        [string]
        $Authentication
    )
    $alg = $Algorithm
    switch ($PSCmdlet.ParameterSetName) {
        'SecretBytes' {
            if ($null -eq $SecretBytes) {
                throw ($PodeLocale.missingKeyForAlgorithmExceptionMessage -f 'secret', 'HMAC', $Algorithm)
            }
            break
        }
        'SecretSecureString' {
            if ($null -eq $Secret) {
                throw ($PodeLocale.missingKeyForAlgorithmExceptionMessage -f 'secret', 'HMAC', $Algorithm)
            }
            # Convert Secret to bytes if provided
            $secretBytes = Convert-PodeSecureStringToByteArray -SecureString $Secret
            break
        }
        'X509Certificate' {
            if ($null -eq $X509Certificate) {
                throw ($PodeLocale.missingKeyForAlgorithmExceptionMessage -f 'private', 'RSA/ECSDA', $Algorithm)
            }
            $alg = Get-PodeJwtSigningAlgorithm -X509Certificate $X509Certificate -RsaPaddingScheme $RsaPaddingScheme

            break
        }
        'AuthenticationMethod' {
            if ($PodeContext -and $PodeContext.Server.Authentications.Methods.ContainsKey($Authentication)) {
                $method = $PodeContext.Server.Authentications.Methods[$Authentication].Scheme.Arguments
                $alg = $method.Algorithm
                if ($null -ne $method.X509Certificate) {
                    $X509Certificate = $method.X509Certificate
                }
                if ($null -ne $method.Secret) {
                    $secretBytes = Convert-PodeSecureStringToByteArray -SecureString $method.Secret
                }
            }
            else {
                throw ($PodeLocale.authenticationMethodDoesNotExistExceptionMessage)
            }
        }
    }

    $valueBytes = [System.Text.Encoding]::UTF8.GetBytes($Token)

    switch ($alg) {

        # HMAC-SHA (HS256, HS384, HS512)
        { $_ -match '^HS(\d{3})$' } {

            # Map HS256, HS384, HS512 to their respective classes
            $hmac = switch ($alg) {
                'HS256' { [System.Security.Cryptography.HMACSHA256]::new($SecretBytes); break }
                'HS384' { [System.Security.Cryptography.HMACSHA384]::new($SecretBytes); break }
                'HS512' { [System.Security.Cryptography.HMACSHA512]::new($SecretBytes); break }
                default { throw ($PodeLocale.unsupportedJwtAlgorithmExceptionMessage -f $alg) }
            }

            $signature = $hmac.ComputeHash($valueBytes)
            break
        }

        # RSA (RS256, RS384, RS512, PS256, PS384, PS512)
        { $_ -match '^(RS|PS)(\d{3})$' } {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($X509Certificate)

            # Map RS256, RS384, RS512 to their correct SHA algorithm
            $hashAlgo = switch ($alg) {
                'RS256' { [System.Security.Cryptography.HashAlgorithmName]::SHA256; break }
                'RS384' { [System.Security.Cryptography.HashAlgorithmName]::SHA384; break }
                'RS512' { [System.Security.Cryptography.HashAlgorithmName]::SHA512; break }
                'PS256' { [System.Security.Cryptography.HashAlgorithmName]::SHA256; break }
                'PS384' { [System.Security.Cryptography.HashAlgorithmName]::SHA384; break }
                'PS512' { [System.Security.Cryptography.HashAlgorithmName]::SHA512; break }
                default { throw ($PodeLocale.unsupportedJwtAlgorithmExceptionMessage -f $alg) }
            }

            $rsaPadding = if ($alg -match '^PS') {
                [System.Security.Cryptography.RSASignaturePadding]::Pss
            }
            else {
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            }

            $signature = $rsa.SignData($valueBytes, $hashAlgo, $rsaPadding)

            break
        }

        # ECDSA (ES256, ES384, ES512)
        { $_ -match '^ES(\d{3})$' } {
            $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($X509Certificate)

            # Map ES256, ES384, ES512 to their correct SHA algorithm
            $hashAlgo = switch ($alg) {
                'ES256' { [System.Security.Cryptography.HashAlgorithmName]::SHA256; break }
                'ES384' { [System.Security.Cryptography.HashAlgorithmName]::SHA384; break }
                'ES512' { [System.Security.Cryptography.HashAlgorithmName]::SHA512; break }
                default { throw ($PodeLocale.unsupportedJwtAlgorithmExceptionMessage -f $alg) }
            }

            $signature = $ecdsa.SignData($valueBytes, $hashAlgo)
            break
        }

        default {
            throw ($PodeLocale.unsupportedJwtAlgorithmExceptionMessage -f $alg)
        }
    }
    return [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}