using namespace System.Security.Cryptography

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param()
BeforeAll {
    $path = $PSCommandPath
    $src = (Split-Path -Parent -Path $path) -ireplace '[\\/]tests[\\/]unit', '/src/'
    Get-ChildItem "$($src)/*.ps1" -Recurse | Resolve-Path | ForEach-Object { . $_ }
    Import-LocalizedData -BindingVariable PodeLocale -BaseDirectory (Join-Path -Path $src -ChildPath 'Locales') -FileName 'Pode'
}

Describe 'New-PodeCertificateRequest Function' {

    BeforeAll {
        # Create a temporary directory for output files.
        $tempOutput = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        New-Item -Path $tempOutput -ItemType Directory | Out-Null
    }

    AfterAll {
        # Clean up the temporary directory after tests.
        Remove-Item $tempOutput -Recurse -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        # Override the internal function with a dummy implementation.
        function New-PodeCertificateRequestInternal {
            param (
                $DnsName, $CommonName, $Organization, $Locality, $State, $Country,
                $KeyType, $KeyLength, $EnhancedKeyUsages, $NotBefore, $CustomExtensions, $FriendlyName
            )

            # Create a dummy private key object with a script method.
            $privateKey = [PSCustomObject]@{}
            $privateKey | Add-Member -MemberType ScriptMethod -Name ExportPkcs8PrivateKey -Value {
                return [System.Text.Encoding]::UTF8.GetBytes('dummykey')
            }

            return [PSCustomObject]@{
                Request    = 'Dummy CSR Content'
                PrivateKey = $privateKey
            }
        }
    }

    It 'Generates a CSR and Private Key and saves them to the specified OutputPath' {
        # Define test input values.
        $dnsName = 'test.example.com'
        $commonName = 'test.example.com'
        $org = 'Test Organization'
        $locality = 'Test City'
        $state = 'Test State'
        $country = 'US'
        $keyType = 'RSA'
        $keyLength = 2048

        # Call the function.
        $result = New-PodeCertificateRequest `
            -DnsName $dnsName `
            -CommonName $commonName `
            -Organization $org `
            -Locality $locality `
            -State $state `
            -Country $country `
            -KeyType $keyType `
            -KeyLength $keyLength `
            -OutputPath $tempOutput

        # Expected file paths.
        $expectedCsrPath = Join-Path $tempOutput "$commonName.csr"
        $expectedKeyPath = Join-Path $tempOutput "$commonName.key"

        # Validate the returned object.
        $result | Should -BeOfType 'PSCustomObject'
        $result.CsrPath | Should -Be $expectedCsrPath
        $result.PrivateKeyPath | Should -Be $expectedKeyPath

        # Verify that the files have been created.
        (Test-Path $result.CsrPath) | Should -BeTrue
        (Test-Path $result.PrivateKeyPath) | Should -BeTrue

        # Validate file contents.
        $csrContent = Get-Content -Path $result.CsrPath -Raw
        $csrContent.Trim() | Should -Be "-----BEGIN CERTIFICATE REQUEST-----`nDummy CSR Content`n-----END CERTIFICATE REQUEST-----"

        $keyContent = Get-Content -Path $result.PrivateKeyPath -Raw
        $keyContent | Should -Match '-----BEGIN PRIVATE KEY-----'
        $keyContent | Should -Match '-----END PRIVATE KEY-----'
        $keyContent | Should -Match 'ZHVtbXlrZXk='
    }
}


Describe 'New-PodeSelfSignedCertificate Function' {


    It 'Generates a valid self-signed certificate with specified parameters' {
        # Define test parameters.
        $dnsName = @('test.example.com')
        $commonName = 'test.example.com'
        $org = 'TestOrg'
        $locality = 'TestCity'
        $state = 'TestState'
        $country = 'US'
        $keyType = 'RSA'
        $keyLength = 2048
        $purpose = 'ServerAuth'
        $notBefore = (Get-Date).ToUniversalTime()
        $script:friendlyName = 'MyTestCertificate'
        $validityDays = 365

        # Optionally, supply a secure string password for PFX protection.
        $script:dummyPassword = ConvertTo-SecureString 'TestPassword' -AsPlainText -Force

        # Call the certificate function.
        $script:dummyCert = New-PodeSelfSignedCertificate -DnsName $dnsName  `
            -Organization $org -Locality $locality -State $state -Country $country `
            -KeyType $keyType -KeyLength $keyLength  -CertificatePurpose $purpose `
            -NotBefore $notBefore -FriendlyName $script:friendlyName -ValidityDays $validityDays `
            -Password $script:dummyPassword  -Exportable

        # Validate that a certificate is returned.
        $script:dummyCert | Should -BeOfType 'System.Security.Cryptography.X509Certificates.X509Certificate2'

        # Validate the certificate's subject contains the common name.
        $script:dummyCert.Subject | Should -MatchExactly 'CN=SelfSigned, O=TestOrg, L=TestCity, S=TestState, C=US'

        # Check certificate validity period.
        $expectedNotBefore = $notBefore.Date
        $expectedNotAfter = $notBefore.AddDays($validityDays).Date

        $script:dummyCert.NotBefore.ToUniversalTime().Date | Should -Be $expectedNotBefore
        $script:dummyCert.NotAfter.ToUniversalTime().Date | Should -Be $expectedNotAfter

        # On Windows, verify the FriendlyName is set.
        if ($IsWindows) {
            $script:dummyCert.FriendlyName | Should -Be $script:friendlyName
        }
    }

    It 'Generates an ephemeral certificate when -Ephemeral is specified' {
        # Define minimal parameters.
        $commonName = 'ephemeral.example.com'

        # Call the function with the Ephemeral switch.
        $cert = New-PodeSelfSignedCertificate  -CommonName $commonName -Ephemeral

        # Validate that a certificate object is returned.
        $cert | Should -BeOfType 'System.Security.Cryptography.X509Certificates.X509Certificate2'

        # Check that the certificate has a private key.
        $cert.HasPrivateKey | Should -BeTrue

        # Note: Ephemeral certificates are created with non-persistent private keys.
        # This test ensures the private key exists, though verifying non-persistence across sessions is out of scope.
    }
}

Describe 'Export-PodeCertificate Function' {
    BeforeAll {
        # Create a temporary directory for exported files.
        $script:tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path  $script:tempDir -ItemType Directory -Force | Out-Null

    }

    Context 'File Export - PFX format' {
        It 'Exports certificate to a PFX file' {
            $filePathBase = Join-Path  $script:tempDir 'dummycertPFX'
            $script:pfxCertPath = Export-PodeCertificate -Certificate $script:dummyCert -Path $filePathBase -Format 'PFX' -CertificatePassword $script:dummyPassword
            $script:pfxCertPath | Should -BeOfType pscustomobject
            $script:pfxCertPath.CertificatePath | Should -Match '\.pfx'
            (Test-Path $script:pfxCertPath.CertificatePath) | Should -BeTrue
        }
    }

    Context 'File Export - CER format' {
        It 'Exports certificate to a CER file' {
            $filePathBase = Join-Path  $script:tempDir 'dummycertCER'
            $script:cerCertPath = Export-PodeCertificate -Certificate $script:dummyCert -Path $filePathBase -Format 'CER' -CertificatePassword $script:dummyPassword
            $script:cerCertPath | Should -BeOfType pscustomobject
            $script:cerCertPath.CertificatePath | Should -Match '\.cer'
            (Test-Path $script:cerCertPath.CertificatePath) | Should -BeTrue
        }
    }

    Context 'File Export - PEM format without private key' -Tag 'Exclude_DesktopEdition' {
        It 'Exports certificate to a PEM file without private key' {
            $filePathBase = Join-Path  $script:tempDir 'dummycertPEM_NoKey'
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                { Export-PodeCertificate -Certificate $script:dummyCert -Path $filePathBase -Format 'PEM' -CertificatePassword $script:dummyPassword } | Should -Throw ($PodeLocale.pemCertificateNotSupportedByPwshVersionExceptionMessage -f $PSVersionTable.PSVersion)
            }
            else {
                $output = Export-PodeCertificate -Certificate $script:dummyCert -Path $filePathBase -Format 'PEM' -CertificatePassword $script:dummyPassword
                # The output for PEM (without key) is a string containing the file path.
                $output | Should -BeOfType pscustomobject
                $output.CertificatePath | Should -Match '\.pem'
            (Test-Path -Path $output.CertificatePath) | Should -BeTrue
            (Get-Content -Path $output.CertificatePath -Raw) | Should -Match '-----BEGIN CERTIFICATE-----'
            }
        }
    }

    Context 'File Export - PEM format with private key' {

        It 'Exports certificate to a PEM file and exports the private key separately' {
            $filePathBase = Join-Path  $script:tempDir 'dummycertPEM_WithKey'
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                { Export-PodeCertificate -Certificate $script:dummyCert -Path $filePathBase -Format 'PEM' -IncludePrivateKey -CertificatePassword $script:dummyPassword } | Should -Throw ($PodeLocale.pemCertificateNotSupportedByPwshVersionExceptionMessage -f $PSVersionTable.PSVersion)
            }
            else {
                $script:pemCertPath = Export-PodeCertificate -Certificate $script:dummyCert -Path $filePathBase -Format 'PEM' -IncludePrivateKey -CertificatePassword $script:dummyPassword
                # When IncludePrivateKey is used, output is a hashtable.
                $script:pemCertPath | Should -BeOfType 'pscustomobject'
                $script:pemCertPath.CertificatePath | Should -Match '\.pem$'
                $script:pemCertPath.PrivateKeyPath | Should -Match '\.key$'
            (Test-Path $script:pemCertPath.CertificatePath) | Should -BeTrue
            (Test-Path $script:pemCertPath.PrivateKeyPath) | Should -BeTrue

            (Get-Content -Path $script:pemCertPath.CertificatePath -Raw) | Should -Match '-----BEGIN CERTIFICATE-----'
            (Get-Content -Path $script:pemCertPath.PrivateKeyPath -Raw) | Should -Match '-----BEGIN ENCRYPTED PRIVATE KEY-----'
            }
        }
    }

    Context 'Windows Store Export' {
        It 'Stores certificate in the Windows certificate store' -Tag 'Exclude_MacOs', 'Exclude_Linux' {
            $script:thumbprint = $script:dummyCert.Thumbprint

            $result = Export-PodeCertificate -Certificate $script:dummyCert -CertificateStoreName 'My' -CertificateStoreLocation 'CurrentUser'
            $result | Should -BeTrue
        }
    }
}



Describe 'Import-PodeCertificate Function' {
    Describe 'Sanity Check' {
        BeforeAll {
            # Create a dummy certificate using New-PodeSelfSignedCertificate.
            # This call should work on PS 5.1 as well as Core.
            $script:dummyCert = New-PodeSelfSignedCertificate -CommonName 'dummy.test' -ValidityDays 365 -Exportable


            # Simulate Test-Path so that paths containing "exists" return true, others false.
            Mock -CommandName Test-Path -MockWith {
                param($Path, $PathType)
                if ($Path[0].Contains('notexists')) { return $false } else { return $true }
            }

            # Mock certificate import helper functions to return our dummy certificate.
            Mock -CommandName Get-PodeCertificateByFile -MockWith {
                param($Certificate, $SecurePassword, $PrivateKeyPath, $Persistent)
                return $script:dummyCert
            }
            Mock -CommandName Get-PodeCertificateByThumbprint -MockWith {
                param($Thumbprint, $StoreName, $StoreLocation)
                return $script:dummyCert
            }
            Mock -CommandName Get-PodeCertificateByName -MockWith {
                param($Name, $StoreName, $StoreLocation)
                return $script:dummyCert
            }
        }

        Context 'When importing from a certificate file' {
            It 'Throws an error if the certificate file does not exist' {
                {
                    Import-PodeCertificate -Path 'C:\Certs\notexists.pfx' `
                        -CertificatePassword (ConvertTo-SecureString 'pass' -AsPlainText -Force)
                } | Should -Throw
            }

            It 'Throws an error if a PrivateKeyPath is provided but does not exist' {
                {
                    Import-PodeCertificate -Path 'C:\Certs\exists.pfx' `
                        -PrivateKeyPath 'C:\Certs\notexists.key' `
                        -CertificatePassword (ConvertTo-SecureString 'pass' -AsPlainText -Force)
                } | Should -Throw
            }

            It 'Imports a certificate from file when the certificate file exists' {
                $cert = Import-PodeCertificate -Path 'C:\Certs\exists.pfx' `
                    -CertificatePassword (ConvertTo-SecureString 'pass' -AsPlainText -Force)
                $cert | Should -Be $script:dummyCert
            }

            It 'Imports a certificate from file with the persistent flag when both files exist' {
                $cert = Import-PodeCertificate -Path 'C:\Certs\exists.pfx' `
                    -PrivateKeyPath 'C:\Certs\exists.key' `
                    -CertificatePassword (ConvertTo-SecureString 'pass' -AsPlainText -Force) `
                    -Exportable
                $cert | Should -Be $script:dummyCert
            }
        }

        Context 'When importing from the certificate store by thumbprint' -Tag 'Exclude_MacOs', 'Exclude_Linux' {
            It 'Retrieves a certificate using its thumbprint' {
                $thumbprint = 'DUMMYTHUMBPRINT'
                $cert = Import-PodeCertificate -CertificateThumbprint $thumbprint `
                    -CertificateStoreName 'My' -CertificateStoreLocation 'CurrentUser'
                $cert | Should -Be $script:dummyCert
            }
        }

        Context 'When importing from the certificate store by name' -Tag 'Exclude_MacOs', 'Exclude_Linux' {
            It 'Retrieves a certificate using its subject name' {
                $name = 'DummyCert'
                $cert = Import-PodeCertificate -CertificateName $name `
                    -CertificateStoreName 'My' -CertificateStoreLocation 'CurrentUser'
                $cert | Should -Be $script:dummyCert
            }
        }
    }

    Describe 'Import Functionality' {
        AfterAll {
            # Cleanup the temporary directory.
            Remove-Item -Path  $script:tempDir -Recurse -Force
        }

        Context 'File Import - PFX format' {
            It 'Imports certificate to a PFX file' {

                $cert = Import-PodeCertificate -Path $script:pfxCertPath.CertificatePath -CertificatePassword $script:dummyPassword

                $cert | Should -BeOfType  System.Security.Cryptography.X509Certificates.X509Certificate2

                # Validate the certificate's subject contains the common name.
                $cert.Subject | Should -MatchExactly 'CN=SelfSigned, O=TestOrg, L=TestCity, S=TestState, C=US'
                # On Windows, verify the FriendlyName is set.
                if ($IsWindows) {
                    $cert.FriendlyName | Should -Be $script:friendlyName
                }
            }
        }

        Context 'File Import - CER format' {
            It 'Imports certificate to a CER file' {
                $cert = Import-PodeCertificate -Path  $script:cerCertPath.CertificatePath -CertificatePassword $script:dummyPassword

                $cert | Should -BeOfType  System.Security.Cryptography.X509Certificates.X509Certificate2

                # Validate the certificate's subject contains the common name.
                $cert.Subject | Should -MatchExactly 'CN=SelfSigned, O=TestOrg, L=TestCity, S=TestState, C=US'

            }
        }

        Context 'File Import - PEM format with private key' -Tag 'Exclude_DesktopEdition' {
            It 'Imports certificate to a PEM file with private key' {
                if ($PSVersionTable.PSEdition -eq 'Desktop') {
                    Mock Test-Path { $true }
                    { $cert = Import-PodeCertificate -Path ( Join-Path  $script:tempDir 'dummycertPEM_WithKey.pem') -CertificatePassword $script:dummyPassword -PrivateKeyPath ( Join-Path  $script:tempDir 'dummycertPEM.key') } |
                        Should -Throw ($PodeLocale.pemCertificateNotSupportedByPwshVersionExceptionMessage -f $PSVersionTable.PSVersion)
                }
                else {
                    $cert = Import-PodeCertificate -Path  $script:pemCertPath.CertificatePath -CertificatePassword $script:dummyPassword -PrivateKeyPath $script:pemCertPath.PrivateKeyPath
                    # The output for PEM (without key) is a string containing the file path.
                    $cert | Should -BeOfType  System.Security.Cryptography.X509Certificates.X509Certificate2

                    # Validate the certificate's subject contains the common name.
                    $cert.Subject | Should -MatchExactly 'CN=SelfSigned, O=TestOrg, L=TestCity, S=TestState, C=US'
                }
            }
        }

        Context 'Windows Store Import' {
            It 'Stores certificate in the Windows certificate store' -Tag 'Exclude_MacOs', 'Exclude_Linux' {
                $cert = Import-PodeCertificate -CertificateStoreName 'My' -CertificateStoreLocation 'CurrentUser' -CertificateThumbprint $script:thumbprint
                $cert | Should -BeOfType  System.Security.Cryptography.X509Certificates.X509Certificate2

                # Validate the certificate's subject contains the common name.
                $cert.Subject | Should -MatchExactly 'CN=SelfSigned, O=TestOrg, L=TestCity, S=TestState, C=US'
                $cert.FriendlyName | Should -Be $script:friendlyName
            }
        }
    }
}

