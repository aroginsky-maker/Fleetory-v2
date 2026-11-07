#requires -Version 7.3
# Synthetic fixture material only. Root private key is never exported or persisted.
function New-PilotDisposableChainPolicy($Root,[string]$Purpose) {
    $policy = [Security.Cryptography.X509Certificates.X509ChainPolicy]::new()
    $policy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
    $null = $policy.CustomTrustStore.Add($Root)
    $policy.DisableCertificateDownloads = $true
    $policy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $policy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    $null = $policy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new($Purpose))
    return $policy
}
function New-PilotDisposableTlsMaterial {
    [CmdletBinding()]
    param([switch]$IncludeClient,[string]$IdentityUri='')
    $ErrorActionPreference = 'Stop'
    if ($IdentityUri.Length -gt 0) {
        $identity = [Guid]::Empty
        if (-not $IncludeClient -or $IdentityUri -cnotmatch '^urn:fleetory:(device|admin):([0-9a-f-]{36})$' -or
            -not [Guid]::TryParseExact(($IdentityUri -split ':')[-1],'D',[ref]$identity) -or $identity -eq [Guid]::Empty) {
            throw 'Invalid disposable identity URI.'
        }
    }
    if ([Environment]::Version.Major -lt 7) { throw 'Disposable TLS requires .NET 7 or later.' }
    $owned = [Collections.Generic.List[IDisposable]]::new()
    try {
        $now = [DateTimeOffset]::UtcNow
        $notBefore = $now.AddMinutes(-5)
        $rootKey = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $owned.Add($rootKey)
        $rootRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Fleetory Disposable Fixture Root', $rootKey, [Security.Cryptography.HashAlgorithmName]::SHA256)
        $null = $rootRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$true,0,$true))
        $caUsage = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        $null = $rootRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($caUsage,$true))
        $null = $rootRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($rootRequest.PublicKey,$false))
        $root = $rootRequest.CreateSelfSigned($notBefore,$now.AddHours(2))
        $owned.Add($root)
        $serverKey = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $owned.Add($serverKey)
        $serverRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=localhost', $serverKey, [Security.Cryptography.HashAlgorithmName]::SHA256)
        $null = $serverRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
        $null = $serverRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,$true))
        $purposes = [Security.Cryptography.OidCollection]::new()
        $null = $purposes.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
        $null = $serverRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($purposes,$true))
        $null = $serverRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($serverRequest.PublicKey,$false))
        $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddDnsName('localhost')
        $san.AddIpAddress([Net.IPAddress]::Loopback)
        $null = $serverRequest.CertificateExtensions.Add($san.Build())
        $serial = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
        $serial[0] = $serial[0] -bor 1
        $leaf = $serverRequest.Create($root,$notBefore,$now.AddHours(1),$serial)
        $owned.Add($leaf)
        $server = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($leaf,$serverKey)
        $owned.Add($server)
        # Only public root material reaches the custom trust store.
        $rootPem = $root.ExportCertificatePem()
        $publicRoot = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($rootPem)
        $owned.Add($publicRoot)
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        $owned.Add($chain)
        $chain.ChainPolicy = New-PilotDisposableChainPolicy $publicRoot '1.3.6.1.5.5.7.3.1'
        if (-not $chain.Build($server) -or $chain.ChainElements.Count -ne 2) { throw 'Invalid synthetic chain.' }
        $sanExtension = @($server.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' })
        if ($sanExtension.Count -ne 1) { throw 'Missing synthetic SAN.' }
        $parsedSan = [Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]::new(
            $sanExtension[0].RawData,$sanExtension[0].Critical)
        $ips = @($parsedSan.EnumerateIPAddresses())
        $names = @($parsedSan.EnumerateDnsNames())
        if ($ips.Count -ne 1 -or -not $ips[0].Equals([Net.IPAddress]::Loopback) -or
            $names.Count -ne 1 -or $names[0] -cne 'localhost') { throw 'Invalid synthetic SAN.' }
        $publicKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($server)
        $owned.Add($publicKey)
        $challenge = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        $signature = $serverKey.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256)
        if (-not $publicKey.VerifyData($challenge,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256)) {
            throw 'Synthetic key mismatch.'
        }
        $result = [ordered]@{
            RootCertificatePem = $rootPem
            ServerCertificatePem = $server.ExportCertificatePem()
            ServerPrivateKeyPem = $serverKey.ExportPkcs8PrivateKeyPem()
        }
        $clientRoles = @()
        if ($IncludeClient) { $clientRoles += 'Client' }
        if ($IdentityUri.Length -gt 0) { $clientRoles += 'IdentityClient' }
        foreach ($clientRole in $clientRoles) {
            # Issue only a leaf while the root handle is alive. Never export its key.
            $clientKey = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
            $owned.Add($clientKey)
            $clientRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Fleetory Disposable Client', $clientKey, [Security.Cryptography.HashAlgorithmName]::SHA256)
            foreach ($extension in $serverRequest.CertificateExtensions) {
                if ($extension.Oid.Value -notin @('2.5.29.37','2.5.29.14','2.5.29.17')) {
                    $null = $clientRequest.CertificateExtensions.Add($extension)
                }
            }
            $clientPurposes = [Security.Cryptography.OidCollection]::new()
            $null = $clientPurposes.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.2'))
            $null = $clientRequest.CertificateExtensions.Add(
                [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($clientPurposes,$true))
            $null = $clientRequest.CertificateExtensions.Add(
                [Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($clientRequest.PublicKey,$false))
            if ($clientRole -ceq 'IdentityClient') {
                $identitySan = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
                $identitySan.AddUri([Uri]::new($IdentityUri))
                $null = $clientRequest.CertificateExtensions.Add($identitySan.Build())
            }
            $clientSerial = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
            $clientSerial[0] = $clientSerial[0] -bor 1
            $clientLeaf = $clientRequest.Create($root,$notBefore,$now.AddHours(1),$clientSerial)
            $owned.Add($clientLeaf)
            $chain.ChainPolicy = New-PilotDisposableChainPolicy $publicRoot '1.3.6.1.5.5.7.3.2'
            if (-not $chain.Build($clientLeaf) -or $chain.ChainElements.Count -ne 2) { throw 'Invalid synthetic client chain.' }
            $result[($clientRole+'CertificatePem')] = $clientLeaf.ExportCertificatePem()
            $result[($clientRole+'PrivateKeyPem')] = $clientKey.ExportPkcs8PrivateKeyPem()
        }
        return [pscustomobject]$result
    } catch {
        throw 'Disposable TLS fixture generation or validation failed.'
    } finally {
        for ($index = $owned.Count - 1; $index -ge 0; $index--) { $owned[$index].Dispose() }
    }
}
