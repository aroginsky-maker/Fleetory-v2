# UTF-8 with BOM keeps this PowerShell test usable on Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source (Join-Path $repoRoot 'eng/provision-fleetory-gateway-pki.ps1') -Names @('Get-FleetoryCertificate', 'Get-FleetoryCertificateSha256', 'Assert-FleetoryCertificateFingerprint', 'Assert-FleetoryGatewayCertificatePolicy', 'Assert-FleetoryGatewayCertificateChain')

function Assert-Throws([scriptblock] $Action, [string] $Message) {
    try { & $Action } catch { return }
    throw $Message
}

function New-TestCertificate(
    [string] $Subject,
    [bool] $CertificateAuthority,
    [Security.Cryptography.X509Certificates.X509Certificate2] $Issuer,
    [Security.Cryptography.ECDsa] $IssuerKey) {
    $key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$Subject", $key, [Security.Cryptography.HashAlgorithmName]::SHA256)
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($CertificateAuthority, $false, 0, $true))
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign, $true))
        $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)
        $notAfter = [DateTimeOffset]::UtcNow.AddHours(2)
        if ($null -eq $Issuer) {
            return [pscustomobject]@{ Certificate = $request.CreateSelfSigned($notBefore, $notAfter); Key = $key }
        }
        $notAfter = [DateTimeOffset]$Issuer.NotAfter.ToUniversalTime().AddMinutes(-1)
        return [pscustomobject]@{ Certificate = $request.Create($Issuer, $notBefore, $notAfter, [byte[]](1, 2, 3, 4)); Key = $key }
    }
    catch {
        $key.Dispose()
        throw
    }
}

$work = Join-Path $repoRoot ('artifacts/windows-pki-test-' + [Guid]::NewGuid().ToString('N'))
$rootFixture = $null
$intermediateFixture = $null
$leafFixture = $null
try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $rootFixture = New-TestCertificate 'Fleetory test root' $true $null $null
    $intermediateFixture = New-TestCertificate 'Fleetory test intermediate' $true $rootFixture.Certificate $rootFixture.Key
    $leafFixture = New-TestCertificate 'Fleetory test leaf' $false $rootFixture.Certificate $rootFixture.Key

    $root = $rootFixture.Certificate
    $intermediate = $intermediateFixture.Certificate
    $leaf = $leafFixture.Certificate
    $actual = Get-FleetoryCertificateSha256 $root
    if ($actual.Length -ne 64) { throw 'Fingerprint was not 64 hexadecimal characters.' }
    Assert-FleetoryCertificateFingerprint $root $actual 'root' | Out-Null
    Assert-Throws { Assert-FleetoryCertificateFingerprint $root ('0' * 64) 'root' } 'Mismatched fingerprint was accepted.'
    Assert-FleetoryGatewayCertificatePolicy $root 'root'
    Assert-FleetoryGatewayCertificatePolicy $intermediate 'intermediate'
    Assert-FleetoryGatewayCertificateChain $root $intermediate
    Assert-Throws { Assert-FleetoryGatewayCertificatePolicy $leaf 'leaf' } 'A non-CA certificate was accepted as a trust anchor.'

    $pfxPath = Join-Path $work 'private-key.pfx'
    [IO.File]::WriteAllBytes($pfxPath, $root.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12))
    Assert-Throws { Get-FleetoryCertificate $pfxPath } 'A certificate file containing a private key was accepted.'
    Write-Host 'WINDOWS PKI TESTS PASS: fingerprint pinning, CA policy, chain validation and private-key rejection.'
}
finally {
    if ($leafFixture) { $leafFixture.Key.Dispose(); $leafFixture.Certificate.Dispose() }
    if ($intermediateFixture) { $intermediateFixture.Key.Dispose(); $intermediateFixture.Certificate.Dispose() }
    if ($rootFixture) { $rootFixture.Key.Dispose(); $rootFixture.Certificate.Dispose() }
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
