# Fleetory gateway host PKI provisioning. UTF-8 BOM + CRLF for Windows PowerShell 5.1.
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $RootCertificatePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $IntermediateCertificatePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $RootSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $IntermediateSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-FleetoryCertificate([string] $Path) {
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path)
    if ($certificate.HasPrivateKey) { throw "Certificate file must not contain a private key: $Path" }
    return $certificate
}

function Get-FleetoryCertificateSha256([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate) {
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    try { return ([BitConverter]::ToString($sha.ComputeHash($Certificate.RawData))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Assert-FleetoryCertificateFingerprint($Certificate, [string] $Expected, [string] $Name) {
    $actual = Get-FleetoryCertificateSha256 $Certificate
    if ($actual -ine $Expected) { throw "$Name fingerprint does not match the approved value." }
    return $actual.ToUpperInvariant()
}

function Assert-FleetoryGatewayCertificatePolicy($Certificate, [string] $Name) {
    $basicExtensions = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
    if ($basicExtensions.Count -eq 0) {
        throw "$Name must contain Basic Constraints." 
    }
    $basic = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]($basicExtensions | Select-Object -First 1)
    if (-not $basic.CertificateAuthority) {
        throw "$Name must be a CA certificate."
    }
    $keyUsage = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' }) |
        Select-Object -First 1
    if ($null -eq $keyUsage -or
        (([Security.Cryptography.X509Certificates.X509KeyUsageExtension]$keyUsage).KeyUsages -band
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign) -eq 0) {
        throw "$Name must allow certificate signing."
    }
    if ($Certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow.AddMinutes(5) -or
        $Certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
        throw "$Name is outside its validity period."
    }
}

function Assert-FleetoryGatewayCertificateChain($Root, $Intermediate) {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.ExtraStore.Add($Root)
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
        if (-not $chain.Build($Intermediate) -or
            $chain.ChainElements.Count -lt 2 -or
            [Convert]::ToBase64String($chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.RawData) -ne
                [Convert]::ToBase64String($Root.RawData)) {
            throw 'Intermediate certificate does not chain to the approved root.'
        }
    } finally { $chain.Dispose() }
}

function Install-FleetoryGatewayCertificate([string] $Path, [string] $ExpectedSha256, [string] $StoreName, [Collections.Generic.List[string]] $AddedThumbprints) {
    $certificate = Get-FleetoryCertificate $Path
    try {
        $fingerprint = Assert-FleetoryCertificateFingerprint $certificate $ExpectedSha256 $StoreName
        Assert-FleetoryGatewayCertificatePolicy $certificate $StoreName
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, 'LocalMachine')
        try {
            $store.Open('ReadWrite')
            if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint })) {
                $store.Add($certificate)
                $AddedThumbprints.Add("$StoreName|$($certificate.Thumbprint)")
            }
        } finally { $store.Close() }
        return $fingerprint
    } finally { $certificate.Dispose() }
}

function Remove-FleetoryGatewayCertificate([string] $StoreName, [string] $Thumbprint) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, 'LocalMachine')
    try {
        $store.Open('ReadWrite')
        foreach ($certificate in @($store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint })) {
            $store.Remove($certificate)
            $certificate.Dispose()
        }
    } finally { $store.Close() }
}

if ($MyInvocation.InvocationName -ne '.') {
    $root = Get-FleetoryCertificate $RootCertificatePath
    $intermediate = Get-FleetoryCertificate $IntermediateCertificatePath
    try {
        Assert-FleetoryCertificateFingerprint $root $RootSha256 'Root certificate' | Out-Null
        Assert-FleetoryCertificateFingerprint $intermediate $IntermediateSha256 'Intermediate certificate' | Out-Null
        Assert-FleetoryGatewayCertificatePolicy $root 'Root certificate'
        Assert-FleetoryGatewayCertificatePolicy $intermediate 'Intermediate certificate'
        Assert-FleetoryGatewayCertificateChain $root $intermediate
    } finally { $root.Dispose(); $intermediate.Dispose() }
    if ($PSCmdlet.ShouldProcess('LocalMachine certificate stores', 'Install approved Fleetory gateway CA certificates')) {
        $added = New-Object 'System.Collections.Generic.List[string]'
        try {
            Install-FleetoryGatewayCertificate $RootCertificatePath $RootSha256 'Root' $added | Out-Null
            Install-FleetoryGatewayCertificate $IntermediateCertificatePath $IntermediateSha256 'CA' $added | Out-Null
            Write-Host 'Fleetory gateway CA certificates installed.'
        }
        catch {
            $rollbackErrors = @()
            foreach ($entry in $added) {
                $parts = $entry -split '\|', 2
                try { Remove-FleetoryGatewayCertificate $parts[0] $parts[1] }
                catch { $rollbackErrors += $_.Exception.Message }
            }
            if ($rollbackErrors.Count -gt 0) {
                throw ('PKI installation failed and rollback was incomplete: ' +
                    ($rollbackErrors -join '; '))
            }
            throw
        }
    }
}
