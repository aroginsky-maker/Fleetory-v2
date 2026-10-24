<#
.SYNOPSIS
    Verifies a signed Fleetory artifact and advances an anti-rollback anchor.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $ArtifactPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $ManifestPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $SignaturePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $PublicKeyPath,
    [Parameter(Mandatory)][string] $AnchorPath,
    [string] $ExpectedArtifactId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Signed artifact verification requires PowerShell 7 or later.'
}

function Get-ArtifactAbsolutePath([string] $Path, [string] $Name) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Name must be an absolute path."
    }
    return [IO.Path]::GetFullPath($Path)
}

function Assert-ArtifactPathIsSafe([string] $Path, [string] $Name) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Name must not be a symbolic link or reparse point."
    }
}

function Get-ArtifactSha256([string] $Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Get-ArtifactManifest([byte[]] $Bytes) {
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
        return ConvertFrom-Json -InputObject $text -Depth 5
    }
    catch { throw 'The artifact manifest is not valid UTF-8 JSON.' }
}

function Assert-ArtifactManifest($Manifest, [string] $ExpectedArtifactId) {
    foreach ($field in @('artifactId', 'version', 'sha256', 'signingKeyId')) {
        if ($null -eq $Manifest.$field -or [string]::IsNullOrWhiteSpace([string]$Manifest.$field)) {
            throw "The artifact manifest field '$field' is missing."
        }
    }
    $artifactId = [string]$Manifest.artifactId
    if ($artifactId -notmatch '^[a-z0-9][a-z0-9._-]{0,127}$') {
        throw 'The artifact identifier is invalid.'
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedArtifactId) -and $artifactId -ne $ExpectedArtifactId) {
        throw 'The artifact identifier is not the expected value.'
    }
    $version = 0L
    if (-not [long]::TryParse([string]$Manifest.version, [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$version) -or $version -lt 1) {
        throw 'The artifact version is invalid.'
    }
    if ([string]$Manifest.sha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw 'The artifact SHA-256 is invalid.'
    }
    if ([string]$Manifest.signingKeyId -notmatch '^[a-z0-9][a-z0-9._-]{0,127}$') {
        throw 'The artifact signing key identifier is invalid.'
    }
}

function Assert-ArtifactSignature([byte[]] $ManifestBytes, [string] $SignaturePath, [string] $PublicKeyPath) {
    try { $signature = [Convert]::FromBase64String([IO.File]::ReadAllText($SignaturePath).Trim()) }
    catch { throw 'The artifact signature is not valid base64.' }
    if ($signature.Length -ne 64) { throw 'The artifact signature must be a P-256 IEEE P1363 signature.' }

    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        $ecdsa.ImportFromPem([IO.File]::ReadAllText($PublicKeyPath))
        if ($ecdsa.KeySize -ne 256 -or
            $ecdsa.ExportParameters($false).Curve.Oid.Value -ne
                [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256').Oid.Value) {
            throw 'The artifact public key must be P-256.'
        }
        if (-not $ecdsa.VerifyData($ManifestBytes, $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'The artifact signature is invalid.'
        }
    }
    catch [Security.Cryptography.CryptographicException] {
        throw 'The artifact public key or signature is invalid.'
    }
    finally { $ecdsa.Dispose() }
}

function Read-ArtifactAnchor([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    Assert-ArtifactPathIsSafe $Path 'The artifact anchor'
    try { return ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Path)) -Depth 5 }
    catch { throw 'The artifact anti-rollback anchor is invalid.' }
}

function Write-ArtifactAnchor([string] $Path, $Manifest) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw 'The artifact anchor directory does not exist.'
    }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $value = [ordered]@{
        artifactId = [string]$Manifest.artifactId
        version = [long]$Manifest.version
        sha256 = ([string]$Manifest.sha256).ToUpperInvariant()
        signingKeyId = [string]$Manifest.signingKeyId
        acceptedAt = [DateTimeOffset]::UtcNow.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    } | ConvertTo-Json -Compress
    try {
        [IO.File]::WriteAllText($temporary, $value, [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporary, $Path, $true)
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

$artifact = Get-ArtifactAbsolutePath $ArtifactPath 'Artifact path'
$manifestPath = Get-ArtifactAbsolutePath $ManifestPath 'Manifest path'
$signaturePath = Get-ArtifactAbsolutePath $SignaturePath 'Signature path'
$publicKeyPath = Get-ArtifactAbsolutePath $PublicKeyPath 'Public key path'
$anchor = Get-ArtifactAbsolutePath $AnchorPath 'Anchor path'
foreach ($entry in @(
    @{ Path = $artifact; Name = 'The artifact' },
    @{ Path = $manifestPath; Name = 'The artifact manifest' },
    @{ Path = $signaturePath; Name = 'The artifact signature' },
    @{ Path = $publicKeyPath; Name = 'The artifact public key' })) {
    Assert-ArtifactPathIsSafe $entry.Path $entry.Name
}
$anchorParent = Split-Path -Parent $anchor
if (-not (Test-Path -LiteralPath $anchorParent -PathType Container)) {
    throw 'The artifact anchor directory does not exist.'
}
if (Test-Path -LiteralPath $anchor -PathType Leaf) { Assert-ArtifactPathIsSafe $anchor 'The artifact anchor' }
if ((Get-Item -LiteralPath $anchorParent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'The artifact anchor directory must not be a symbolic link or reparse point.'
}

$manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
$manifest = Get-ArtifactManifest $manifestBytes
Assert-ArtifactManifest $manifest $ExpectedArtifactId
$actualSha256 = Get-ArtifactSha256 $artifact
if ($actualSha256 -ine [string]$manifest.sha256) { throw 'The artifact SHA-256 does not match its signed manifest.' }
Assert-ArtifactSignature $manifestBytes $signaturePath $publicKeyPath

$existing = Read-ArtifactAnchor $anchor
if ($null -ne $existing) {
    if ([string]$existing.artifactId -ne [string]$manifest.artifactId) {
        throw 'The artifact anchor belongs to another artifact.'
    }
    $oldVersion = [long]$existing.version
    $newVersion = [long]$manifest.version
    if ($newVersion -lt $oldVersion) { throw 'The artifact version is older than the anti-rollback anchor.' }
    if ($newVersion -eq $oldVersion -and
        ([string]$existing.sha256 -ine [string]$manifest.sha256 -or
            [string]$existing.signingKeyId -ne [string]$manifest.signingKeyId)) {
        throw 'The artifact version conflicts with the anti-rollback anchor.'
    }
}

$status = if ($null -eq $existing -or [long]$manifest.version -gt [long]$existing.version) {
    Write-ArtifactAnchor $anchor $manifest
    'accepted'
} else { 'idempotent' }
Write-Output (ConvertTo-Json ([ordered]@{
    schema = 'fleetory.signed-artifact-verification.v1'
    artifactId = [string]$manifest.artifactId
    version = [long]$manifest.version
    sha256 = ([string]$manifest.sha256).ToUpperInvariant()
    signingKeyId = [string]$manifest.signingKeyId
    status = $status
}) -Compress)
