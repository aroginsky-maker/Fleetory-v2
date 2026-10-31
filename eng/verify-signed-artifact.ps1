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
. (Join-Path $PSScriptRoot 'evidence-file-helpers.ps1')
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
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '')
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $sha.Dispose()
    }
}

function Read-ArtifactText([string] $Path, [string] $Name) {
    $snapshot = Read-BoundedEvidenceSnapshot $Path $Name 4KB
    try { return [Text.UTF8Encoding]::new($false, $true).GetString($snapshot.Bytes).TrimStart([char]0xFEFF) }
    catch { throw "$Name must be valid UTF-8." }
}

function Get-ArtifactPemSlice([string] $Text, [Range] $Range) {
    $start = $Range.Start.GetOffset($Text.Length)
    return $Text.Substring($start, $Range.End.GetOffset($Text.Length) - $start)
}

function Import-ArtifactPublicKey([string] $Text) {
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        $fields = [Security.Cryptography.PemEncoding]::Find($Text)
        $start = $fields.Location.Start.GetOffset($Text.Length)
        $end = $fields.Location.End.GetOffset($Text.Length)
        if ((Get-ArtifactPemSlice $Text $fields.Label) -cne 'PUBLIC KEY' -or
            -not [string]::IsNullOrWhiteSpace($Text.Substring(0, $start)) -or
            -not [string]::IsNullOrWhiteSpace($Text.Substring($end))) {
            throw 'Expected one public key PEM block.'
        }
        $der = [Convert]::FromBase64String((Get-ArtifactPemSlice $Text $fields.Base64Data))
        $read = 0
        $ecdsa.ImportSubjectPublicKeyInfo($der, [ref]$read)
        if ($read -ne $der.Length -or $ecdsa.KeySize -ne 256 -or
            $ecdsa.ExportParameters($false).Curve.Oid.Value -ne
                [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256').Oid.Value) {
            throw 'Expected a complete P-256 SubjectPublicKeyInfo value.'
        }
        return $ecdsa
    }
    catch {
        $ecdsa.Dispose()
        throw 'The artifact public key must contain exactly one P-256 PUBLIC KEY PEM block.'
    }
}

function ConvertFrom-ArtifactRecord([byte[]] $Bytes, [switch] $IncludeAcceptedAt) {
    $document = $null
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
        $options = [Text.Json.JsonDocumentOptions]::new()
        $options.MaxDepth = 2
        $document = [Text.Json.JsonDocument]::Parse($text, $options)
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'Expected a metadata object.' }
        $fields = @('artifactId', 'version', 'sha256', 'signingKeyId')
        if ($IncludeAcceptedAt) { $fields += 'acceptedAt' }
        $members = @($root.EnumerateObject())
        if ($members.Count -ne $fields.Count) { throw 'Metadata fields are missing or unsupported.' }
        foreach ($field in $fields) {
            if (@($members | Where-Object { $_.Name -ceq $field }).Count -ne 1) {
                throw 'Metadata fields must be unique and supported.'
            }
            if ($field -cne 'version' -and $root.GetProperty($field).ValueKind -ne [Text.Json.JsonValueKind]::String) {
                throw 'Expected string metadata.'
            }
        }
        $version = 0L
        if (-not $root.GetProperty('version').TryGetInt64([ref]$version) -or $version -lt 1) {
            throw 'Expected a positive integer metadata version.'
        }
        $record = [ordered]@{
            artifactId = $root.GetProperty('artifactId').GetString()
            version = $version
            sha256 = $root.GetProperty('sha256').GetString()
            signingKeyId = $root.GetProperty('signingKeyId').GetString()
        }
        if ($IncludeAcceptedAt) { $record.acceptedAt = $root.GetProperty('acceptedAt').GetString() }
        return [pscustomobject]$record
    }
    catch { throw 'Artifact metadata must be a UTF-8 JSON object with unique supported fields and valid types.' }
    finally { if ($null -ne $document) { $document.Dispose() } }
}

function Assert-ArtifactManifest($Manifest, [string] $ExpectedArtifactId) {
    foreach ($field in @('artifactId', 'version', 'sha256', 'signingKeyId')) {
        if ($null -eq $Manifest.$field -or [string]::IsNullOrWhiteSpace([string]$Manifest.$field)) {
            throw "The artifact manifest field '$field' is missing."
        }
    }
    $artifactId = [string]$Manifest.artifactId
    if ($artifactId -notmatch '\A[a-z0-9][a-z0-9._-]{0,127}\z') {
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
    if ([string]$Manifest.sha256 -notmatch '\A[0-9A-Fa-f]{64}\z') {
        throw 'The artifact SHA-256 is invalid.'
    }
    if ([string]$Manifest.signingKeyId -notmatch '\A[a-z0-9][a-z0-9._-]{0,127}\z') {
        throw 'The artifact signing key identifier is invalid.'
    }
}

function Assert-ArtifactSignature([byte[]] $ManifestBytes, [string] $SignaturePath, [string] $PublicKeyPath) {
    $signatureText = Read-ArtifactText $SignaturePath 'The artifact signature'
    try { $signature = [Convert]::FromBase64String($signatureText.Trim()) }
    catch { throw 'The artifact signature is not valid base64.' }
    if ($signature.Length -ne 64) { throw 'The artifact signature must be a P-256 IEEE P1363 signature.' }

    $ecdsa = Import-ArtifactPublicKey (Read-ArtifactText $PublicKeyPath 'The artifact public key')
    try {
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

function Assert-ArtifactLockPath([string] $Path, [bool] $Required = $false) {
    $entry = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $entry) {
        if ($Required) { throw 'The artifact anchor lock file disappeared.' }
        return
    }
    if ($entry.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) {
        throw 'The artifact anchor lock must be a regular file without a reparse point.'
    }
}

function Enter-ArtifactAnchorLock([string] $AnchorPath) {
    Assert-ArtifactPathIsSafe (Split-Path -Parent $AnchorPath) 'The artifact anchor directory'
    $path = $AnchorPath + '.lock'
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        Assert-ArtifactLockPath $path
        if ($elapsed.ElapsedMilliseconds -ge 5000) { throw 'Timed out waiting for the artifact anchor lock.' }
        try { $held = [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch [IO.IOException] { Start-Sleep -Milliseconds 50; continue }
        try {
            Assert-ArtifactLockPath $path $true
            return $held
        }
        catch { $held.Dispose(); throw }
    }
}

function Read-ArtifactAnchor([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    Assert-ArtifactPathIsSafe $Path 'The artifact anchor'
    $snapshot = Read-BoundedEvidenceSnapshot $Path 'The artifact anchor' 4KB
    try {
        $anchor = ConvertFrom-ArtifactRecord $snapshot.Bytes -IncludeAcceptedAt
        Assert-ArtifactManifest $anchor ''
        $accepted = [DateTimeOffset]::MinValue
        if ($anchor.acceptedAt -cnotmatch '\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00)\z' -or
            -not [DateTimeOffset]::TryParse($anchor.acceptedAt,
                [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
                [ref]$accepted)) { throw 'Expected an anchor UTC timestamp.' }
        return $anchor
    }
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

$manifestBytes = (Read-BoundedEvidenceSnapshot $manifestPath 'The artifact manifest' 64KB).Bytes
$manifest = ConvertFrom-ArtifactRecord $manifestBytes
Assert-ArtifactManifest $manifest $ExpectedArtifactId
Assert-ArtifactSignature $manifestBytes $signaturePath $publicKeyPath
$actualSha256 = Get-ArtifactSha256 $artifact
if ($actualSha256 -ine [string]$manifest.sha256) { throw 'The artifact SHA-256 does not match its signed manifest.' }

$anchorLock = Enter-ArtifactAnchorLock $anchor
try {
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
}
finally { $anchorLock.Dispose() }
