$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repoRoot 'eng/verify-signed-artifact.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $source -Names @()
$work = Join-Path $repoRoot ('artifacts/signed-artifact-test-' + [Guid]::NewGuid().ToString('N'))
$artifactPath = Join-Path $work 'Fleetory.Server.zip'
$manifestPath = Join-Path $work 'Fleetory.Server.manifest.json'
$signaturePath = Join-Path $work 'Fleetory.Server.manifest.sig'
$publicKeyPath = Join-Path $work 'Fleetory.release.public.pem'
$anchorPath = Join-Path $work 'Fleetory.Server.anchor.json'
$script:rejections = 0
$key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))

function Get-TestSha256([byte[]] $Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Write-SignedArtifact([long] $Version, [string] $Content, [string] $KeyId = 'fleetory-release-v1') {
    $artifactBytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
    [IO.File]::WriteAllBytes($artifactPath, $artifactBytes)
    $manifest = [ordered]@{
        artifactId = 'fleetory.server'
        version = $Version
        sha256 = (Get-TestSha256 $artifactBytes)
        signingKeyId = $KeyId
    } | ConvertTo-Json -Compress
    $manifestBytes = [Text.UTF8Encoding]::new($false).GetBytes($manifest)
    [IO.File]::WriteAllBytes($manifestPath, $manifestBytes)
    $signature = $key.SignData($manifestBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    [IO.File]::WriteAllText($signaturePath, [Convert]::ToBase64String($signature),
        [Text.UTF8Encoding]::new($false))
    if (-not (Test-Path -LiteralPath $publicKeyPath)) {
        [IO.File]::WriteAllText($publicKeyPath, $key.ExportSubjectPublicKeyInfoPem(),
            [Text.UTF8Encoding]::new($false))
    }
}

function Invoke-ArtifactVerifier {
    $output = & pwsh -NoProfile -File $source -ArtifactPath $artifactPath -ManifestPath $manifestPath -SignaturePath $signaturePath -PublicKeyPath $publicKeyPath -AnchorPath $anchorPath -ExpectedArtifactId 'fleetory.server'
    if ($LASTEXITCODE -ne 0) { throw 'Artifact verifier failed unexpectedly.' }
    return $output | ConvertFrom-Json
}

function Assert-VerifierFails([string] $Message) {
    $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($anchorPath))
    & pwsh -NoProfile -File $source -ArtifactPath $artifactPath -ManifestPath $manifestPath -SignaturePath $signaturePath -PublicKeyPath $publicKeyPath -AnchorPath $anchorPath -ExpectedArtifactId 'fleetory.server' *> $null
    if ($LASTEXITCODE -eq 0) { throw $Message }
    if ($before -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($anchorPath))) {
        throw 'A failed verification changed the anti-rollback anchor bytes.'
    }
    $script:rejections++
    $global:LASTEXITCODE = 0
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    Write-SignedArtifact 1 'release-one'
    $first = Invoke-ArtifactVerifier
    if ($first.status -ne 'accepted' -or $first.version -ne 1) { throw 'Initial artifact was not accepted.' }

    $repeat = Invoke-ArtifactVerifier
    if ($repeat.status -ne 'idempotent') { throw 'Repeated artifact verification was not idempotent.' }

    Write-SignedArtifact 2 'release-two'
    $second = Invoke-ArtifactVerifier
    if ($second.status -ne 'accepted' -or $second.version -ne 2) { throw 'Newer artifact was not accepted.' }

    Write-SignedArtifact 1 'rollback-release'
    Assert-VerifierFails 'A lower artifact version bypassed the anti-rollback anchor.'

    Write-SignedArtifact 3 'release-three'
    [IO.File]::WriteAllText($artifactPath, 'tampered', [Text.UTF8Encoding]::new($false))
    Assert-VerifierFails 'An artifact with a changed content hash was accepted.'

    Write-SignedArtifact 3 'release-three'
    [IO.File]::WriteAllText($signaturePath, [Convert]::ToBase64String([byte[]](0..63)), [Text.UTF8Encoding]::new($false))
    Assert-VerifierFails 'An artifact with an invalid signature was accepted.'

    # A present but corrupt anchor must never be interpreted as first acceptance.
    $validAnchorBytes = [IO.File]::ReadAllBytes($anchorPath)
    foreach ($json in @('null', '[]', 'false', '')) {
        [IO.File]::WriteAllText($anchorPath, $json, [Text.UTF8Encoding]::new($false))
        Write-SignedArtifact 1 'rollback-release'
        Assert-VerifierFails 'A damaged existing anchor permitted a signed rollback.'
    }

    function New-AnchorFixture {
        return [ordered]@{
            artifactId = 'fleetory.server'
            version = 2L
            sha256 = $second.sha256
            signingKeyId = 'fleetory-release-v1'
            acceptedAt = '2026-01-01T00:00:00+00:00'
        }
    }
    $invalidFields = @(
        { param($a) $a.version = $false },
        { param($a) $a.version = $null },
        { param($a) $a.version = 0 },
        { param($a) $a.version = -1 },
        { param($a) $a.version = '2' },
        { param($a) $a.version = 2.5 },
        { param($a) $a.sha256 = 'bad' },
        { param($a) $a.sha256 += "`n" },
        { param($a) $a.signingKeyId += "`n" },
        { param($a) $a.sha256 = $false },
        { param($a) $a.signingKeyId = '' },
        { param($a) $a.acceptedAt = 'not-a-time' },
        { param($a) $a.acceptedAt = '2026-01-01T00:00:00+03:00' },
        { param($a) $a.acceptedAt = $true },
        { param($a) [void]$a.Remove('acceptedAt') },
        { param($a) $a['unexpected'] = 'unsupported' }
    )
    foreach ($change in $invalidFields) {
        $anchorFixture = New-AnchorFixture
        & $change $anchorFixture
        [IO.File]::WriteAllText($anchorPath, ($anchorFixture | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
        Write-SignedArtifact 3 'release-three'
        Assert-VerifierFails 'Invalid anchor fields were coerced or overwritten.'
    }

    $canonical = New-AnchorFixture | ConvertTo-Json -Compress
    foreach ($json in @(
        $canonical.Replace('"version":2', '"version":2,"version":0'),
        $canonical.Replace('"version":2', '"version":2,"vers\u0069on":0'),
        ('null' + (' ' * 4093))
    )) {
        [IO.File]::WriteAllText($anchorPath, $json, [Text.UTF8Encoding]::new($false))
        Write-SignedArtifact 1 'rollback-release'
        Assert-VerifierFails 'Duplicate or oversized anchor JSON permitted rollback.'
    }
    [IO.File]::WriteAllBytes($anchorPath, [byte[]]@(0xFF))
    Write-SignedArtifact 3 'release-three'
    Assert-VerifierFails 'Invalid anchor UTF-8 was accepted.'

    # Valid UTC spellings and exact-size BOM/whitespace retain idempotence and raw bytes.
    foreach ($timestamp in @('2026-01-01T00:00:00Z', '2026-01-01T00:00:00.1234567+00:00')) {
        $anchorFixture = New-AnchorFixture
        $anchorFixture.acceptedAt = $timestamp
        [IO.File]::WriteAllText($anchorPath, ($anchorFixture | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($true))
        $payload = [IO.File]::ReadAllBytes($anchorPath)
        $padded = New-Object byte[] 4096
        [Buffer]::BlockCopy($payload, 0, $padded, 0, $payload.Length)
        for ($offset = $payload.Length; $offset -lt $padded.Length; $offset++) { $padded[$offset] = 32 }
        [IO.File]::WriteAllBytes($anchorPath, $padded)
        Write-SignedArtifact 2 'release-two'
        $repeat = Invoke-ArtifactVerifier
        if ($repeat.status -ne 'idempotent' -or
            [Convert]::ToBase64String($padded) -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($anchorPath))) {
            throw 'Valid bounded anchor bytes or idempotent acceptance were not preserved.'
        }
    }
    [IO.File]::WriteAllBytes($anchorPath, $validAnchorBytes)
    Write-SignedArtifact 2 'same-version-changed-content'
    Assert-VerifierFails 'A same-version artifact conflict was accepted.'
    Write-SignedArtifact 2 'release-two' 'another-release-key'
    Assert-VerifierFails 'A same-version key identifier conflict was accepted.'
    Write-SignedArtifact 3 'release-three'
    if ((Invoke-ArtifactVerifier).status -ne 'accepted') { throw 'Valid forward acceptance was lost.' }
    Write-Host "SIGNED ARTIFACT TESTS PASS: $script:rejections rejection cases; strict bounded anchor, unchanged rejected bytes, signature/hash, idempotence and forward acceptance."
}
finally {
    $key.Dispose()
    Remove-FleetoryTestArtifacts $work $repoRoot
}
