$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repoRoot 'eng/verify-signed-artifact.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $source -Names @('Get-ArtifactSha256')
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

function Write-ManifestSignature {
    $signature = $key.SignData([IO.File]::ReadAllBytes($manifestPath),
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    [IO.File]::WriteAllText($signaturePath, [Convert]::ToBase64String($signature),
        [Text.UTF8Encoding]::new($false))
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
    Write-ManifestSignature
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

    $publicBytes = [IO.File]::ReadAllBytes($publicKeyPath)
    $publicPem = $key.ExportSubjectPublicKeyInfoPem()
    $otherCurve = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP384'))
    $rsa = [Security.Cryptography.RSA]::Create(2048)
    try {
        $privateDer = [Security.Cryptography.PemEncoding]::WriteString('PUBLIC KEY', $key.ExportPkcs8PrivateKey())
        $trailingDer = [Security.Cryptography.PemEncoding]::WriteString('PUBLIC KEY', [byte[]]($key.ExportSubjectPublicKeyInfo() + 0))
        foreach ($invalidPem in @(
            $key.ExportPkcs8PrivateKeyPem(),
            $key.ExportECPrivateKeyPem(),
            ($publicPem + "`n" + $publicPem),
            ('unexpected' + $publicPem),
            ($publicPem + 'unexpected'),
            $privateDer,
            $trailingDer,
            $otherCurve.ExportSubjectPublicKeyInfoPem(),
            $rsa.ExportSubjectPublicKeyInfoPem(),
            $publicPem.PadRight(4097)
        )) {
            Write-SignedArtifact 4 'release-four'
            [IO.File]::WriteAllText($publicKeyPath, $invalidPem, [Text.UTF8Encoding]::new($false))
            Assert-VerifierFails 'An unsupported, ambiguous or oversized public key was accepted.'
        }
        [IO.File]::WriteAllBytes($publicKeyPath, [byte[]]@(0xFF))
        Assert-VerifierFails 'Invalid public-key UTF-8 was accepted.'
    }
    finally {
        [IO.File]::WriteAllBytes($publicKeyPath, $publicBytes)
        $otherCurve.Dispose()
        $rsa.Dispose()
    }

    Write-SignedArtifact 4 'release-four'
    $signatureText = [IO.File]::ReadAllText($signaturePath)
    foreach ($invalidSignature in @($signatureText.PadRight(4097), 'invalid-base64', [Convert]::ToBase64String([byte[]](0..62)))) {
        [IO.File]::WriteAllText($signaturePath, $invalidSignature, [Text.UTF8Encoding]::new($false))
        Assert-VerifierFails 'An oversized or malformed signature was accepted.'
    }
    [IO.File]::WriteAllBytes($signaturePath, [byte[]]@(0xFF))
    Assert-VerifierFails 'Invalid signature UTF-8 was accepted.'

    # Both oversized and exact-boundary manifests carry valid signatures.
    Write-SignedArtifact 4 'release-four'
    $manifestText = [IO.File]::ReadAllText($manifestPath)
    [IO.File]::WriteAllText($manifestPath, $manifestText.PadRight(65537), [Text.UTF8Encoding]::new($false))
    Write-ManifestSignature
    Assert-VerifierFails 'A validly signed oversized manifest was accepted.'
    [IO.File]::WriteAllBytes($manifestPath, [byte[]]@(0xFF))
    Write-ManifestSignature
    Assert-VerifierFails 'Invalid signed manifest UTF-8 was accepted.'

    Write-SignedArtifact 3 'release-three'
    $anchorBefore = [Convert]::ToBase64String([IO.File]::ReadAllBytes($anchorPath))
    $manifestText = [IO.File]::ReadAllText($manifestPath)
    [IO.File]::WriteAllText($manifestPath, $manifestText.PadRight(65536 - 3), [Text.UTF8Encoding]::new($true))
    Write-ManifestSignature
    $signatureText = [IO.File]::ReadAllText($signaturePath)
    [IO.File]::WriteAllText($signaturePath, $signatureText.PadRight(4096 - 3), [Text.UTF8Encoding]::new($true))
    [IO.File]::WriteAllText($publicKeyPath, (" `n" + $publicPem + "`n ").PadRight(4096 - 3), [Text.UTF8Encoding]::new($true))
    if ((Get-Item -LiteralPath $manifestPath).Length -ne 65536 -or
        (Get-Item -LiteralPath $signaturePath).Length -ne 4096 -or
        (Get-Item -LiteralPath $publicKeyPath).Length -ne 4096) { throw 'Metadata boundary fixtures have the wrong byte lengths.' }
    if ((Invoke-ArtifactVerifier).status -ne 'idempotent' -or
        $anchorBefore -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($anchorPath))) {
        throw 'Valid metadata at its byte limits did not preserve idempotence and anchor bytes.'
    }

    # Package size must not determine the managed buffer allocation.
    $largePath = Join-Path $work 'large-artifact.bin'
    $large = [IO.File]::Open($largePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $large.SetLength(32MB) } finally { $large.Dispose() }
    $expected = (Get-FileHash -LiteralPath $largePath -Algorithm SHA256).Hash
    [void](Get-ArtifactSha256 $artifactPath)
    $allocatedBefore = [GC]::GetAllocatedBytesForCurrentThread()
    $largeDigest = Get-ArtifactSha256 $largePath
    $allocated = [GC]::GetAllocatedBytesForCurrentThread() - $allocatedBefore
    if ($largeDigest -cne $expected -or $allocated -ge 8MB) {
        throw 'Artifact hashing did not preserve its digest within the bounded allocation budget.'
    }
    Write-Host "SIGNED ARTIFACT TESTS PASS: $script:rejections rejection cases; strict bounded metadata and anchor, public-only keys, unchanged rejected bytes, idempotence, forward acceptance; 32 MiB hashing allocated $allocated bytes (budget <8 MiB)."
}
finally {
    $key.Dispose()
    Remove-FleetoryTestArtifacts $work $repoRoot
}
