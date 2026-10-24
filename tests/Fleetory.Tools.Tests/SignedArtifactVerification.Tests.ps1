$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repoRoot 'eng/verify-signed-artifact.ps1'
$work = Join-Path $repoRoot ('artifacts/signed-artifact-test-' + [Guid]::NewGuid().ToString('N'))
$artifactPath = Join-Path $work 'Fleetory.Server.zip'
$manifestPath = Join-Path $work 'Fleetory.Server.manifest.json'
$signaturePath = Join-Path $work 'Fleetory.Server.manifest.sig'
$publicKeyPath = Join-Path $work 'Fleetory.release.public.pem'
$anchorPath = Join-Path $work 'Fleetory.Server.anchor.json'
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
    & pwsh -NoProfile -File $source -ArtifactPath $artifactPath -ManifestPath $manifestPath -SignaturePath $signaturePath -PublicKeyPath $publicKeyPath -AnchorPath $anchorPath -ExpectedArtifactId 'fleetory.server' *> $null
    if ($LASTEXITCODE -eq 0) { throw $Message }
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
    Write-Host 'SIGNED ARTIFACT TESTS PASS: signature, artifact hash, idempotence and anti-rollback validation.'
}
finally {
    $key.Dispose()
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
