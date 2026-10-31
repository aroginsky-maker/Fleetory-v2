$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repoRoot 'eng/provision-security-lab-command-signing.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $source `
    -Names @('Get-LabCommandPublicKey', 'Sync-LabCommandTrust')

function New-TestKeyData([int] $Version, [hashtable] $PemByVersion) {
    $keys = [pscustomobject] $PemByVersion
    return [pscustomobject]@{ latest_version = $Version; keys = $keys }
}

function New-TestPublicKey {
    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    try {
        return [pscustomobject]@{
            pem = $key.ExportSubjectPublicKeyInfoPem()
            bytes = $key.ExportSubjectPublicKeyInfo()
        }
    }
    finally { $key.Dispose() }
}

$work = Join-Path $repoRoot ('artifacts/command-trust-test-' +
    [Guid]::NewGuid().ToString('N'))
$trustDirectory = Join-Path $work 'trust'
$retiredDirectory = Join-Path $work 'retired'
$device = [Guid]::NewGuid()
$foreign = [Guid]::NewGuid()
$first = New-TestPublicKey
$second = New-TestPublicKey
$restart = New-TestPublicKey
try {
    $initial = New-TestKeyData 1 @{
        '1' = [pscustomobject]@{ public_key = $first.pem }
    }
    $firstPath = Sync-LabCommandTrust $trustDirectory $retiredDirectory `
        $device $initial $false
    if (-not [Linq.Enumerable]::SequenceEqual(
        [byte[]][IO.File]::ReadAllBytes($firstPath), [byte[]]$first.bytes)) {
        throw 'Initial Agent trust key differs from OpenBao.'
    }
    $foreignPath = Join-Path $trustDirectory ("{0:N}-fleetory-lab-command-v1.spki" -f $foreign)
    [IO.File]::WriteAllBytes($foreignPath, $first.bytes)

    $rotated = New-TestKeyData 2 @{
        '1' = [pscustomobject]@{ public_key = $first.pem }
        '2' = [pscustomobject]@{ public_key = $second.pem }
    }
    $secondPath = Sync-LabCommandTrust $trustDirectory $retiredDirectory `
        $device $rotated $false
    if (-not (Test-Path -LiteralPath $firstPath) -or
        -not (Test-Path -LiteralPath $secondPath)) {
        throw 'Normal rotation did not retain both trusted versions.'
    }

    $restarted = New-TestKeyData 1 @{
        '1' = [pscustomobject]@{ public_key = $restart.pem }
    }
    $rejected = $false
    try {
        Sync-LabCommandTrust $trustDirectory $retiredDirectory `
            $device $restarted $false | Out-Null
    }
    catch { $rejected = $true }
    if (-not $rejected -or -not (Test-Path -LiteralPath $firstPath) -or
        -not (Test-Path -LiteralPath $secondPath)) {
        throw 'Stale trust was modified without explicit reset.'
    }

    $currentPath = Sync-LabCommandTrust $trustDirectory $retiredDirectory `
        $device $restarted $true
    if ($currentPath -ne $firstPath -or
        -not [Linq.Enumerable]::SequenceEqual(
            [byte[]][IO.File]::ReadAllBytes($currentPath), [byte[]]$restart.bytes) -or
        (Test-Path -LiteralPath $secondPath) -or
        -not (Test-Path -LiteralPath $foreignPath) -or
        @(Get-ChildItem -LiteralPath $retiredDirectory -File).Count -ne 2) {
        throw 'Explicit reset did not retire every stale target key.'
    }
    Sync-LabCommandTrust $trustDirectory $retiredDirectory `
        $device $restarted $false | Out-Null
    if (@(Get-ChildItem -LiteralPath $retiredDirectory -File).Count -ne 2) {
        throw 'Idempotent provisioning changed the retired key set.'
    }
    Write-Host 'PASS: normal overlap, stale key rejection, full reset, foreign DeviceId isolation and idempotence.'
}
finally {
    Remove-FleetoryTestArtifacts $work $repoRoot
}
