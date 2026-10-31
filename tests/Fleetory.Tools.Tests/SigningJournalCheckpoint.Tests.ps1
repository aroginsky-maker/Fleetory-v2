#requires -Version 7.2
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source (Join-Path $PSScriptRoot 'SigningJournalSnapshot.Tests.ps1') -Names @('New-SnapshotFixture')
$verifierPath = Join-Path $repo 'eng/verify-signing-journal-snapshot.ps1'
$work = Join-Path $repo ('artifacts/signer-checkpoint-' + [Guid]::NewGuid().ToString('N'))
$candidatePath = Join-Path $work 'candidate.json'
$checkpointPath = Join-Path $work 'checkpoint.json'
$tables = @('requests', 'results', 'rejections', 'revocations')
$utf8 = [Text.UTF8Encoding]::new($false)

function Copy-CheckpointFixture($Value) {
    $copy = [ordered]@{}
    foreach ($key in $Value.Keys) {
        if ($key -notin $tables) { $copy[$key] = $Value[$key]; continue }
        $copy[$key] = @(foreach ($row in $Value[$key]) {
            $record = [ordered]@{}
            foreach ($field in $row.Keys) { $record[$field] = $row[$field] }
            $record
        })
    }
    return $copy
}

function Write-CheckpointFixture([string] $Path, $Value) {
    $bytes = $utf8.GetBytes((ConvertTo-Json $Value -Compress -Depth 8) + "`n")
    [IO.File]::WriteAllBytes($Path, $bytes)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
}

function Invoke-CheckpointVerification($Candidate, $Checkpoint) {
    $candidateDigest = Write-CheckpointFixture $candidatePath $Candidate
    $checkpointDigest = Write-CheckpointFixture $checkpointPath $Checkpoint
    $result = (& $verifierPath -SnapshotPath $candidatePath -ExpectedSha256 $candidateDigest `
        -CheckpointPath $checkpointPath -CheckpointSha256 $checkpointDigest) | ConvertFrom-Json
    if (-not $result.checkpointVerified -or $result.checkpointSha256 -cne $checkpointDigest -or
        $result.deliveryVerified -or $result.executionVerified -or $result.independentCustodyVerified) {
        throw 'Signer checkpoint summary is incorrect.'
    }
    foreach ($entry in @(@($candidatePath, $candidateDigest), @($checkpointPath, $checkpointDigest))) {
        $actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($entry[0])))
        if ($actual -cne $entry[1]) { throw 'Checkpoint verification modified retained evidence.' }
    }
}

function Assert-CheckpointRejected($Candidate, $Checkpoint, [string] $Name) {
    $failed = $false
    try { Invoke-CheckpointVerification $Candidate $Checkpoint }
    catch { $failed = $true }
    if (-not $failed) { throw "Invalid checkpoint history accepted: $Name" }
}

try {
    [void](New-Item -ItemType Directory -Path $work)
    $checkpoint = New-SnapshotFixture
    Invoke-CheckpointVerification (Copy-CheckpointFixture $checkpoint) $checkpoint

    $forward = Copy-CheckpointFixture $checkpoint
    $newRows = New-SnapshotFixture
    $newRows.revocations[0].certificate_sha256 = 'E' * 64
    foreach ($table in $tables) { $forward[$table] = @($newRows[$table]) + @($forward[$table]) }
    $forward.observedAt = '2026-10-27T12:00:00Z'
    $forward.databaseOperator = 'rotated_reader'
    Invoke-CheckpointVerification $forward $checkpoint

    $pending = Copy-CheckpointFixture $checkpoint
    $pending.results = @()
    Invoke-CheckpointVerification (Copy-CheckpointFixture $checkpoint) $pending

    $equivalent = Copy-CheckpointFixture $checkpoint
    $equivalent.observedAt = '2026-10-27T11:00:00.1234560Z'
    foreach ($table in $tables) {
        foreach ($row in $equivalent[$table]) {
            foreach ($field in @($row.Keys)) {
                if ($field -in @('request_id', 'target_device_id', 'event_id', 'command_id') -and $null -ne $row[$field]) {
                    $row[$field] = $row[$field].ToUpperInvariant()
                }
                if ($field.EndsWith('_at', [StringComparison]::Ordinal)) { $row[$field] = '2026-10-27T11:00:00.1234560Z' }
            }
        }
    }
    Invoke-CheckpointVerification $equivalent $checkpoint

    $changedFields = @{ requests = 'caller_id'; results = 'signing_key_id'; rejections = 'reason'; revocations = 'incident_reference' }
    foreach ($table in $tables) {
        $rollback = Copy-CheckpointFixture $checkpoint
        $rollback[$table] = @()
        Assert-CheckpointRejected $rollback $checkpoint "missing $table"
        $changed = Copy-CheckpointFixture $checkpoint
        $changed[$table][0][$changedFields[$table]] = 'changed'
        Assert-CheckpointRejected $changed $checkpoint "changed $table"
        $duplicate = Copy-CheckpointFixture $checkpoint
        $duplicate[$table] = @($duplicate[$table][0], $duplicate[$table][0])
        Assert-CheckpointRejected $duplicate $checkpoint "duplicate identity $table"
    }
    $wrongDatabase = Copy-CheckpointFixture $checkpoint
    $wrongDatabase.database = 'other_test'
    Assert-CheckpointRejected $wrongDatabase $checkpoint 'different database'
    $earlier = Copy-CheckpointFixture $checkpoint
    $earlier.observedAt = '2026-10-27T10:00:00Z'
    Assert-CheckpointRejected $earlier $checkpoint 'earlier observation'
    $resubmitted = Copy-CheckpointFixture $checkpoint
    $resubmitted.observedAt = '2026-10-27T12:01:00Z'
    Assert-CheckpointRejected $resubmitted $forward 'old history resubmitted with a fresh observation and matching digest'

    $candidateDigest = Write-CheckpointFixture $candidatePath $checkpoint
    $checkpointDigest = Write-CheckpointFixture $checkpointPath $checkpoint
    foreach ($parameters in @(
        @{ CheckpointPath = $checkpointPath },
        @{ CheckpointSha256 = $checkpointDigest },
        @{ CheckpointPath = $checkpointPath; CheckpointSha256 = ('0' * 64) }
    )) {
        $failed = $false
        try { & $verifierPath -SnapshotPath $candidatePath -ExpectedSha256 $candidateDigest @parameters *> $null }
        catch { $failed = $true }
        if (-not $failed) { throw 'Incomplete or unapproved checkpoint input was accepted.' }
    }
    Write-Host 'SIGNER CHECKPOINT PASS: identical/forward/late-completion history, normalized representation, rollback/tamper/duplicate denial and unchanged input artifacts.'
    $global:LASTEXITCODE = 0
}
finally { Remove-FleetoryTestArtifacts $work $repo }
