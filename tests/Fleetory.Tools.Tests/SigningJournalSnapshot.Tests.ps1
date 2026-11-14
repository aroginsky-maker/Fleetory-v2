#requires -Version 7.2
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repo 'eng/verify-signing-journal-snapshot.ps1'
$work = Join-Path $repo ('artifacts/signer-snapshot-verification-' + [Guid]::NewGuid().ToString('N'))
$snapshotPath = Join-Path $work 'snapshot.json'
$utf8 = [Text.UTF8Encoding]::new($false)

function New-SnapshotFixture {
    $request = [Guid]::NewGuid().ToString()
    $device = [Guid]::NewGuid().ToString()
    $time = '2026-10-27T11:00:00.123456+00:00'
    return [ordered]@{
        schema = 'fleetory.signer-journal-snapshot.v1'
        observedAt = $time
        database = 'signer_test'
        databaseOperator = 'evidence_reader'
        readOnly = $true
        snapshotComplete = $true
        deliveryVerified = $false
        executionVerified = $false
        independentCustodyVerified = $false
        requests = @([ordered]@{ request_id = $request; caller_id = 'approval'; client_certificate_sha256 = ('A' * 64)
            target_device_id = $device; command_type = 'Inventory.Refresh'; accepted_at = $time })
        results = @([ordered]@{ request_id = $request; command_id = [Guid]::NewGuid().ToString()
            signing_key_id = 'test-key'; envelope_sha256 = ('B' * 64); recorded_at = $time })
        rejections = @([ordered]@{ event_id = [Guid]::NewGuid().ToString(); client_certificate_sha256 = ('A' * 64)
            reason = 'Unavailable'; request_id = $null; target_device_id = $null; recorded_at = $time })
        revocations = @([ordered]@{ certificate_sha256 = ('C' * 64); event_id = [Guid]::NewGuid().ToString()
            incident_reference = 'ИНЦИДЕНТ-漢字-é'; operator_reference = 'operator'; approver_reference = 'approver'
            evidence_sha256 = ('D' * 64); database_operator = 'revocation_operator'; revoked_at = $time })
    }
}

function Write-SnapshotFixture($Value, [string] $Suffix = "`n") {
    $text = ConvertTo-Json $Value -Compress -Depth 8
    [IO.File]::WriteAllBytes($snapshotPath, $utf8.GetBytes($text + $Suffix))
}

function Get-TestSnapshotHash {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($snapshotPath)))
}

function Assert-SnapshotRejected([string] $Name, [string] $Digest = '') {
    if ($Digest -eq '') { $Digest = Get-TestSnapshotHash }
    $rejected = $false
    try { & $source -SnapshotPath $snapshotPath -ExpectedSha256 $Digest *> $null }
    catch { $rejected = $true }
    if (-not $rejected) { throw "Invalid signer snapshot accepted: $Name" }
}

try {
    [void](New-Item -ItemType Directory -Path $work)
    foreach ($suffix in @('', "`n", "`r`n")) {
        Write-SnapshotFixture (New-SnapshotFixture) $suffix
        $approved = Get-TestSnapshotHash
        $verified = (& $source -SnapshotPath $snapshotPath -ExpectedSha256 $approved.ToLowerInvariant()) | ConvertFrom-Json
        if ($verified.snapshotSha256 -cne $approved -or -not $verified.approvedDigestMatched -or
            $verified.rowCounts.requests -ne 1 -or $verified.rowCounts.revocations -ne 1 -or
            $verified.deliveryVerified -or $verified.executionVerified -or $verified.independentCustodyVerified) {
            throw 'Valid signer snapshot verification summary is incorrect.'
        }
        if ((Get-TestSnapshotHash) -cne $approved) { throw 'Verification changed the snapshot.' }
    }
    $empty = New-SnapshotFixture
    foreach ($name in @('requests', 'results', 'rejections', 'revocations')) { $empty[$name] = @() }
    Write-SnapshotFixture $empty
    $verified = (& $source -SnapshotPath $snapshotPath -ExpectedSha256 (Get-TestSnapshotHash)) | ConvertFrom-Json
    if ($verified.rowCounts.requests -ne 0) { throw 'Empty snapshot was not accepted.' }
    $boundary = (ConvertTo-Json $empty -Compress -Depth 8).PadRight(8MB, ' ')
    foreach ($suffix in @("`n", "`r`n")) {
        [IO.File]::WriteAllBytes($snapshotPath, $utf8.GetBytes($boundary + $suffix))
        $verified = (& $source -SnapshotPath $snapshotPath -ExpectedSha256 (Get-TestSnapshotHash)) | ConvertFrom-Json
        if ($verified.snapshotBytes -ne (8MB + $suffix.Length)) { throw 'Native newline was omitted from the retained byte count.' }
    }
    [IO.File]::WriteAllBytes($snapshotPath, $utf8.GetBytes($boundary + " `n"))
    Assert-SnapshotRejected 'oversized JSON payload with permitted suffix'

    $cases = @(
        @{ name = 'schema'; change = { param($v) $v.schema = 'unknown' } }
        @{ name = 'missing'; change = { param($v) $v.Remove('database') } }
        @{ name = 'unknown'; change = { param($v) $v.extra = 'private-sentinel' } }
        @{ name = 'string flag'; change = { param($v) $v.readOnly = 'true' } }
        @{ name = 'numeric flag'; change = { param($v) $v.snapshotComplete = 1 } }
        @{ name = 'delivery claim'; change = { param($v) $v.deliveryVerified = $true } }
        @{ name = 'execution claim'; change = { param($v) $v.executionVerified = $true } }
        @{ name = 'custody claim'; change = { param($v) $v.independentCustodyVerified = $true } }
        @{ name = 'non-UTC'; change = { param($v) $v.observedAt = '2026-10-27T12:00:00+01:00' } }
        @{ name = 'invalid date'; change = { param($v) $v.observedAt = '2026-02-30T11:00:00Z' } }
        @{ name = 'blank identity'; change = { param($v) $v.databaseOperator = ' ' } }
        @{ name = 'not array'; change = { param($v) $v.requests = [ordered]@{} } }
        @{ name = 'too many rows'; change = { param($v) $v.rejections = @($v.rejections[0]) * 5001 } }
        @{ name = 'not object row'; change = { param($v) $v.results = @('private-sentinel') } }
        @{ name = 'row extra field'; change = { param($v) $v.requests[0].privateKey = 'private-sentinel' } }
        @{ name = 'null field'; change = { param($v) $v.requests[0].caller_id = $null } }
        @{ name = 'wrong digest'; change = { param($v) $v.results[0].envelope_sha256 = 'not-a-digest' } }
        @{ name = 'UUID'; change = { param($v) $v.results[0].command_id = 'not-a-uuid' } }
        @{ name = 'row date'; change = { param($v) $v.results[0].recorded_at = 'yesterday' } }
        @{ name = 'digest newline'; change = { param($v) $v.results[0].envelope_sha256 += "`n" } }
        @{ name = 'UUID whitespace'; change = { param($v) $v.results[0].command_id = ' ' + $v.results[0].command_id + ' ' } }
        @{ name = 'date newline'; change = { param($v) $v.observedAt += "`n" } }
    )
    foreach ($case in $cases) {
        $fixture = New-SnapshotFixture
        & $case.change $fixture
        Write-SnapshotFixture $fixture
        Assert-SnapshotRejected $case.name
    }
    Write-SnapshotFixture (New-SnapshotFixture)
    Assert-SnapshotRejected 'approved digest mismatch' ('0' * 64)
    $json = [IO.File]::ReadAllText($snapshotPath)
    $jsonCases = [ordered]@{
        'duplicate flag' = $json.Replace('"readOnly":true', '"readOnly":true,"readOnly":true')
        'duplicate row field' = $json.Replace('"caller_id":"approval"', '"caller_id":"approval","caller_id":"other"')
        'two documents' = ($json + $json)
        'malformed object' = '{"private-sentinel":'
        'excessive nesting' = (('[' * 10) + '0' + (']' * 10))
    }
    foreach ($name in $jsonCases.Keys) {
        [IO.File]::WriteAllBytes($snapshotPath, $utf8.GetBytes($jsonCases[$name]))
        Assert-SnapshotRejected $name
    }
    [IO.File]::WriteAllBytes($snapshotPath, [byte[]]@(0xC3, 0x28))
    Assert-SnapshotRejected 'invalid UTF-8'
    [IO.File]::WriteAllBytes($snapshotPath, [Text.Encoding]::Unicode.GetBytes($json))
    Assert-SnapshotRejected 'UTF-16 capture'
    [IO.File]::WriteAllBytes($snapshotPath, [byte[]]::new(0))
    Assert-SnapshotRejected 'empty file'
    [IO.File]::WriteAllBytes($snapshotPath, [byte[]]::new(8MB + 3))
    Assert-SnapshotRejected 'oversized file'
    Write-SnapshotFixture (New-SnapshotFixture)
    # File symlink creation needs a Windows privilege; Linux CI exercises this rejection.
    if (-not $IsWindows) {
        $link = Join-Path $work 'linked.json'
        [void](New-Item -ItemType SymbolicLink -Path $link -Target $snapshotPath)
        $rejected = $false
        try { & $source -SnapshotPath $link -ExpectedSha256 (Get-TestSnapshotHash) *> $null }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'Snapshot symbolic link was accepted.' }
    }
    Write-Host 'SIGNER SNAPSHOT VERIFICATION PASS: approved exact-byte digest, UTF-8, strict typed schema, limits, no writes and no external custody claim.'
    $global:LASTEXITCODE = 0
}
finally {
    $root = [IO.Path]::GetFullPath((Join-Path $repo 'artifacts')) + [IO.Path]::DirectorySeparatorChar
    $target = [IO.Path]::GetFullPath($work)
    if ($target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $target)) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}
