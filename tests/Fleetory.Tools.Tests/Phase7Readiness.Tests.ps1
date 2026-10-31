# UTF-8 with BOM keeps this PowerShell test usable on Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$verifyScript = Join-Path $repoRoot 'eng/verify-phase7-readiness.ps1'
. (Join-Path $repoRoot 'eng/evidence-file-helpers.ps1')
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $verifyScript -Names @(
    'Test-ReadinessAbsolutePath', 'Assert-ReadinessJsonProperties', 'Read-ReadinessRecord', 'Get-ReadinessProperty',
    'Get-RequiredString', 'Get-RequiredObject', 'Assert-ReadinessConfirmation',
    'Get-RequiredActor', 'Get-RequiredUtc', 'Get-RequiredReadinessUri',
    'Get-ReadinessCoverage', 'Test-Phase7Readiness')
$work = Join-Path $repoRoot ('artifacts/phase7-readiness-test-' +
    [Guid]::NewGuid().ToString('N'))
$recordPath = Join-Path $work 'readiness.json'
$clock = [DateTimeOffset]::Parse('2030-01-01T10:45:00Z')
$script:rejections = 0

function Assert-Throws([scriptblock] $Action, [string] $Message, [string] $ExpectedError) {
    $thrown = $false
    try { & $Action } catch {
        if ($_.Exception.Message -notlike "*$ExpectedError*") { throw }
        $thrown = $true
        $script:rejections++
    }
    if (-not $thrown) { throw $Message }
}

function New-Record {
    return [ordered]@{
        schema = 'fleetory.phase7-readiness.v1'
        environment = 'production-eu1'
        changeReference = 'CHG-2026-0007'
        requestedBy = 'person:requester'
        approvedBy = 'person:approver'
        deployedBy = 'person:operator'
        approvedAt = '2030-01-01T10:00:00Z'
        validatedAt = '2030-01-01T10:30:00Z'
        expiresAt = '2030-01-02T10:30:00Z'
        controls = [ordered]@{
            caPki = $true; signer = $true; immudbTls = $true
            wormAnchor = $true; recovery = $true
        }
        ci = [ordered]@{
            runUrl = 'https://github.com/aroginsky-maker/Fleetory-v2/actions/runs/40128148331'
            sonarQualityGate = 'PASS'
            coveragePercent = '93.52'
        }
        evidence = @(foreach ($kind in @('caPki', 'signer', 'immudbTls', 'wormAnchor', 'recovery')) {
            [ordered]@{
                kind = $kind
                sha256 = ('A' * 64)
                reference = "worm://fleetory/phase7/CHG-2026-0007/$kind"
            }
        })
        rollback = [ordered]@{
            plan = 'Restore the approved prior certificate and signer trust versions.'
            validated = $true
        }
    }
}

function Write-Record($Record) {
    [IO.File]::WriteAllText($recordPath,
        ($Record | ConvertTo-Json -Compress -Depth 8),
        [Text.UTF8Encoding]::new($false))
}

function Test-RecordAtClock {
    $document = Read-ReadinessRecord $recordPath
    return Test-Phase7Readiness $document.Record -Now $clock
}

function Assert-RejectedRecord([scriptblock] $Change, [string] $ExpectedError) {
    $record = New-Record
    & $Change $record
    Write-Record $record
    Assert-Throws { Test-RecordAtClock } 'An invalid readiness record was accepted.' $ExpectedError
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $valid = New-Record
    Write-Record $valid
    $accepted = Test-RecordAtClock
    if ($accepted.verified -ne $true -or $accepted.evidenceCount -ne 5 -or
        $accepted.sonarQualityGate -ne 'PASS' -or $accepted.coveragePercent -ne 93.52) {
        throw 'Valid readiness record was not accepted.'
    }

    Assert-RejectedRecord { param($r) $r.approvedBy = $r.requestedBy } 'distinct identities'
    Assert-RejectedRecord { param($r) $r.approvedBy = 'PERSON:REQUESTER' } 'distinct identities'
    Assert-RejectedRecord { param($r) $r.deployedBy = ' person:approver ' } 'distinct identities'
    Assert-RejectedRecord { param($r) $r.deployedBy = 'PERSON:REQUESTER' } 'distinct identities'
    Assert-RejectedRecord { param($r) $r.requestedBy = 'Requesting Person' } 'stable ASCII identifiers'
    Assert-RejectedRecord { param($r) $r.requestedBy = 123 } 'non-empty string'

    Assert-RejectedRecord { param($r) $r.approvedAt = '2030-01-01T10:31:00Z' } 'not monotonic'
    Assert-RejectedRecord { param($r) $r.expiresAt = $r.validatedAt } 'not monotonic'
    Assert-RejectedRecord { param($r) $r.validatedAt = '2030-01-01T10:45:01Z' } 'not currently valid'
    Assert-RejectedRecord { param($r) $r.expiresAt = '2030-01-01T10:45:00Z' } 'not currently valid'
    Assert-RejectedRecord { param($r) $r.expiresAt = '2030-01-01T10:44:59Z' } 'not currently valid'
    foreach ($value in @('2030-01-01T10:00:00+03:00', '2030-01-01T10:00:00+00:00',
        '2030-01-01T10:00:00', '2030-01-01T10:00:00z', '2030-01-01T10:00:00.12345678Z',
        '/Date(1893492000000)/', '01/01/2030 10:00:00', '2030-02-30T10:00:00Z')) {
        Assert-RejectedRecord { param($r) $r.approvedAt = $value } 'UTC timestamp ending in Z'
    }

    foreach ($value in @('true', 'false', 1, 0, $false, $null, @($true))) {
        Assert-RejectedRecord { param($r) $r.controls.signer = $value } 'must be JSON true'
        Assert-RejectedRecord { param($r) $r.rollback.validated = $value } 'must be JSON true'
    }
    Assert-RejectedRecord { param($r) [void]$r.controls.Remove('caPki') } "field 'caPki' is required"
    Assert-RejectedRecord { param($r) $r.controls = @($r.controls) } 'must be a JSON object'
    Assert-RejectedRecord { param($r) $r.rollback.plan = 'short' } 'rollback plan'
    foreach ($value in @('NaN', 'Infinity', '-Infinity', '79.99', '100.01', $true, $null, @('93.52'))) {
        Assert-RejectedRecord { param($r) $r.ci.coveragePercent = $value } 'finite number'
    }
    Assert-RejectedRecord { param($r) $r.ci.sonarQualityGate = 'FAIL' } 'Quality Gate is not PASS'
    foreach ($value in @('https://github.com/', 'https://github.com/u/r/pull/2',
        'https://github.com/u/r/actions/runs/0', 'https://github.com:444/u/r/actions/runs/1')) {
        Assert-RejectedRecord { param($r) $r.ci.runUrl = $value } 'identify a GitHub Actions run'
    }
    foreach ($value in @('/relative', 'http://github.com/u/r/actions/runs/1',
        'https://user:secret@github.com/u/r/actions/runs/1',
        'https://github.com/u/r/actions/runs/1?token=secret',
        'https://github.com/u/r/actions/runs/1#fragment')) {
        Assert-RejectedRecord { param($r) $r.ci.runUrl = $value } 'URI'
    }
    Assert-RejectedRecord { param($r) $r.ci.runUrl = 'https://other.example/u/r/actions/runs/1' } 'identify a GitHub Actions run'
    foreach ($kind in @('caPki', 'signer', 'immudbTls', 'wormAnchor', 'recovery')) {
        Assert-RejectedRecord { param($r) $r.evidence = @($r.evidence | Where-Object { $_.kind -ne $kind }) } 'Evidence for'
    }
    Assert-RejectedRecord { param($r) $r.evidence[0].kind = 'unknown' } 'Evidence kind'
    Assert-RejectedRecord { param($r) $r.evidence[0].sha256 = 'bad' } '64 hexadecimal'
    Assert-RejectedRecord { param($r) $r.evidence[0].reference = 'worm://fleetory/' } 'identify an object'
    foreach ($value in @('local-file.txt', 'file:///tmp/evidence.json',
        'http://objects.example/evidence', 'https://user:secret@objects.example/evidence',
        'https://objects.example/evidence?token=secret')) {
        Assert-RejectedRecord { param($r) $r.evidence[0].reference = $value } 'URI'
    }
    Assert-RejectedRecord { param($r) $r.evidence = @() } 'non-empty evidence array'
    Assert-RejectedRecord { param($r) $r.evidence = $r.evidence[0] } 'non-empty evidence array'
    Assert-RejectedRecord { param($r) $r.evidence[0] = $null } 'JSON object'

    # Exercise exact validity boundaries with a fixed clock, without overriding
    # the public CLI's mandatory wall-clock check.
    $valid.validatedAt = '2030-01-01T10:45:00Z'
    $valid.expiresAt = '2030-01-01T10:45:00.0000001Z'
    foreach ($value in @(80, 100.0, '90.6')) {
        $valid.ci.coveragePercent = $value
        Write-Record $valid
        if ((Test-RecordAtClock).verified -ne $true) { throw 'Valid readiness boundary was rejected.' }
    }

    $live = New-Record
    $now = [DateTime]::UtcNow
    $live.approvedAt = $now.AddMinutes(-15).ToString('o')
    $live.validatedAt = $now.AddMinutes(-5).ToString('o')
    $live.expiresAt = $now.AddHours(1).ToString('o')
    Write-Record $live
    $result = & $verifyScript -RecordPath $recordPath | ConvertFrom-Json
    if ($result.verified -ne $true -or
        $result.recordSha256 -cne (Get-FileHash $recordPath -Algorithm SHA256).Hash -or
        [DateTimeOffset]$result.checkedAt -lt [DateTimeOffset]$now -or
        [DateTimeOffset]$result.expiresAt -le [DateTimeOffset]::UtcNow) {
        throw 'The CLI did not bind its result to the current record and validity interval.'
    }
    $future = New-Record
    $future.approvedAt = $now.AddMinutes(10).ToString('o')
    $future.validatedAt = $now.AddMinutes(15).ToString('o')
    $future.expiresAt = $now.AddHours(1).ToString('o')
    Write-Record $future
    Assert-Throws { & $verifyScript -RecordPath $recordPath } 'A future-dated CLI record was accepted.' 'not currently valid'
    $expired = New-Record
    $expired.approvedAt = $now.AddHours(-2).ToString('o')
    $expired.validatedAt = $now.AddHours(-1).ToString('o')
    $expired.expiresAt = $now.AddMinutes(-1).ToString('o')
    Write-Record $expired
    Assert-Throws { & $verifyScript -RecordPath $recordPath } 'An expired CLI record was accepted.' 'not currently valid'

    Assert-Throws { & $verifyScript -RecordPath 'relative-readiness.json' } `
        'A relative readiness path was accepted.' 'must be absolute'
    foreach ($json in @('[]', '[{}]', '{broken', 'null')) {
        [IO.File]::WriteAllText($recordPath, $json)
        Assert-Throws { Read-ReadinessRecord $recordPath } 'Invalid JSON shape was accepted.' 'UTF-8 JSON object'
    }
    [IO.File]::WriteAllBytes($recordPath, [byte[]](0xFF))
    Assert-Throws { Read-ReadinessRecord $recordPath } 'Invalid UTF-8 was accepted.' 'UTF-8 JSON object'
    foreach ($bytes in @(0, (64KB + 1))) {
        [IO.File]::WriteAllBytes($recordPath, (New-Object byte[] $bytes))
        Assert-Throws { Read-ReadinessRecord $recordPath } 'Invalid file size was accepted.' 'size is outside'
    }

    # The last value must not silently replace a conflicting approved field.
    Write-Record (New-Record)
    $canonical = [IO.File]::ReadAllText($recordPath)
    $ambiguousDocuments = @(
        $canonical.Replace('"signer":true', '"signer":false,"signer":true'),
        $canonical.Replace('"signer":true', '"signer":false,"si\u0067ner":true'),
        $canonical.Replace('"requestedBy":"person:requester"', '"requestedBy":"person:approver","requestedBy":"person:requester"'),
        $canonical.Replace('"approvedAt":"2030-01-01T10:00:00Z"', '"approvedAt":"2030-01-01T11:00:00Z","approvedAt":"2030-01-01T10:00:00Z"'),
        $canonical.Replace('"sonarQualityGate":"PASS"', '"sonarQualityGate":"FAIL","sonarQualityGate":"PASS"'),
        $canonical.Replace('"sha256":"', '"sha256":"bad","sha256":"'),
        $canonical.Replace('"validated":true', '"validated":false,"validated":true')
    )
    foreach ($json in $ambiguousDocuments) {
        if ($json -ceq $canonical) { throw 'Duplicate-property fixture did not change the JSON.' }
        [IO.File]::WriteAllText($recordPath, $json, [Text.UTF8Encoding]::new($false))
        Assert-Throws { Test-RecordAtClock } 'Ambiguous readiness JSON was accepted.' 'UTF-8 JSON object'
    }

    $nested = ('{"child":' * 18) + 'true' + ('}' * 18)
    foreach ($json in @(
        $canonical.Replace('"signer":true', '"signer":false,"Signer":true'),
        ('{"__type":"unexpected:metadata",' + $canonical.Substring(1)),
        ('{"extra":' + $nested + ',' + $canonical.Substring(1))
    )) {
        [IO.File]::WriteAllText($recordPath, $json, [Text.UTF8Encoding]::new($false))
        Assert-Throws { Test-RecordAtClock } 'Unbounded or ambiguous JSON structure was accepted.' 'UTF-8 JSON object'
    }

    # Escaped names remain valid when unique, and every accepted raw byte is hashed.
    $unique = $canonical.Replace('"signer":true', '"si\u0067ner":true')
    [IO.File]::WriteAllText($recordPath, $unique, [Text.UTF8Encoding]::new($true))
    $document = Read-ReadinessRecord $recordPath
    if (-not (Test-Phase7Readiness $document.Record -Now $clock).verified -or
        $document.Sha256 -cne (Get-FileHash $recordPath -Algorithm SHA256).Hash) {
        throw 'Unique escaped fields or their original BOM bytes were not preserved.'
    }
    $boundary = New-Record
    $boundary.rollback.plan = 'Restore approved trust versions; восстановить журнал.'
    Write-Record $boundary
    $payload = [IO.File]::ReadAllBytes($recordPath)
    $padded = New-Object byte[] 65536
    [Buffer]::BlockCopy($payload, 0, $padded, 0, $payload.Length)
    for ($offset = $payload.Length; $offset -lt $padded.Length; $offset++) { $padded[$offset] = 32 }
    [IO.File]::WriteAllBytes($recordPath, $padded)
    $document = Read-ReadinessRecord $recordPath
    if (-not (Test-Phase7Readiness $document.Record -Now $clock).verified -or
        $document.Sha256 -cne (Get-FileHash $recordPath -Algorithm SHA256).Hash) {
        throw 'Exact 64-KiB UTF-8 readiness snapshot or exact-byte hash was rejected.'
    }
    if ($env:OS -ne 'Windows_NT') {
        $link = Join-Path $work 'readiness-link.json'
        [void](New-Item -ItemType SymbolicLink -Path $link -Target $recordPath)
        Assert-Throws { Read-ReadinessRecord $link } 'A linked readiness record was accepted.' 'symbolic link'
    }
    Write-Host "PHASE 7 READINESS TESTS PASS: $script:rejections negative cases, clock boundaries, typed confirmations, unique JSON fields, 64-KiB bound, per-control evidence and exact-byte record hash."
}
finally {
    Remove-FleetoryTestArtifacts $work $repoRoot
}
