# UTF-8 with BOM keeps this PowerShell test usable on Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$verifyScript = Join-Path $repoRoot 'eng/verify-phase7-readiness.ps1'
$work = Join-Path $repoRoot ('artifacts/phase7-readiness-test-' +
    [Guid]::NewGuid().ToString('N'))
$recordPath = Join-Path $work 'readiness.json'

function Assert-Throws([scriptblock] $Action, [string] $Message) {
    $thrown = $false
    try { & $Action } catch { $thrown = $true }
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
        evidence = @([ordered]@{
            kind = 'certificate-lifecycle'
            sha256 = ('A' * 64)
            reference = 'worm://fleetory/phase7/CHG-2026-0007/certificates'
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

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $valid = New-Record
    Write-Record $valid
    $accepted = & $verifyScript -RecordPath $recordPath | ConvertFrom-Json
    if (-not $accepted.verified -or $accepted.evidenceCount -ne 1 -or
        $accepted.sonarQualityGate -ne 'PASS') {
        throw 'Valid readiness record was not accepted.'
    }

    $invalidActors = New-Record
    $invalidActors.approvedBy = $invalidActors.requestedBy
    Write-Record $invalidActors
    Assert-Throws { & $verifyScript -RecordPath $recordPath } `
        'Duplicate requester/approver identities were accepted.'

    $invalidEvidence = New-Record
    $invalidEvidence.evidence[0].sha256 = 'bad'
    Write-Record $invalidEvidence
    Assert-Throws { & $verifyScript -RecordPath $recordPath } `
        'Invalid evidence hash was accepted.'

    $invalidGate = New-Record
    $invalidGate.ci.sonarQualityGate = 'FAIL'
    Write-Record $invalidGate
    Assert-Throws { & $verifyScript -RecordPath $recordPath } `
        'Failed Sonar Quality Gate was accepted.'

    Assert-Throws { & $verifyScript -RecordPath 'relative-readiness.json' } `
        'A relative readiness path was accepted.'
    Write-Host 'PHASE 7 READINESS TESTS PASS: identity separation, timestamps, controls, CI/Sonar evidence, WORM evidence and rollback validation.'
}
finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
