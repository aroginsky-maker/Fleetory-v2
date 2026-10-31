# Offline checkpoint/rollback checks use only ephemeral fixture keys.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$verify = Join-Path $repoRoot 'eng/verify-immudb-receipt-export.ps1'
$exporter = Join-Path $repoRoot 'eng/export-immudb-receipt-anchor.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') `
    -Source (Join-Path $repoRoot 'eng/verify-immudb-state.ps1') -Names @(
        'Get-ImmudbSha256', 'ConvertTo-ImmudbUpperHex', 'New-ImmudbStateSigningPayload',
        'Get-ImmudbReceiptCanonicalJson', 'Get-ImmudbReceiptSha256')
$work = Join-Path $repoRoot ('artifacts/immudb-checkpoint-test-' + [Guid]::NewGuid().ToString('N'))
$anchor = Join-Path $work 'anchor.ndjson'
$candidate = Join-Path $work 'candidate.json'
$checkpoint = Join-Path $work 'approved-checkpoint.json'
$keyPath = Join-Path $work 'public.pem'
$key = $null
$script:rejections = 0

function Write-Candidate([object[]] $Receipts) {
    $lines = @($Receipts | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 })
    [IO.File]::WriteAllText($anchor, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Force }
    $null = & $exporter -AnchorPath $anchor -ExportPath $candidate
}

function Invoke-CheckpointVerification {
    return & $verify -ExportPath $candidate -AnchorPath $anchor -PublicKeyPath $keyPath `
        -CheckpointPath $checkpoint -ExpectedCheckpointSha256 $approvedDigest | ConvertFrom-Json
}

function Assert-Rejected([scriptblock] $Action, [string] $Expected) {
    try { & $Action } catch {
        if ($_.Exception.Message -notlike "*$Expected*") { throw }
        $script:rejections++
        return
    }
    throw 'An invalid checkpoint or a rewritten receipt history was accepted.'
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    $material = ConvertTo-P256PublicKeyMaterial $key
    [IO.File]::WriteAllText($keyPath, $material.Pem)
    $first = New-SignedReceipt $key $material.Point 1 ''
    $second = New-SignedReceipt $key $material.Point 2 $first.receiptSha256
    $third = New-SignedReceipt $key $material.Point 3 $second.receiptSha256
    Write-Candidate @($first, $second)
    $approvedBytes = [IO.File]::ReadAllBytes($candidate)
    [IO.File]::WriteAllBytes($checkpoint, $approvedBytes)
    $approvedDigest = (Get-FileHash $checkpoint -Algorithm SHA256).Hash
    $equal = Invoke-CheckpointVerification
    if ($equal.checkpointVerified -ne $true -or $equal.checkpointReceiptCount -ne 2 -or
        $equal.checkpointLastTxId -ne 2 -or $equal.checkpointExportSha256 -cne $approvedDigest) {
        throw 'An unchanged approved checkpoint was not accepted.'
    }
    Write-Candidate @($first, $second, $third)
    $forward = Invoke-CheckpointVerification
    if ($forward.lastTxId -ne 3 -or $forward.checkpointLastTxId -ne 2 -or
        $forward.anchorPathVerified -ne $true -or $forward.signaturesVerified -ne $true) {
        throw 'A valid receipt-history extension was rejected.'
    }

    # Roll back both the candidate and its matching anchor. Signatures remain
    # valid, so only the independently identified checkpoint detects rollback.
    Write-Candidate @($first)
    $unguarded = & $verify -ExportPath $candidate -AnchorPath $anchor -PublicKeyPath $keyPath | ConvertFrom-Json
    if ($unguarded.signaturesVerified -ne $true -or $unguarded.anchorPathVerified -ne $true -or
        $unguarded.checkpointVerified -ne $false) { throw 'Checkpoint status is ambiguous without an approved input.' }
    Assert-Rejected { Invoke-CheckpointVerification } 'rolls back'

    $forkFirst = New-SignedReceipt $key $material.Point 1 '' -HashSeed 100
    $forkSecond = New-SignedReceipt $key $material.Point 2 $forkFirst.receiptSha256
    $forkThird = New-SignedReceipt $key $material.Point 3 $forkSecond.receiptSha256
    Write-Candidate @($forkFirst, $forkSecond, $forkThird)
    Assert-Rejected { Invoke-CheckpointVerification } 'rewrites'
    Write-Candidate @($first, (New-SignedReceipt $key $material.Point 2 $first.receiptSha256 -HashSeed 100))
    Assert-Rejected { Invoke-CheckpointVerification } 'rewrites'
    $metadata = $first.PSObject.Copy()
    $metadata.observedAt = ([DateTimeOffset]$first.observedAt).AddHours(1).ToString('o')
    Write-Candidate @($metadata, $second, $third)
    Assert-Rejected { Invoke-CheckpointVerification } 'rewrites'

    $other = New-SignedReceipt $key $material.Point 1 '' -Database 'otherdb'
    Write-Candidate @($other)
    Assert-Rejected { Invoke-CheckpointVerification } 'database differs'
    Write-Candidate @($first, $second, $third)
    [IO.File]::AppendAllText($checkpoint, ' ')
    Assert-Rejected { Invoke-CheckpointVerification } 'approved digest'
    [IO.File]::WriteAllBytes($checkpoint, $approvedBytes)

    # A matching file digest does not excuse an invalid checkpoint signature.
    $invalid = [Text.Encoding]::UTF8.GetString($approvedBytes) | ConvertFrom-Json
    $der = [Convert]::FromBase64String($invalid.receipts[0].signature)
    $der[-1] = $der[-1] -bxor 1
    $invalid.receipts[0].signature = [Convert]::ToBase64String($der)
    $invalid.receipts[0].receiptSha256 = Get-ImmudbReceiptSha256 $invalid.receipts[0]
    $invalid.receipts[1].previousReceiptSha256 = $invalid.receipts[0].receiptSha256
    $invalid.receipts[1].receiptSha256 = Get-ImmudbReceiptSha256 $invalid.receipts[1]
    [IO.File]::WriteAllText($checkpoint, ($invalid | ConvertTo-Json -Compress -Depth 8))
    $invalidDigest = (Get-FileHash $checkpoint -Algorithm SHA256).Hash
    Assert-Rejected {
        & $verify -ExportPath $candidate -PublicKeyPath $keyPath -CheckpointPath $checkpoint `
            -ExpectedCheckpointSha256 $invalidDigest
    } 'signature is invalid'
    [IO.File]::WriteAllBytes($checkpoint, $approvedBytes)

    Assert-Rejected { & $verify -ExportPath $candidate -PublicKeyPath $keyPath -CheckpointPath $checkpoint } 'both its path'
    Assert-Rejected { & $verify -ExportPath $candidate -ExpectedCheckpointSha256 $approvedDigest } 'both its path'
    Assert-Rejected {
        & $verify -ExportPath $candidate -CheckpointPath $checkpoint -ExpectedCheckpointSha256 $approvedDigest
    } 'pinned public key'
    Assert-Rejected {
        & $verify -ExportPath $candidate -PublicKeyPath $keyPath -CheckpointPath 'relative.json' `
            -ExpectedCheckpointSha256 $approvedDigest
    } 'must be an absolute path'
    Assert-Rejected {
        & $verify -ExportPath $candidate -PublicKeyPath $keyPath -CheckpointPath (Join-Path $work 'missing.json') `
            -ExpectedCheckpointSha256 $approvedDigest
    } 'does not exist'
    # Approved SHA-256 spelling is case-insensitive; file content remains exact.
    $lower = & $verify -ExportPath $candidate -PublicKeyPath $keyPath -CheckpointPath $checkpoint `
        -ExpectedCheckpointSha256 $approvedDigest.ToLowerInvariant() | ConvertFrom-Json
    if ($lower.checkpointVerified -ne $true) { throw 'A lowercase approved digest was rejected.' }
    if ((Get-FileHash $checkpoint -Algorithm SHA256).Hash -cne $approvedDigest) {
        throw 'Verification modified its approved checkpoint.'
    }
    Write-Host "IMMUDB CHECKPOINT TESTS PASS: $script:rejections negative cases, approved digest, valid signatures, rollback/fork denial, idempotence and forward extension."
}
finally {
    if ($null -ne $key) { $key.Dispose() }
    Remove-FleetoryTestArtifacts $work $repoRoot
}
