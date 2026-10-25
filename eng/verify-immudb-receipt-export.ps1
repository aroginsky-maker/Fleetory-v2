# Fleetory immudb receipt-export verifier.
# This verifier is read-only and does not contact a WORM/SIEM destination.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $ExportPath,
    [string] $AnchorPath,
    [string] $PublicKeyPath,
    [string] $CheckpointPath,
    [ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCheckpointSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'immudb-receipt-helpers.ps1')

function Read-ReceiptExport([string] $Path) {
    $snapshot = Read-ReceiptExportSnapshot $Path 'Receipt export'
    try {
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($snapshot.Bytes).TrimStart([char]0xFEFF)
        if ($json -notmatch '^\s*\{') { throw 'Expected an export object.' }
        $package = $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch { throw 'The receipt export is not valid UTF-8 JSON.' }
    return [pscustomobject]@{ Bytes = $snapshot.Bytes; Package = $package }
}

function Test-ReceiptExportPackage(
    $Package,
    [string] $ExpectedAnchorPath,
    [string] $ExpectedPublicKeyPath,
    [byte[]] $ExportBytes) {
    if ($null -eq $Package -or [string]$Package.schema -cne
        'fleetory.immudb-receipt-export.v1') {
        throw 'The receipt export schema is invalid.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$Package.database)) {
        throw 'The receipt export database is missing.'
    }
    if ([string]$Package.anchorSha256 -notmatch '^[0-9A-F]{64}$') {
        throw 'The receipt export anchor hash is invalid.'
    }
    $receipts = @($Package.receipts)
    if ($receipts.Count -eq 0 -or $receipts.Count -gt 100000) {
        throw 'The receipt export receipt count is outside the permitted range.'
    }
    $declaredCount = 0L
    if (-not [long]::TryParse([string]$Package.receiptCount,
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$declaredCount) -or
        $declaredCount -ne $receipts.Count) {
        throw 'The receipt export receipt count does not match its contents.'
    }
    $database = Test-ReceiptExportReceipts $receipts
    if ($database -cne [string]$Package.database) {
        throw 'The receipt export database does not match its receipts.'
    }
    if ([long]$Package.firstTxId -ne [long]$receipts[0].txId -or
        [long]$Package.lastTxId -ne [long]$receipts[-1].txId) {
        throw 'The receipt export transaction range does not match its contents.'
    }

    $anchorVerified = $false
    if (-not [string]::IsNullOrWhiteSpace($ExpectedAnchorPath)) {
        $anchor = Get-ReceiptExportAbsolutePath $ExpectedAnchorPath 'Anchor path'
        $source = Read-ReceiptExportAnchor $anchor
        if ($source.Sha256 -cne [string]$Package.anchorSha256) {
            throw 'The receipt export anchor hash does not match the source anchor.'
        }
        if ($source.Receipts.Count -ne $receipts.Count) {
            throw 'The receipt export does not match the source anchor receipts.'
        }
        for ($index = 0; $index -lt $receipts.Count; $index++) {
            if ((Get-ReceiptExportComparableJson $receipts[$index]) -cne
                (Get-ReceiptExportComparableJson $source.Receipts[$index])) {
                throw 'The receipt export does not match the source anchor receipts.'
            }
        }
        $anchorVerified = $true
    }

    $signaturesVerified = $false
    if (-not [string]::IsNullOrWhiteSpace($ExpectedPublicKeyPath)) {
        $publicKey = Get-ReceiptExportAbsolutePath $ExpectedPublicKeyPath 'Public key path'
        $pinnedPoint = Get-PinnedImmudbPublicKeyBytes $publicKey
        $fingerprint = ConvertTo-ImmudbUpperHex (Get-ImmudbSha256 $pinnedPoint)
        foreach ($receipt in $receipts) {
            if ([string]$receipt.publicKeySha256 -cne $fingerprint) {
                throw 'A receipt public-key fingerprint does not match the pinned key.'
            }
            $txHash = ConvertFrom-Base64Strict ([string]$receipt.txHash) 'receipt transaction hash'
            if ($txHash.Length -ne 32) { throw 'A receipt transaction hash is not 32 bytes.' }
            $signature = ConvertFrom-Base64Strict ([string]$receipt.signature) 'receipt signature'
            $payload = New-ImmudbStateSigningPayload ([string]$receipt.database) `
                ([long]$receipt.txId) $txHash
            Invoke-ImmudbSignatureVerification $payload $signature $pinnedPoint
        }
        $signaturesVerified = $true
    }

    return [ordered]@{
        schema = 'fleetory.immudb-receipt-export-verification.v1'
        database = [string]$Package.database
        receiptCount = [long]$Package.receiptCount
        firstTxId = [long]$Package.firstTxId
        lastTxId = [long]$Package.lastTxId
        anchorSha256 = [string]$Package.anchorSha256
        anchorPathVerified = $anchorVerified
        signaturesVerified = $signaturesVerified
        exportSha256 = Get-ReceiptExportFileSha256 $ExportBytes
    }
}

function Test-ReceiptExportCheckpoint(
    $CurrentPackage, [string] $Path, [string] $ExpectedSha256, [string] $PinnedKeyPath) {
    $checkpoint = Get-ReceiptExportAbsolutePath $Path 'Checkpoint path'
    $read = Read-ReceiptExport $checkpoint
    $digest = Get-ReceiptExportFileSha256 $read.Bytes
    if ($digest -cne $ExpectedSha256.ToUpperInvariant()) {
        throw 'The checkpoint hash does not match the independently approved digest.'
    }
    # A pinned file digest identifies the approved package. Verify its state
    # signatures as well; a new package must retain its complete receipt prefix.
    $prior = Test-ReceiptExportPackage $read.Package '' $PinnedKeyPath $read.Bytes
    if ($CurrentPackage.database -cne $prior.database) {
        throw 'The receipt export database differs from the approved checkpoint.'
    }
    $before = @($read.Package.receipts)
    $after = @($CurrentPackage.receipts)
    if ($after.Count -lt $before.Count -or [long]$CurrentPackage.lastTxId -lt $prior.lastTxId) {
        throw 'The receipt export rolls back the approved checkpoint.'
    }
    for ($index = 0; $index -lt $before.Count; $index++) {
        if ((Get-ReceiptExportComparableJson $before[$index]) -cne
            (Get-ReceiptExportComparableJson $after[$index])) {
            throw 'The receipt export rewrites the approved checkpoint history.'
        }
    }
    return [ordered]@{
        checkpointVerified = $true
        checkpointExportSha256 = $digest
        checkpointReceiptCount = $before.Count
        checkpointLastTxId = $prior.lastTxId
    }
}

$hasCheckpoint = -not [string]::IsNullOrWhiteSpace($CheckpointPath)
$hasCheckpointDigest = -not [string]::IsNullOrWhiteSpace($ExpectedCheckpointSha256)
if ($hasCheckpoint -ne $hasCheckpointDigest) {
    throw 'A checkpoint requires both its path and independently approved SHA-256.'
}
if ($hasCheckpoint -and [string]::IsNullOrWhiteSpace($PublicKeyPath)) {
    throw 'Checkpoint verification requires the independently pinned public key.'
}
$export = Get-ReceiptExportAbsolutePath $ExportPath 'Export path'
if (-not (Test-Path -LiteralPath $export -PathType Leaf)) {
    throw 'The receipt export does not exist.'
}
$read = Read-ReceiptExport $export
$result = Test-ReceiptExportPackage $read.Package $AnchorPath $PublicKeyPath $read.Bytes
$result['checkpointVerified'] = $false
if ($hasCheckpoint) {
    $verifiedCheckpoint = Test-ReceiptExportCheckpoint $read.Package $CheckpointPath `
        $ExpectedCheckpointSha256 $PublicKeyPath
    foreach ($name in $verifiedCheckpoint.Keys) { $result[$name] = $verifiedCheckpoint[$name] }
}
$result | ConvertTo-Json -Compress -Depth 4
