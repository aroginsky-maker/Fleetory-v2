# Fleetory immudb restore acceptance verifier.
# Backup and restore are performed by a separately privileged immudb operator.
# This script only reads the restored endpoint with a read-only bearer token.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri] $Address,
    [Parameter(Mandatory)][string] $PublicKeyPath,
    [Parameter(Mandatory)][string] $AnchorPath,
    [Parameter(Mandatory)][string] $KnownEventId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedValueSha256,
    [string] $ExpectedDatabase = 'defaultdb',
    [long] $ExpectedRevision = 1,
    [string] $ReadOnlyBearerToken = $env:FLEETORY_IMMUDB_RESTORE_READ_TOKEN,
    [string] $CheckpointPath,
    [ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCheckpointSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($ReadOnlyBearerToken)) {
    throw 'The read-only immudb bearer token must be supplied through FLEETORY_IMMUDB_RESTORE_READ_TOKEN or the parameter.'
}

# Import the signed-state verifier without running its entry point.
. (Join-Path $PSScriptRoot 'verify-immudb-state.ps1') `
    -Address $Address -PublicKeyPath $PublicKeyPath -AnchorPath $AnchorPath `
    -ExpectedDatabase $ExpectedDatabase -BearerToken $ReadOnlyBearerToken
. (Join-Path $PSScriptRoot 'immudb-receipt-verification.ps1')

function ConvertTo-ImmudbRestoreEventKey([Guid] $EventId) {
    if ($EventId -eq [Guid]::Empty) { throw 'The known audit EventId is empty.' }
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
        'fleetory/audit/v1/' + $EventId.ToString('N')))
}

function ConvertFrom-ImmudbRestoreBase64Strict([string] $Value, [string] $Name) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Name is missing." }
    try { $bytes = [Convert]::FromBase64String($Value) }
    catch { throw "$Name is not valid base64." }
    if ($bytes.Length -eq 0) { throw "$Name is empty." }
    return $bytes
}

function Invoke-ImmudbRestoreGetJson(
    [uri] $Origin, [string] $Token, [string] $Path, [string] $FailureMessage) {
    if ([string]::IsNullOrWhiteSpace($Token)) {
        throw 'The read-only immudb bearer token is missing.'
    }
    return Invoke-ImmudbGetJson $Origin $Token $Path $FailureMessage
}

function Get-ImmudbRestoreDatabaseToken([uri] $Origin, [string] $Token, [string] $Database) {
    if ([string]::IsNullOrWhiteSpace($Database) -or $Database.Length -gt 128 -or
        $Database.IndexOfAny([char[]]@('/', '\', ':')) -ge 0 -or
        $Database -match '\s') {
        throw 'The expected immudb database name is invalid.'
    }
    $body = Invoke-ImmudbRestoreGetJson $Origin $Token `
        ('api/db/use/' + [uri]::EscapeDataString($Database)) `
        'The read-only immudb token could not select the expected database.'
    $selectedToken = [string]$body.token
    if ([string]::IsNullOrWhiteSpace($selectedToken) -or
        $selectedToken.Length -gt 8192 -or $selectedToken -match '\s') {
        throw 'The immudb database-selection response is invalid.'
    }
    return $selectedToken
}

function Get-ImmudbAuditReadback([uri] $Origin, [string] $Token, [string] $Key) {
    return Invoke-ImmudbRestoreGetJson $Origin $Token `
        ('api/db/get/' + [uri]::EscapeDataString($Key)) `
        'The restored immudb audit key could not be read.'
}

function Test-ImmudbRestoredEvent(
    $Response,
    [Guid] $EventId,
    [long] $ExpectedRevision,
    [string] $ExpectedValueSha256) {
    if ($null -eq $Response) { throw 'The restored immudb audit response is empty.' }
    if ($ExpectedRevision -le 0) { throw 'The expected immudb revision is invalid.' }
    $expectedKey = ConvertTo-ImmudbRestoreEventKey $EventId
    if ([string]$Response.key -cne $expectedKey) {
        throw 'The restored immudb audit key does not match the known EventId.'
    }
    $revision = 0L
    if (-not [long]::TryParse([string]$Response.revision,
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$revision) -or
        $revision -ne $ExpectedRevision) {
        throw 'The restored immudb audit key has an unexpected revision.'
    }
    $valueBytes = ConvertFrom-ImmudbRestoreBase64Strict ([string]$Response.value) `
        'restored immudb audit value'
    $actualHash = ConvertTo-ImmudbUpperHex (Get-ImmudbSha256 $valueBytes)
    if ($actualHash -ine $ExpectedValueSha256) {
        throw 'The restored immudb audit value hash does not match the acceptance record.'
    }
    return [ordered]@{
        eventId = $EventId.ToString('N')
        revision = $revision
        valueSha256 = $actualHash
    }
}

function Get-ImmudbRestorePoint(
    [string] $CheckpointPath, [string] $ExpectedSha256,
    [string] $PublicKeyPath, [string] $ExpectedDatabase) {
    $hasPath = -not [string]::IsNullOrWhiteSpace($CheckpointPath)
    $hasDigest = -not [string]::IsNullOrWhiteSpace($ExpectedSha256)
    if ($hasPath -ne $hasDigest) { throw 'A restore checkpoint requires both its path and approved SHA-256.' }
    if (-not $hasPath) { return $null }
    $checkpoint = Get-VerifiedReceiptCheckpoint $CheckpointPath $ExpectedSha256 $PublicKeyPath
    if ($checkpoint.Summary.database -cne $ExpectedDatabase) {
        throw 'The approved restore checkpoint uses a different database.'
    }
    $last = @($checkpoint.Package.receipts)[-1]
    return [pscustomobject]@{
        Sha256 = $checkpoint.Sha256
        TxId = [long]$last.txId
        TxHash = [Convert]::ToBase64String([Convert]::FromBase64String($last.txHash))
    }
}

function Invoke-ImmudbRestoreAcceptance(
    [uri] $Origin,
    [string] $PublicKeyPath,
    [string] $AnchorPath,
    [string] $ExpectedDatabase,
    [Guid] $EventId,
    [long] $ExpectedRevision,
    [string] $ExpectedValueSha256,
    [string] $ReadOnlyToken,
    [string] $CheckpointPath = '',
    [string] $ExpectedCheckpointSha256 = '') {
    $point = Get-ImmudbRestorePoint $CheckpointPath $ExpectedCheckpointSha256 $PublicKeyPath $ExpectedDatabase
    $databaseToken = Get-ImmudbRestoreDatabaseToken $Origin $ReadOnlyToken $ExpectedDatabase
    $receipt = Get-VerifiedImmudbStateReceipt $Origin $PublicKeyPath $ExpectedDatabase $databaseToken
    if ($null -ne $point -and ($receipt.txId -ne $point.TxId -or $receipt.txHash -cne $point.TxHash)) {
        throw 'The restored signed state does not match the approved restore point.'
    }
    $key = ConvertTo-ImmudbRestoreEventKey $EventId
    $response = Get-ImmudbAuditReadback $Origin $databaseToken $key
    $restoredEvent = Test-ImmudbRestoredEvent $response $EventId $ExpectedRevision `
        $ExpectedValueSha256
    $confirmed = Get-VerifiedImmudbStateReceipt $Origin $PublicKeyPath $ExpectedDatabase $databaseToken
    if ($confirmed.txId -ne $receipt.txId -or $confirmed.txHash -cne $receipt.txHash -or
        $confirmed.publicKeySha256 -cne $receipt.publicKeySha256) {
        throw 'The restored signed state changed during acceptance.'
    }
    # Failed state/event checks must never establish a new local acceptance tip.
    [void](Write-ImmudbStateReceipt $confirmed $AnchorPath)
    return [ordered]@{
        schema = 'fleetory.immudb-restore-acceptance.v1'
        database = $ExpectedDatabase
        receiptTxId = [long]$receipt.txId
        receiptTxHash = $receipt.txHash
        checkpointVerified = $null -ne $point
        checkpointExportSha256 = if ($null -ne $point) { $point.Sha256 } else { $null }
        knownEventId = $restoredEvent.eventId
        revision = $restoredEvent.revision
        valueSha256 = $restoredEvent.valueSha256
        acceptedAt = [DateTimeOffset]::UtcNow.ToString('O',
            [Globalization.CultureInfo]::InvariantCulture)
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $eventId = [Guid]::Empty
    if (-not [Guid]::TryParse($KnownEventId, [ref]$eventId) -or
        $eventId -eq [Guid]::Empty) {
        throw 'The known audit EventId is invalid.'
    }
    if ($ExpectedRevision -le 0) { throw 'The expected immudb revision is invalid.' }
    $result = Invoke-ImmudbRestoreAcceptance $Address $PublicKeyPath $AnchorPath `
        $ExpectedDatabase $eventId $ExpectedRevision $ExpectedValueSha256 `
        $ReadOnlyBearerToken $CheckpointPath $ExpectedCheckpointSha256
    $result | ConvertTo-Json -Compress -Depth 4
}
