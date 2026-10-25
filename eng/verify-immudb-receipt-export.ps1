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

. (Join-Path $PSScriptRoot 'immudb-receipt-verification.ps1')

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
