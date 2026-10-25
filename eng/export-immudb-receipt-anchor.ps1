[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $AnchorPath,
    [Parameter(Mandatory)][string] $ExportPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'immudb-receipt-helpers.ps1')

function Write-ReceiptExport([string] $Path, [byte[]] $Bytes) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw 'The receipt export directory does not exist.'
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $existing = (Read-ReceiptExportSnapshot $Path 'Existing receipt export').Bytes
        if ([Convert]::ToBase64String($existing) -eq [Convert]::ToBase64String($Bytes)) {
            return 'idempotent'
        }
        throw 'The receipt export path already contains different content.'
    }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllBytes($temporary, $Bytes)
        [IO.File]::Move($temporary, $Path)
        return 'accepted'
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

$anchor = Get-ReceiptExportAbsolutePath $AnchorPath 'Anchor path'
$export = Get-ReceiptExportAbsolutePath $ExportPath 'Export path'
if ((Get-Item -LiteralPath $anchor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'The immudb receipt anchor cannot be a symbolic link.'
}
$exportParent = Split-Path -Parent $export
if (-not (Test-Path -LiteralPath $exportParent -PathType Container)) {
    throw 'The receipt export directory does not exist.'
}
if ((Get-Item -LiteralPath $exportParent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'The receipt export directory cannot be a symbolic link.'
}

$snapshot = Read-ReceiptExportAnchor $anchor
$receipts = $snapshot.Receipts
$package = [ordered]@{
    schema = 'fleetory.immudb-receipt-export.v1'
    database = [string]$receipts[0].database
    firstTxId = [long]$receipts[0].txId
    lastTxId = [long]$receipts[-1].txId
    receiptCount = $receipts.Count
    anchorSha256 = $snapshot.Sha256
    receipts = $receipts
} | ConvertTo-Json -Compress -Depth 8
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($package)
if ($bytes.Length -gt 8MB) { throw 'The receipt export size is outside the permitted range.' }
$status = Write-ReceiptExport $export $bytes
Write-Output (ConvertTo-Json ([ordered]@{
    schema = 'fleetory.immudb-receipt-export.v1'
    database = [string]$receipts[0].database
    receiptCount = $receipts.Count
    firstTxId = [long]$receipts[0].txId
    lastTxId = [long]$receipts[-1].txId
    status = $status
}) -Compress)
