[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string] $AnchorPath,
    [Parameter(Mandatory)][string] $ExportPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$stateSource = Join-Path $PSScriptRoot 'verify-immudb-state.ps1'
$syntaxErrors = $null
$stateAst = [Management.Automation.Language.Parser]::ParseFile(
    $stateSource, [ref]$null, [ref]$syntaxErrors)
if ($syntaxErrors.Count -ne 0) { throw 'The immudb receipt verifier has a syntax error.' }
foreach ($name in @(
    'Get-ImmudbSha256',
    'ConvertTo-ImmudbUpperHex',
    'Get-ImmudbReceiptCanonicalJson',
    'Get-ImmudbReceiptSha256',
    'Get-ExistingImmudbReceipts',
    'Test-ImmudbReceiptChain')) {
    $definition = $stateAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing receipt helper: $name." }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Get-ReceiptExportAbsolutePath([string] $Path, [string] $Name) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Name must be an absolute path."
    }
    return [IO.Path]::GetFullPath($Path)
}

function Get-ReceiptFileSha256([byte[]] $Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Write-ReceiptExport([string] $Path, [byte[]] $Bytes) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw 'The receipt export directory does not exist.'
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $existing = [IO.File]::ReadAllBytes($Path)
        if ([Convert]::ToBase64String($existing) -eq [Convert]::ToBase64String($Bytes)) {
            return 'idempotent'
        }
        throw 'The receipt export path already contains different content.'
    }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllBytes($temporary, $Bytes)
        [IO.File]::Move($temporary, $Path, $false)
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

$receipts = @(Get-ExistingImmudbReceipts $anchor)
if ($receipts.Count -eq 0) { throw 'The immudb receipt anchor is empty.' }
[void](Test-ImmudbReceiptChain $receipts)
if ($receipts | Where-Object { [string]$_.schema -cne 'fleetory.immudb-state-receipt.v1' }) {
    throw 'The immudb receipt anchor contains an incompatible schema.'
}
$rawAnchor = [IO.File]::ReadAllBytes($anchor)
$package = [ordered]@{
    schema = 'fleetory.immudb-receipt-export.v1'
    database = [string]$receipts[0].database
    firstTxId = [long]$receipts[0].txId
    lastTxId = [long]$receipts[-1].txId
    receiptCount = $receipts.Count
    anchorSha256 = (Get-ReceiptFileSha256 $rawAnchor)
    receipts = $receipts
} | ConvertTo-Json -Compress -Depth 8
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($package)
$status = Write-ReceiptExport $export $bytes
Write-Output (ConvertTo-Json ([ordered]@{
    schema = 'fleetory.immudb-receipt-export.v1'
    database = [string]$receipts[0].database
    receiptCount = $receipts.Count
    firstTxId = [long]$receipts[0].txId
    lastTxId = [long]$receipts[-1].txId
    status = $status
}) -Compress)
