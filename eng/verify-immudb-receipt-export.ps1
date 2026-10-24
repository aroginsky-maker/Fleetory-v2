# Fleetory immudb receipt-export verifier.
# This verifier is read-only and does not contact a WORM/SIEM destination.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $ExportPath,
    [string] $AnchorPath,
    [string] $PublicKeyPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$stateSource = Join-Path $PSScriptRoot 'verify-immudb-state.ps1'
$syntaxErrors = $null
$stateAst = [Management.Automation.Language.Parser]::ParseFile(
    $stateSource, [ref]$null, [ref]$syntaxErrors)
if ($syntaxErrors.Count -ne 0) { throw 'The immudb receipt verifier has a syntax error.' }
foreach ($name in @(
    'ConvertFrom-Base64Strict',
    'Get-ImmudbSha256',
    'ConvertTo-ImmudbUpperHex',
    'Test-ImmudbAbsolutePath',
    'Get-ImmudbReceiptCanonicalJson',
    'Get-ImmudbReceiptSha256',
    'Test-ImmudbReceiptChain',
    'New-ImmudbStateSigningPayload',
    'Invoke-ImmudbSignatureVerification',
    'ConvertFrom-ImmudbDerSignature',
    'Read-ImmudbDerInteger',
    'ConvertTo-ImmudbPublicKeyPoint',
    'Get-PinnedImmudbPublicKeyBytes')) {
    $definition = $stateAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing receipt helper: $name." }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Get-ExportAbsolutePath([string] $Path, [string] $Name) {
    if (-not (Test-ImmudbAbsolutePath $Path)) {
        throw "$Name must be an absolute path."
    }
    return [IO.Path]::GetFullPath($Path)
}

function Get-ExportFileSha256([byte[]] $Bytes) {
    return ConvertTo-ImmudbUpperHex (Get-ImmudbSha256 $Bytes)
}

function Read-ReceiptExport([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The receipt export cannot be a symbolic link.'
    }
    if ($item.Length -le 0 -or $item.Length -gt 8MB) {
        throw 'The receipt export size is outside the permitted range.'
    }
    $raw = [IO.File]::ReadAllBytes($Path)
    try { $package = ([Text.UTF8Encoding]::new($false, $true).GetString($raw) | ConvertFrom-Json) }
    catch { throw 'The receipt export is not valid UTF-8 JSON.' }
    return [pscustomobject]@{ Bytes = $raw; Package = $package }
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
    $previousTxId = 0L
    foreach ($receipt in $receipts) {
        if ([string]$receipt.schema -cne 'fleetory.immudb-state-receipt.v1' -or
            [string]$receipt.database -cne [string]$Package.database) {
            throw 'The receipt export contains an incompatible receipt.'
        }
        $txId = 0L
        if (-not [long]::TryParse([string]$receipt.txId,
                [Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture, [ref]$txId) -or
            $txId -le 0 -or $txId -lt $previousTxId) {
            throw 'The receipt export transaction range is not monotonic.'
        }
        $previousTxId = $txId
    }
    [void](Test-ImmudbReceiptChain $receipts)
    if ([long]$Package.firstTxId -ne [long]$receipts[0].txId -or
        [long]$Package.lastTxId -ne [long]$receipts[-1].txId) {
        throw 'The receipt export transaction range does not match its contents.'
    }

    $anchorVerified = $false
    if (-not [string]::IsNullOrWhiteSpace($ExpectedAnchorPath)) {
        $anchor = Get-ExportAbsolutePath $ExpectedAnchorPath 'Anchor path'
        if (-not (Test-Path -LiteralPath $anchor -PathType Leaf)) {
            throw 'The expected anchor file does not exist.'
        }
        $anchorItem = Get-Item -LiteralPath $anchor -Force
        if ($anchorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'The expected anchor cannot be a symbolic link.'
        }
        $anchorHash = Get-ExportFileSha256 ([IO.File]::ReadAllBytes($anchor))
        if ($anchorHash -cne [string]$Package.anchorSha256) {
            throw 'The receipt export anchor hash does not match the source anchor.'
        }
        $anchorVerified = $true
    }

    $signaturesVerified = $false
    if (-not [string]::IsNullOrWhiteSpace($ExpectedPublicKeyPath)) {
        $publicKey = Get-ExportAbsolutePath $ExpectedPublicKeyPath 'Public key path'
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
        exportSha256 = Get-ExportFileSha256 $ExportBytes
    }
}

$export = Get-ExportAbsolutePath $ExportPath 'Export path'
if (-not (Test-Path -LiteralPath $export -PathType Leaf)) {
    throw 'The receipt export does not exist.'
}
$read = Read-ReceiptExport $export
$result = Test-ReceiptExportPackage $read.Package $AnchorPath $PublicKeyPath $read.Bytes
$result | ConvertTo-Json -Compress -Depth 4
