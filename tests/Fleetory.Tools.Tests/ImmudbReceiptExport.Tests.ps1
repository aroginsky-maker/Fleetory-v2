$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exportScript = Join-Path $repoRoot 'eng/export-immudb-receipt-anchor.ps1'
$work = Join-Path $repoRoot ('artifacts/immudb-receipt-export-test-' + [Guid]::NewGuid().ToString('N'))
$anchor = Join-Path $work 'receipts.ndjson'
$export = Join-Path $work 'worm/export.json'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source (Join-Path $repoRoot 'eng/verify-immudb-state.ps1') -Names @('Get-ImmudbSha256', 'ConvertTo-ImmudbUpperHex', 'Get-ImmudbReceiptCanonicalJson', 'Get-ImmudbReceiptSha256')

function New-TestReceipt([long] $TxId, [string] $Previous) {
    $receipt = [pscustomobject][ordered]@{
        schema = 'fleetory.immudb-state-receipt.v1'
        database = 'defaultdb'
        txId = $TxId
        txHash = [Convert]::ToBase64String([byte[]](1..32))
        signature = [Convert]::ToBase64String([byte[]](2..33))
        publicKeySha256 = ('A' * 64)
        observedAt = [DateTimeOffset]::UtcNow.ToString('O')
        previousReceiptSha256 = $Previous
    }
    $receipt | Add-Member -NotePropertyName receiptSha256 -NotePropertyValue (Get-ImmudbReceiptSha256 $receipt)
    return $receipt
}

function Invoke-ReceiptExport {
    $output = & $exportScript -AnchorPath $anchor -ExportPath $export
    return $output | ConvertFrom-Json
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $export) -Force | Out-Null
    $first = New-TestReceipt 1 ''
    $second = New-TestReceipt 2 $first.receiptSha256
    $anchorLines = @($first, $second) | ForEach-Object {
        $_ | ConvertTo-Json -Compress -Depth 4
    }
    [IO.File]::WriteAllText($anchor,
        ($anchorLines -join [Environment]::NewLine) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))

    $accepted = Invoke-ReceiptExport
    if ($accepted.status -ne 'accepted' -or $accepted.receiptCount -ne 2) {
        throw 'Initial receipt export was not accepted.'
    }
    $repeat = Invoke-ReceiptExport
    if ($repeat.status -ne 'idempotent') { throw 'Repeated receipt export was not idempotent.' }

    $existing = Join-Path $work 'worm/existing.json'
    [IO.File]::WriteAllText($existing, 'retained content')
    $overwriteDenied = $false
    try { & $exportScript -AnchorPath $anchor -ExportPath $existing *> $null }
    catch {
        if ($_.Exception.Message -notlike '*different content*') { throw }
        $overwriteDenied = $true
    }
    if (-not $overwriteDenied -or [IO.File]::ReadAllText($existing) -cne 'retained content') {
        throw 'An existing receipt export was overwritten.'
    }

    $tampered = [IO.File]::ReadAllText($anchor).Replace(
        [Convert]::ToBase64String([byte[]](1..32)),
        [Convert]::ToBase64String([byte[]](3..34)))
    [IO.File]::WriteAllText($anchor, $tampered, [Text.UTF8Encoding]::new($false))
    $newExport = Join-Path $work 'worm/tampered.json'
    $tamperFailed = $false
    try { & $exportScript -AnchorPath $anchor -ExportPath $newExport *> $null }
    catch { $tamperFailed = $true }
    if (-not $tamperFailed) {
        throw 'Tampered receipt anchor was exported.'
    }
    $global:LASTEXITCODE = 0
    Write-Host 'IMMUDB RECEIPT EXPORT TESTS PASS: chain validation, bounded snapshot, atomic no-overwrite export and idempotence.'
}
finally {
    Remove-FleetoryTestArtifacts $work $repoRoot
}
