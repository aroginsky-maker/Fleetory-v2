# UTF-8 with BOM keeps this PowerShell test usable on Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repoRoot 'eng/verify-immudb-state.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $source `
    -Names @(
        'ConvertFrom-Base64Strict', 'Get-ImmudbState',
        'New-ImmudbStateSigningPayload', 'ConvertTo-ImmudbPublicKeyPoint',
        'Invoke-ImmudbSignatureVerification', 'Get-PinnedImmudbPublicKeyBytes',
        'New-ImmudbStateReceipt', 'Get-ExistingImmudbReceipts',
        'Write-ImmudbStateReceipt', 'Invoke-ImmudbStateVerification')

$work = Join-Path $repoRoot ('artifacts/immudb-state-test-' +
    [Guid]::NewGuid().ToString('N'))
$anchor = Join-Path $work 'receipts.ndjson'
$keyPath = Join-Path $work 'immudb-state-public.pem'

function Assert-Throws([scriptblock] $Action, [string] $Message) {
    $thrown = $false
    try { & $Action } catch { $thrown = $true }
    if (-not $thrown) { throw $Message }
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    try {
        [IO.File]::WriteAllText($keyPath, $key.ExportSubjectPublicKeyInfoPem())
        $publicKey = ConvertTo-ImmudbPublicKeyPoint $key.ExportSubjectPublicKeyInfo()

        $hash = [byte[]](1..32)
        $state = [pscustomobject]@{
            db = 'defaultdb'
            txId = 42
            txHash = [Convert]::ToBase64String($hash)
            signature = [pscustomobject]@{
                publicKey = [Convert]::ToBase64String($publicKey)
                signature = ''
            }
        }
        $payload = New-ImmudbStateSigningPayload $state.db $state.txId $hash
        $state.signature.signature = [Convert]::ToBase64String(
            $key.SignHash(
                [Security.Cryptography.SHA256]::HashData($payload),
                [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence))
        $receipt = New-ImmudbStateReceipt $state 'defaultdb' $keyPath
    if ($receipt.txId -ne 42 -or $receipt.txHash -ne $state.txHash -or
        $receipt.schema -ne 'fleetory.immudb-state-receipt.v1') {
        throw 'Signed-state receipt normalization failed.'
    }
    if (-not (Write-ImmudbStateReceipt $receipt $anchor)) {
        throw 'The first receipt was not appended.'
    }
    if (Write-ImmudbStateReceipt $receipt $anchor) {
        throw 'An identical receipt was appended twice.'
    }

    $olderState = $state.PSObject.Copy()
    $olderState.txId = 41
    $olderPayload = New-ImmudbStateSigningPayload $olderState.db $olderState.txId $hash
    $olderState.signature.signature = [Convert]::ToBase64String(
        $key.SignHash(
            [Security.Cryptography.SHA256]::HashData($olderPayload),
            [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence))
    $olderReceipt = New-ImmudbStateReceipt $olderState 'defaultdb' $keyPath
    Assert-Throws { Write-ImmudbStateReceipt $olderReceipt $anchor } `
        'Rollback state was accepted by the receipt anchor.'

    $conflictState = $state.PSObject.Copy()
    $conflictState.signature = [pscustomobject]@{
        publicKey = [Convert]::ToBase64String($publicKey)
        signature = $receipt.signature
    }
    $conflictReceipt = New-ImmudbStateReceipt $conflictState 'defaultdb' $keyPath
    $conflictReceipt.txHash = [Convert]::ToBase64String([byte[]](32..63))
    Assert-Throws { Write-ImmudbStateReceipt $conflictReceipt $anchor } `
        'Conflicting state at one transaction was accepted.'
    [IO.File]::AppendAllText($anchor,
        '{"schema":"other","database":"otherdb","txId":99,"txHash":"x"}' +
        [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Assert-Throws { Write-ImmudbStateReceipt $receipt $anchor } `
        'An incompatible existing receipt was accepted.'
    $lines = [IO.File]::ReadAllLines($anchor)
    [IO.File]::WriteAllLines($anchor, $lines[0], [Text.UTF8Encoding]::new($false))

    $wrongDatabase = $state.PSObject.Copy()
    $wrongDatabase.db = 'otherdb'
    Assert-Throws { New-ImmudbStateReceipt $wrongDatabase 'defaultdb' $keyPath } `
        'Unexpected database was accepted.'
    $wrongHash = $state.PSObject.Copy()
    $wrongHash.txHash = [Convert]::ToBase64String([byte[]](1..31))
    Assert-Throws { New-ImmudbStateReceipt $wrongHash 'defaultdb' $keyPath } `
        'Short transaction hash was accepted.'
    $missingSignature = $state.PSObject.Copy()
    $missingSignature.signature = $null
    Assert-Throws { New-ImmudbStateReceipt $missingSignature 'defaultdb' $keyPath } `
        'Missing state signature was accepted.'
    Assert-Throws { Write-ImmudbStateReceipt $receipt 'relative.ndjson' } `
        'A relative receipt anchor path was accepted.'

    $state.signature.signature = $receipt.signature
    function Get-ImmudbState([uri] $Origin, [string] $Token) { return $state }
    $verified = Invoke-ImmudbStateVerification ([uri]'https://audit.example/') `
        $keyPath $anchor 'defaultdb' ''
    if ($verified.txId -ne 42) { throw 'The verifier did not return the anchored state.' }

    Write-Host 'IMMUDB STATE TESTS PASS: exact payload signature, receipt append, duplicate, rollback, conflict and fail-closed validation.'
    }
    finally { $key.Dispose() }
}
finally {
    Remove-FleetoryTestArtifacts $work $repoRoot
}
