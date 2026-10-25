# UTF-8 with BOM keeps this PowerShell test usable on Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source = Join-Path $repoRoot 'eng/verify-immudb-state.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $source `
    -Names @(
        'ConvertFrom-Base64Strict', 'Get-ImmudbSha256',
        'ConvertTo-ImmudbUpperHex', 'Test-ImmudbAbsolutePath', 'Get-ImmudbState',
        'New-ImmudbStateSigningPayload', 'ConvertTo-ImmudbPublicKeyPoint',
        'Read-ImmudbDerInteger', 'ConvertFrom-ImmudbDerSignature',
        'Invoke-ImmudbSignatureVerification', 'Get-PinnedImmudbPublicKeyBytes',
        'New-ImmudbStateReceipt', 'Get-ExistingImmudbReceipts',
        'Get-ImmudbReceiptCanonicalJson', 'Get-ImmudbReceiptSha256',
        'Test-ImmudbReceiptChain',
        'Write-ImmudbStateReceipt', 'Get-VerifiedImmudbStateReceipt', 'Invoke-ImmudbStateVerification')

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
        $publicKeyMaterial = ConvertTo-P256PublicKeyMaterial $key
        [IO.File]::WriteAllText($keyPath, $publicKeyMaterial.Pem)
        $publicKey = $publicKeyMaterial.Point

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
            (ConvertTo-DerEcdsaSignature ($key.SignHash(
                (Get-ImmudbSha256 $payload)))))
        $receipt = New-ImmudbStateReceipt $state 'defaultdb' $keyPath
    if ($receipt.txId -ne 42 -or $receipt.txHash -ne $state.txHash -or
        $receipt.schema -ne 'fleetory.immudb-state-receipt.v1') {
        throw 'Signed-state receipt normalization failed.'
    }
    if (-not (Write-ImmudbStateReceipt $receipt $anchor)) {
        throw 'The first receipt was not appended.'
    }
    $originalLine = [IO.File]::ReadAllLines($anchor)[0]
    $firstLine = $originalLine | ConvertFrom-Json
    if ([string]$firstLine.previousReceiptSha256 -ne '' -or
        [string]$firstLine.receiptSha256 -notmatch '^[0-9A-F]{64}$') {
        throw 'The receipt integrity chain was not initialized.'
    }
    if (Write-ImmudbStateReceipt $receipt $anchor) {
        throw 'An identical receipt was appended twice.'
    }

    # Exercise the real ordered-dictionary receipt returned by live state
    # verification, then validate the persisted chain after a forward append.
    $signedNext = New-SignedReceipt $key $publicKey 43 $firstLine.receiptSha256
    $nextState = [pscustomobject]@{
        db = 'defaultdb'; txId = 43; txHash = $signedNext.txHash
        signature = [pscustomobject]@{
            publicKey = [Convert]::ToBase64String($publicKey); signature = $signedNext.signature
        }
    }
    $nextReceipt = New-ImmudbStateReceipt $nextState 'defaultdb' $keyPath
    if (-not (Write-ImmudbStateReceipt $nextReceipt $anchor)) { throw 'A forward state receipt was not appended.' }
    $persisted = @(Get-ExistingImmudbReceipts $anchor)
    if ($persisted.Count -ne 2 -or
        (Test-ImmudbReceiptChain $persisted) -cne $persisted[-1].receiptSha256 -or
        (Write-ImmudbStateReceipt $nextReceipt $anchor)) {
        throw 'Forward state receipt chain or idempotence failed.'
    }
    [IO.File]::WriteAllText($anchor, $originalLine + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))

    $tampered = $firstLine.PSObject.Copy()
    $tampered.txHash = [Convert]::ToBase64String([byte[]](32..63))
    [IO.File]::WriteAllText($anchor,
        ($tampered | ConvertTo-Json -Compress -Depth 4) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
    Assert-Throws { Write-ImmudbStateReceipt $receipt $anchor } `
        'A tampered receipt anchor was accepted.'
    [IO.File]::WriteAllText($anchor, $originalLine,
        [Text.UTF8Encoding]::new($false))

    $olderState = $state.PSObject.Copy()
    $olderState.txId = 41
    $olderPayload = New-ImmudbStateSigningPayload $olderState.db $olderState.txId $hash
    $olderState.signature.signature = [Convert]::ToBase64String(
            (ConvertTo-DerEcdsaSignature ($key.SignHash(
                (Get-ImmudbSha256 $olderPayload)))))
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
    [IO.File]::WriteAllText($anchor, $originalLine + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))

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
