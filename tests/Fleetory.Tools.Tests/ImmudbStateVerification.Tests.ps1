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

function ConvertTo-P256PublicKeyMaterial([Security.Cryptography.ECDsa] $Key) {
    $parameters = $Key.ExportParameters($false)
    $point = New-Object byte[] 65
    $point[0] = 4
    [Buffer]::BlockCopy($parameters.Q.X, 0, $point, 1, 32)
    [Buffer]::BlockCopy($parameters.Q.Y, 0, $point, 33, 32)
    $prefix = [byte[]](0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,
        0xCE,0x3D,0x02,0x01,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,
        0x01,0x07,0x03,0x42,0x00)
    $der = New-Object byte[] ($prefix.Length + $point.Length)
    [Buffer]::BlockCopy($prefix, 0, $der, 0, $prefix.Length)
    [Buffer]::BlockCopy($point, 0, $der, $prefix.Length, $point.Length)
    $base64 = [Convert]::ToBase64String($der)
    $lines = for ($offset = 0; $offset -lt $base64.Length; $offset += 64) {
        $length = [Math]::Min(64, $base64.Length - $offset)
        $base64.Substring($offset, $length)
    }
    return [pscustomobject]@{
        Pem = "-----BEGIN PUBLIC KEY-----`r`n$($lines -join "`r`n")`r`n-----END PUBLIC KEY-----`r`n"
        Point = $point
    }
}

function ConvertTo-DerEcdsaSignature([byte[]] $P1363) {
    if ($null -eq $P1363 -or $P1363.Length -ne 64) {
        throw 'The test ECDSA signature must contain two 32-byte components.'
    }
    $components = @()
    foreach ($offset in @(0, 32)) {
        $start = $offset
        while ($start -lt ($offset + 31) -and $P1363[$start] -eq 0) {
            $start++
        }
        $componentLength = $offset + 32 - $start
        $leadingZero = if (($P1363[$start] -band 0x80) -ne 0) { 1 } else { 0 }
        $component = New-Object byte[] ($componentLength + $leadingZero + 2)
        $component[0] = 0x02
        $component[1] = $componentLength + $leadingZero
        if ($leadingZero -eq 1) { $component[2] = 0 }
        [Buffer]::BlockCopy($P1363, $start, $component, 2 + $leadingZero,
            $componentLength)
        $components += ,$component
    }
    $sequenceLength = $components[0].Length + $components[1].Length
    $der = New-Object byte[] ($sequenceLength + 2)
    $der[0] = 0x30
    $der[1] = $sequenceLength
    [Buffer]::BlockCopy($components[0], 0, $der, 2, $components[0].Length)
    [Buffer]::BlockCopy($components[1], 0, $der, 2 + $components[0].Length,
        $components[1].Length)
    return $der
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
    if (Write-ImmudbStateReceipt $receipt $anchor) {
        throw 'An identical receipt was appended twice.'
    }

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
