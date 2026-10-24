# UTF-8 with BOM keeps this PowerShell test usable on Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$stateSource = Join-Path $repoRoot 'eng/verify-immudb-state.ps1'
$exportScript = Join-Path $repoRoot 'eng/export-immudb-receipt-anchor.ps1'
$verifyScript = Join-Path $repoRoot 'eng/verify-immudb-receipt-export.ps1'
$work = Join-Path $repoRoot ('artifacts/immudb-receipt-export-verification-test-' +
    [Guid]::NewGuid().ToString('N'))
$anchor = Join-Path $work 'receipts.ndjson'
$export = Join-Path $work 'worm/export.json'
$keyPath = Join-Path $work 'immudb-state-public.pem'

. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $stateSource -Names @(
    'Get-ImmudbSha256', 'ConvertTo-ImmudbUpperHex',
    'New-ImmudbStateSigningPayload', 'Get-ImmudbReceiptCanonicalJson',
    'Get-ImmudbReceiptSha256')

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
        while ($start -lt ($offset + 31) -and $P1363[$start] -eq 0) { $start++ }
        $componentLength = $offset + 32 - $start
        $leadingZero = if (($P1363[$start] -band 0x80) -ne 0) { 1 } else { 0 }
        $component = New-Object byte[] ($componentLength + $leadingZero + 2)
        $component[0] = 0x02
        $component[1] = $componentLength + $leadingZero
        if ($leadingZero -eq 1) { $component[2] = 0 }
        [Buffer]::BlockCopy($P1363, $start, $component, 2 + $leadingZero, $componentLength)
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

function New-SignedReceipt(
    [Security.Cryptography.ECDsa] $Key,
    [byte[]] $PublicPoint,
    [long] $TxId,
    [string] $Previous) {
    $hash = [byte[]](1..32)
    $hash[0] = [byte](($TxId + 1) % 255)
    $receipt = [pscustomobject][ordered]@{
        schema = 'fleetory.immudb-state-receipt.v1'
        database = 'defaultdb'
        txId = $TxId
        txHash = [Convert]::ToBase64String($hash)
        signature = ''
        publicKeySha256 = ConvertTo-ImmudbUpperHex (Get-ImmudbSha256 $PublicPoint)
        observedAt = [DateTimeOffset]::UtcNow.ToString('O')
        previousReceiptSha256 = $Previous
    }
    $payload = New-ImmudbStateSigningPayload $receipt.database $TxId $hash
    $receipt.signature = [Convert]::ToBase64String((ConvertTo-DerEcdsaSignature (
        $Key.SignHash((Get-ImmudbSha256 $payload)))))
    $receipt | Add-Member -NotePropertyName receiptSha256 -NotePropertyValue (
        Get-ImmudbReceiptSha256 $receipt)
    return $receipt
}

function Invoke-Verification([string[]] $Arguments) {
    $parameters = @{}
    for ($index = 0; $index -lt $Arguments.Count; $index += 2) {
        $parameters[$Arguments[$index].TrimStart('-')] = $Arguments[$index + 1]
    }
    try {
        $output = & $verifyScript @parameters
        return [pscustomobject]@{ ExitCode = 0; Output = @($output); Error = $null }
    }
    catch {
        return [pscustomobject]@{ ExitCode = 1; Output = @(); Error = $_.Exception.Message }
    }
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $export) -Force | Out-Null
    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    $wrongKey = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    try {
        $material = ConvertTo-P256PublicKeyMaterial $key
        [IO.File]::WriteAllText($keyPath, $material.Pem)
        $first = New-SignedReceipt $key $material.Point 1 ''
        $second = New-SignedReceipt $key $material.Point 2 $first.receiptSha256
        $anchorLines = @($first, $second) | ForEach-Object {
            $_ | ConvertTo-Json -Compress -Depth 4
        }
        [IO.File]::WriteAllText($anchor,
            ($anchorLines -join [Environment]::NewLine) + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))

        & pwsh -NoProfile -File $exportScript -AnchorPath $anchor -ExportPath $export *> $null
        if ($LASTEXITCODE -ne 0) { throw 'Receipt export setup failed.' }

        $verified = Invoke-Verification @('-ExportPath', $export,
            '-AnchorPath', $anchor, '-PublicKeyPath', $keyPath)
        if ($verified.ExitCode -ne 0) {
            throw "A valid receipt export was not independently verified: $($verified.Error)"
        }
        $verifiedResult = @($verified.Output | ConvertFrom-Json)[0]
        if ($verifiedResult.signaturesVerified -ne $true -or
            $verifiedResult.anchorPathVerified -ne $true) {
            throw 'A valid receipt export returned an incomplete verification summary.'
        }

        $standalone = Invoke-Verification @('-ExportPath', $export)
        if ($standalone.ExitCode -ne 0) { throw 'A self-contained export was rejected.' }

        $package = Get-Content -LiteralPath $export -Raw | ConvertFrom-Json
        $package.anchorSha256 = ('B' * 64)
        [IO.File]::WriteAllText($export,
            ($package | ConvertTo-Json -Compress -Depth 8),
            [Text.UTF8Encoding]::new($false))
        $hashMismatch = Invoke-Verification @('-ExportPath', $export, '-AnchorPath', $anchor)
        if ($hashMismatch.ExitCode -eq 0) { throw 'Mismatched anchor hash was accepted.' }

        Remove-Item -LiteralPath $export -Force
        & pwsh -NoProfile -File $exportScript -AnchorPath $anchor -ExportPath $export *> $null
        if ($LASTEXITCODE -ne 0) { throw 'Receipt export could not be recreated.' }
        $wrongKeyMaterial = ConvertTo-P256PublicKeyMaterial $wrongKey
        $wrongKeyPath = Join-Path $work 'wrong-public.pem'
        [IO.File]::WriteAllText($wrongKeyPath, $wrongKeyMaterial.Pem)
        $wrongKeyResult = Invoke-Verification @('-ExportPath', $export,
            '-PublicKeyPath', $wrongKeyPath)
        if ($wrongKeyResult.ExitCode -eq 0) { throw 'Wrong public key was accepted.' }

        $tampered = Get-Content -LiteralPath $export -Raw | ConvertFrom-Json
        $tampered.receipts[0].txHash = [Convert]::ToBase64String([byte[]](3..34))
        [IO.File]::WriteAllText($export,
            ($tampered | ConvertTo-Json -Compress -Depth 8),
            [Text.UTF8Encoding]::new($false))
        $tamperedResult = Invoke-Verification @('-ExportPath', $export)
        if ($tamperedResult.ExitCode -eq 0) { throw 'Tampered receipt export was accepted.' }

        $relative = Invoke-Verification @('-ExportPath', 'relative-export.json')
        if ($relative.ExitCode -eq 0) { throw 'A relative export path was accepted.' }
        $global:LASTEXITCODE = 0
        Write-Host 'IMMUDB RECEIPT EXPORT VERIFICATION TESTS PASS: schema, anchor hash, chain, signatures and fail-closed tamper checks.'
    }
    finally {
        $key.Dispose()
        $wrongKey.Dispose()
    }
}
finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
