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
. (Join-Path $repoRoot 'eng/immudb-receipt-helpers.ps1')
$script:anchorRejections = 0

function Assert-Throws([scriptblock] $Action, [string] $Message) {
    $thrown = $false
    try { & $Action } catch { $thrown = $true }
    if (-not $thrown) { throw $Message }
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

function Assert-AnchorMismatch($Package, [string] $Expected = 'does not match') {
    [IO.File]::WriteAllText($export, ($Package | ConvertTo-Json -Compress -Depth 8),
        [Text.UTF8Encoding]::new($false))
    $result = Invoke-Verification @('-ExportPath', $export,
        '-AnchorPath', $anchor, '-PublicKeyPath', $keyPath)
    if ($result.ExitCode -eq 0) { throw 'A signed package with different anchor contents was accepted.' }
    if ($result.Error -notlike "*$Expected*") { throw $result.Error }
    $script:anchorRejections++
}

function Read-OriginalPackage { return [Text.Encoding]::UTF8.GetString($originalExport) | ConvertFrom-Json }

function Assert-SourceRejected([string] $Expected) {
    $result = Invoke-Verification @('-ExportPath', $export, '-AnchorPath', $anchor)
    if ($result.ExitCode -eq 0 -or $result.Error -notlike "*$Expected*") {
        throw "An invalid source anchor was not rejected as expected: $($result.Error)"
    }
    $script:anchorRejections++
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

        $originalExport = [IO.File]::ReadAllBytes($export)
        $originalAnchor = [IO.File]::ReadAllBytes($anchor)
        $truncated = Read-OriginalPackage
        $truncated.receipts = @($truncated.receipts[0])
        $truncated.receiptCount = 1
        $truncated.lastTxId = 1
        Assert-AnchorMismatch $truncated

        $suffix = Read-OriginalPackage
        $last = $suffix.receipts[1]
        $last.previousReceiptSha256 = ''
        $last.receiptSha256 = Get-ImmudbReceiptSha256 $last
        $suffix.receipts = @($last)
        $suffix.receiptCount = 1
        $suffix.firstTxId = 2
        Assert-AnchorMismatch $suffix

        $extended = Read-OriginalPackage
        $extended.receipts = @($extended.receipts) + @(
            (New-SignedReceipt $key $material.Point 3 $extended.receipts[-1].receiptSha256))
        $extended.receiptCount = 3
        $extended.lastTxId = 3
        Assert-AnchorMismatch $extended

        # Both receipts remain correctly signed and retain the same count/range.
        $substituted = Read-OriginalPackage
        $substituted.receipts[0] = New-SignedReceipt $key $material.Point 1 '' -HashSeed 100
        $substituted.receipts[1].previousReceiptSha256 = $substituted.receipts[0].receiptSha256
        $substituted.receipts[1].receiptSha256 = Get-ImmudbReceiptSha256 $substituted.receipts[1]
        Assert-AnchorMismatch $substituted

        $metadataChanged = Read-OriginalPackage
        $metadataChanged.receipts[0].observedAt = '2040-01-01T00:00:00Z'
        Assert-AnchorMismatch $metadataChanged
        $extraField = Read-OriginalPackage
        $extraField.receipts[0] | Add-Member -NotePropertyName other -NotePropertyValue 'unbound metadata'
        Assert-AnchorMismatch $extraField 'fields do not match'
        $wrongType = Read-OriginalPackage
        $wrongType.receipts[0].txId = '1'
        Assert-AnchorMismatch $wrongType 'must be an integer'

        # JSON property order and an equivalent timezone spelling do not change content.
        $equivalent = Read-OriginalPackage
        $when = [DateTimeOffset]$equivalent.receipts[0].observedAt
        $equivalent.receipts[0].observedAt = $when.ToOffset([TimeSpan]::FromHours(3)).ToString('o')
        foreach ($index in @(0, 1)) {
            $reordered = [ordered]@{}
            $properties = @($equivalent.receipts[$index].PSObject.Properties)
            [array]::Reverse($properties)
            foreach ($property in $properties) { $reordered[$property.Name] = $property.Value }
            $equivalent.receipts[$index] = [pscustomobject]$reordered
        }
        [IO.File]::WriteAllText($export, ($equivalent | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        $equivalentResult = Invoke-Verification @('-ExportPath', $export, '-AnchorPath', $anchor, '-PublicKeyPath', $keyPath)
        if ($equivalentResult.ExitCode -ne 0) { throw "Equivalent receipt formatting was rejected: $($equivalentResult.Error)" }

        [IO.File]::WriteAllBytes($export, $originalExport)

        # Modify the on-disk file after the buffer has been read but during
        # validation. The returned hash and receipts must still describe that buffer.
        $realChain = (Get-Command Test-ImmudbReceiptChain).ScriptBlock
        function Test-ImmudbReceiptChain($Receipts) {
            $chain = & $realChain $Receipts
            [IO.File]::WriteAllText($anchor, $anchorLines[0] + [Environment]::NewLine)
            return $chain
        }
        try { $snapshot = Read-ReceiptExportAnchor $anchor }
        finally { Set-Item Function:\Test-ImmudbReceiptChain $realChain }
        if ($snapshot.Receipts.Count -ne 2 -or
            $snapshot.Sha256 -cne (Get-ReceiptExportFileSha256 $originalAnchor) -or
            $snapshot.Sha256 -ceq (Get-FileHash $anchor -Algorithm SHA256).Hash) {
            throw 'Anchor parsing and digest were not bound to the same byte snapshot.'
        }
        [IO.File]::WriteAllBytes($anchor, $originalAnchor)
        foreach ($bytes in @(0, (8MB + 1))) {
            [IO.File]::WriteAllBytes($anchor, (New-Object byte[] $bytes))
            Assert-SourceRejected 'size is outside'
        }
        [IO.File]::WriteAllBytes($anchor, [byte[]](0xFF))
        Assert-SourceRejected 'not valid UTF-8'
        [IO.File]::WriteAllText($anchor, '[{}]')
        Assert-SourceRejected 'invalid JSON'
        [IO.File]::WriteAllBytes($anchor, $originalAnchor)

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
        Write-Host "IMMUDB RECEIPT EXPORT VERIFICATION TESTS PASS: $script:anchorRejections anchor-binding rejections, signed-content comparison, snapshot consistency, chain/signatures and equivalent formatting."
    }
    finally {
        $key.Dispose()
        $wrongKey.Dispose()
    }
}
finally {
    Remove-FleetoryTestArtifacts $work $repoRoot
}
