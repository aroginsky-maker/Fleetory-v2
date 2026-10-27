# Shared helpers for immudb receipt export operations.

. (Join-Path $PSScriptRoot 'evidence-file-helpers.ps1')
$stateSource = Join-Path $PSScriptRoot 'verify-immudb-state.ps1'
$syntaxErrors = $null
$stateAst = [Management.Automation.Language.Parser]::ParseFile(
    $stateSource, [ref]$null, [ref]$syntaxErrors)
if ($syntaxErrors.Count -ne 0) {
    throw 'The immudb receipt verifier has a syntax error.'
}
foreach ($name in @(
    'ConvertFrom-Base64Strict',
    'Get-ImmudbSha256',
    'ConvertTo-ImmudbUpperHex',
    'Test-ImmudbAbsolutePath',
    'Get-ImmudbReceiptCanonicalJson',
    'Get-ImmudbReceiptSha256',
    'Get-ExistingImmudbReceipts',
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

function Get-ReceiptExportAbsolutePath([string] $Path, [string] $Name) {
    if (-not (Test-ImmudbAbsolutePath $Path)) {
        throw "$Name must be an absolute path."
    }
    return [IO.Path]::GetFullPath($Path)
}

function Get-ReceiptExportFileSha256([byte[]] $Bytes) {
    return ConvertTo-ImmudbUpperHex (Get-ImmudbSha256 $Bytes)
}

function Read-ReceiptExportSnapshot([string] $Path, [string] $Name) {
    return Read-BoundedEvidenceSnapshot $Path $Name
}

function Get-ReceiptExportComparableJson($Receipt) {
    $names = @('schema', 'database', 'txId', 'txHash', 'signature', 'publicKeySha256',
        'observedAt', 'previousReceiptSha256', 'receiptSha256')
    if ($Receipt -isnot [pscustomobject] -or @($Receipt.PSObject.Properties).Count -ne $names.Count) {
        throw 'The receipt fields do not match the v1 schema.'
    }
    $normalized = [ordered]@{}
    foreach ($name in $names) {
        $property = $Receipt.PSObject.Properties[$name]
        if ($null -eq $property -or $property.Name -cne $name) { throw 'A required receipt field is missing.' }
        $value = $property.Value
        if ($name -eq 'txId') {
            if ($value -isnot [int] -and $value -isnot [long]) { throw 'The receipt transaction ID must be an integer.' }
            $normalized[$name] = [long]$value
        }
        elseif ($name -eq 'observedAt') {
            # JSON date handling differs across PowerShell versions. Compare the
            # observation instant in UTC, rather than a serializer's spelling.
            if ($value -is [DateTime] -and $value.Kind -ne [DateTimeKind]::Unspecified) {
                $instant = [DateTimeOffset]::new($value)
            }
            else {
                $instant = [DateTimeOffset]::MinValue
                if ($value -isnot [string] -or $value -notmatch '(?:Z|[+-]\d{2}:\d{2})$' -or
                    -not [DateTimeOffset]::TryParse($value, [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::None, [ref]$instant)) {
                    throw 'The receipt observation time must identify a UTC instant.'
                }
            }
            $normalized[$name] = $instant.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        else {
            if ($value -isnot [string]) { throw "The receipt field '$name' must be a string." }
            $normalized[$name] = $value
        }
    }
    return $normalized | ConvertTo-Json -Compress -Depth 4
}

function Test-ReceiptExportReceipts($Receipts) {
    if ($Receipts.Count -eq 0 -or $Receipts.Count -gt 100000) {
        throw 'The receipt count is outside the permitted range.'
    }
    $database = [string]$Receipts[0].database
    if ([string]::IsNullOrWhiteSpace($database)) { throw 'The receipt database is missing.' }
    $previous = 0L
    foreach ($receipt in $Receipts) {
        [void](Get-ReceiptExportComparableJson $receipt)
        if ($receipt.schema -cne 'fleetory.immudb-state-receipt.v1' -or $receipt.database -cne $database) {
            throw 'The receipt set contains an incompatible receipt.'
        }
        if ($receipt.txId -le 0 -or $receipt.txId -lt $previous) {
            throw 'The receipt transaction range is not monotonic.'
        }
        $previous = $receipt.txId
    }
    [void](Test-ImmudbReceiptChain $Receipts)
    return $database
}

function Read-ReceiptExportAnchor([string] $Path) {
    $snapshot = Read-ReceiptExportSnapshot $Path 'Receipt anchor'
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($snapshot.Bytes).TrimStart([char]0xFEFF) }
    catch { throw 'The receipt anchor is not valid UTF-8.' }
    $reader = [IO.StringReader]::new($text)
    $receipts = [Collections.Generic.List[object]]::new()
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                if ($line -notmatch '^\s*\{') { throw 'Expected a receipt object.' }
                $receipts.Add(($line | ConvertFrom-Json -ErrorAction Stop))
            }
            catch { throw 'The receipt anchor contains invalid JSON.' }
        }
    }
    finally { $reader.Dispose() }
    $items = $receipts.ToArray()
    $database = Test-ReceiptExportReceipts $items
    return [pscustomobject]@{
        Bytes = $snapshot.Bytes; Sha256 = $snapshot.Sha256; Receipts = $items; Database = $database
    }
}
