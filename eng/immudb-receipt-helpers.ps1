# Shared helpers for immudb receipt export operations.

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
