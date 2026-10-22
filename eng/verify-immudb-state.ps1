# Fleetory immudb signed-state receipt verifier.
# This script is an operational verifier; it never writes to immudb.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri] $Address,
    [Parameter(Mandatory)][string] $PublicKeyPath,
    [Parameter(Mandatory)][string] $AnchorPath,
    [string] $ExpectedDatabase = 'defaultdb',
    [string] $BearerToken
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function ConvertFrom-Base64Strict([string] $Value, [string] $Name) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name is missing."
    }
    try {
        $bytes = [Convert]::FromBase64String($Value)
    }
    catch {
        throw "$Name is not valid base64."
    }
    if ($bytes.Length -eq 0) { throw "$Name is empty." }
    return $bytes
}

function Get-ImmudbState([uri] $Origin, [string] $Token) {
    if ($Origin.Scheme -ne 'https') {
        throw 'immudb state verification requires HTTPS.'
    }
    $uri = [uri]::new($Origin, 'api/db/state')
    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $headers.Authorization = "Bearer $Token"
    }
    try {
        return Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 20
    }
    catch {
        throw 'Could not read the immudb signed state.'
    }
}

function Invoke-ImmudbSignatureVerification(
    [byte[]] $HashBytes,
    [byte[]] $SignatureBytes,
    [string] $PublicKeyPath) {
    if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
        throw 'The immudb public signing key is missing.'
    }
    $fullKeyPath = [IO.Path]::GetFullPath($PublicKeyPath)
    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('fleetory-immudb-state-' +
        [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    try {
        $hashPath = Join-Path $tempRoot 'tx-hash.bin'
        $signaturePath = Join-Path $tempRoot 'state-signature.bin'
        [IO.File]::WriteAllBytes($hashPath, $HashBytes)
        [IO.File]::WriteAllBytes($signaturePath, $SignatureBytes)
        & openssl dgst -sha256 -verify $fullKeyPath -signature $signaturePath $hashPath 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'The immudb state signature is invalid.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}

function Get-PinnedImmudbPublicKeyBytes([string] $PublicKeyPath) {
    if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
        throw 'The immudb public signing key is missing.'
    }
    $pem = [IO.File]::ReadAllText([IO.Path]::GetFullPath($PublicKeyPath))
    $match = [regex]::Match($pem,
        '-----BEGIN PUBLIC KEY-----(?<body>[A-Za-z0-9+/=\r\n]+)-----END PUBLIC KEY-----')
    if (-not $match.Success) { throw 'The immudb public signing key is not a PUBLIC KEY PEM.' }
    try { return [Convert]::FromBase64String(($match.Groups['body'].Value -replace '\s', '')) }
    catch { throw 'The immudb public signing key PEM is invalid.' }
}

function New-ImmudbStateReceipt($State, [string] $ExpectedDatabase, [string] $PublicKeyPath) {
    if ($null -eq $State -or [string]::IsNullOrWhiteSpace([string]$State.db)) {
        throw 'immudb state does not contain a database name.'
    }
    if ([string]$State.db -cne $ExpectedDatabase) {
        throw "Unexpected immudb database '$($State.db)'."
    }
    $txId = 0L
    if (-not [long]::TryParse([string]$State.txId,
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$txId) -or $txId -le 0) {
        throw 'immudb state transaction ID is invalid.'
    }
    $hashBytes = ConvertFrom-Base64Strict ([string]$State.txHash) 'immudb state transaction hash'
    if ($hashBytes.Length -ne 32) { throw 'immudb transaction hash must be 32 bytes.' }
    $signature = $State.signature
    if ($null -eq $signature) { throw 'immudb state signature is missing.' }
    $signatureBytes = ConvertFrom-Base64Strict ([string]$signature.signature) 'immudb state signature'
    $serverPublicKey = if ($signature.publicKey) {
        ConvertFrom-Base64Strict ([string]$signature.publicKey) 'immudb state public key'
    }
    else { $null }
    if ($null -ne $serverPublicKey) {
        $pinnedPublicKey = Get-PinnedImmudbPublicKeyBytes $PublicKeyPath
        $expectedPublicKeyHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($pinnedPublicKey))
        $serverPublicKeyHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($serverPublicKey))
        if ($serverPublicKeyHash -cne $expectedPublicKeyHash) {
            throw 'immudb state public key does not match the pinned key.'
        }
    }
    Invoke-ImmudbSignatureVerification $hashBytes $signatureBytes $PublicKeyPath
    [ordered]@{
        schema = 'fleetory.immudb-state-receipt.v1'
        database = [string]$State.db
        txId = $txId
        txHash = [Convert]::ToBase64String($hashBytes)
        signature = [Convert]::ToBase64String($signatureBytes)
        publicKeySha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData((Get-PinnedImmudbPublicKeyBytes $PublicKeyPath)))
        observedAt = [DateTimeOffset]::UtcNow.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    }
}

function Get-ExistingImmudbReceipts([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    if ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The immudb receipt anchor cannot be a symbolic link.'
    }
    $receipts = @()
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $receipts += ($line | ConvertFrom-Json) }
        catch { throw 'The immudb receipt anchor contains invalid JSON.' }
    }
    return $receipts
}

function Write-ImmudbStateReceipt($Receipt, [string] $AnchorPath) {
    if (-not [IO.Path]::IsPathFullyQualified($AnchorPath)) {
        throw 'The immudb receipt anchor path must be absolute.'
    }
    $fullPath = [IO.Path]::GetFullPath($AnchorPath)
    $parent = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $existing = @(Get-ExistingImmudbReceipts $fullPath)
    $previousTx = 0L
    foreach ($candidate in $existing) {
        if ([string]$candidate.schema -cne 'fleetory.immudb-state-receipt.v1' -or
            [string]$candidate.database -cne [string]$Receipt.database) {
            throw 'The immudb receipt anchor contains an incompatible receipt.'
        }
        $candidateTx = 0L
        if (-not [long]::TryParse([string]$candidate.txId,
                [Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture, [ref]$candidateTx) -or
            $candidateTx -le 0 -or $candidateTx -lt $previousTx -or
            [string]::IsNullOrWhiteSpace([string]$candidate.txHash)) {
            throw 'The immudb receipt anchor is not monotonic.'
        }
        $previousTx = $candidateTx
    }
    if ($existing.Count -gt 0) {
        $last = $existing[-1]
        $lastTx = [long]$last.txId
        if ($lastTx -gt [long]$Receipt.txId) {
            throw 'The immudb state moved backwards relative to the receipt anchor.'
        }
        if ($lastTx -eq [long]$Receipt.txId) {
            if ([string]$last.txHash -ne [string]$Receipt.txHash) {
                throw 'The immudb state conflicts with the receipt anchor.'
            }
            return $false
        }
    }
    $line = $Receipt | ConvertTo-Json -Compress -Depth 4
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::AppendAllText($fullPath, $line + [Environment]::NewLine, $utf8)
    return $true
}

function Invoke-ImmudbStateVerification(
    [uri] $Origin,
    [string] $PublicKeyPath,
    [string] $AnchorPath,
    [string] $ExpectedDatabase,
    [string] $Token) {
    $state = Get-ImmudbState $Origin $Token
    $receipt = New-ImmudbStateReceipt $state $ExpectedDatabase $PublicKeyPath
    [void](Write-ImmudbStateReceipt $receipt $AnchorPath)
    return $receipt
}

if ($MyInvocation.InvocationName -ne '.') {
    $receipt = Invoke-ImmudbStateVerification $Address $PublicKeyPath $AnchorPath `
        $ExpectedDatabase $BearerToken
    $receipt | ConvertTo-Json -Compress -Depth 4
}
