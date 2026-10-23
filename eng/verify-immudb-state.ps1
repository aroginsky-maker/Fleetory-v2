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

function Get-ImmudbSha256([byte[]] $Bytes) {
    if ($null -eq $Bytes) { throw 'The SHA-256 input is missing.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return $sha.ComputeHash($Bytes) }
    finally { $sha.Dispose() }
}

function ConvertTo-ImmudbUpperHex([byte[]] $Bytes) {
    if ($null -eq $Bytes) { throw 'The hexadecimal input is missing.' }
    $builder = [Text.StringBuilder]::new($Bytes.Length * 2)
    foreach ($byte in $Bytes) {
        [void]$builder.Append($byte.ToString('X2',
            [Globalization.CultureInfo]::InvariantCulture))
    }
    return $builder.ToString()
}

function Test-ImmudbAbsolutePath([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return $Path -match '^(?:[A-Za-z]:[\\/]|\\\\|/)'
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

function New-ImmudbStateSigningPayload(
    [string] $Database,
    [long] $TxId,
    [byte[]] $HashBytes) {
    if ([string]::IsNullOrEmpty($Database)) { throw 'The immudb database name is empty.' }
    if ($TxId -le 0) { throw 'The immudb transaction ID is invalid.' }
    if ($HashBytes.Length -ne 32) { throw 'The immudb transaction hash must be 32 bytes.' }
    $databaseBytes = [Text.UTF8Encoding]::new($false).GetBytes($Database)
    if ($databaseBytes.Length -gt [uint32]::MaxValue) { throw 'The immudb database name is too long.' }
    $payload = New-Object byte[] (4 + $databaseBytes.Length + 8 + $HashBytes.Length)
    $offset = 0
    $lengthBytes = [BitConverter]::GetBytes([uint32]$databaseBytes.Length)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lengthBytes) }
    [Buffer]::BlockCopy($lengthBytes, 0, $payload, $offset, 4)
    $offset += 4
    [Buffer]::BlockCopy($databaseBytes, 0, $payload, $offset, $databaseBytes.Length)
    $offset += $databaseBytes.Length
    $txBytes = [BitConverter]::GetBytes([uint64]$TxId)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($txBytes) }
    [Buffer]::BlockCopy($txBytes, 0, $payload, $offset, 8)
    [Buffer]::BlockCopy($HashBytes, 0, $payload, $offset + 8, $HashBytes.Length)
    return $payload
}

function ConvertTo-ImmudbPublicKeyPoint([byte[]] $PublicKeyBytes) {
    if ($PublicKeyBytes.Length -eq 65 -and $PublicKeyBytes[0] -eq 4) {
        return $PublicKeyBytes
    }
    # The operator key is stored as a standard PUBLIC KEY PEM (X.509 SPKI).
    # The P-256 uncompressed point is the final 65 bytes of that DER structure.
    if ($PublicKeyBytes.Length -ge 65) {
        $point = [byte[]]$PublicKeyBytes[($PublicKeyBytes.Length - 65)..($PublicKeyBytes.Length - 1)]
        if ($point[0] -eq 4) { return $point }
    }
    throw 'The immudb public signing key must be a P-256 public key.'
}

function Read-ImmudbDerInteger([byte[]] $Signature, [int] $Offset) {
    if ($Offset -lt 0 -or $Offset + 2 -gt $Signature.Length -or
        $Signature[$Offset] -ne 0x02) {
        throw 'The immudb state signature is not a valid DER sequence.'
    }
    $length = [int]$Signature[$Offset + 1]
    if (($length -band 0x80) -ne 0 -or $length -le 0 -or
        $Offset + 2 + $length -gt $Signature.Length) {
        throw 'The immudb state signature integer length is invalid.'
    }
    $start = $Offset + 2
    if (($Signature[$start] -band 0x80) -ne 0) {
        throw 'The immudb state signature integer is negative.'
    }
    if ($length -gt 1 -and $Signature[$start] -eq 0 -and
        ($Signature[$start + 1] -band 0x80) -eq 0) {
        throw 'The immudb state signature integer is not minimally encoded.'
    }
    if ($Signature[$start] -eq 0) {
        $start++
        $length--
    }
    if ($length -le 0 -or $length -gt 32) {
        throw 'The immudb state signature integer is outside the P-256 range.'
    }
    return [pscustomobject]@{
        Bytes = [byte[]]$Signature[$start..($start + $length - 1)]
        NextOffset = $Offset + 2 + [int]$Signature[$Offset + 1]
    }
}

function ConvertFrom-ImmudbDerSignature([byte[]] $Signature) {
    if ($null -eq $Signature -or $Signature.Length -lt 8 -or
        $Signature[0] -ne 0x30) {
        throw 'The immudb state signature is not a valid DER sequence.'
    }
    $sequenceLength = [int]$Signature[1]
    if (($sequenceLength -band 0x80) -ne 0 -or
        $sequenceLength -ne $Signature.Length - 2) {
        throw 'The immudb state signature sequence length is invalid.'
    }
    $r = Read-ImmudbDerInteger $Signature 2
    $s = Read-ImmudbDerInteger $Signature $r.NextOffset
    if ($s.NextOffset -ne $Signature.Length) {
        throw 'The immudb state signature contains trailing data.'
    }
    $p1363 = New-Object byte[] 64
    [Buffer]::BlockCopy($r.Bytes, 0, $p1363, 32 - $r.Bytes.Length, $r.Bytes.Length)
    [Buffer]::BlockCopy($s.Bytes, 0, $p1363, 64 - $s.Bytes.Length, $s.Bytes.Length)
    return $p1363
}

function Invoke-ImmudbSignatureVerification(
    [byte[]] $PayloadBytes,
    [byte[]] $SignatureBytes,
    [byte[]] $PublicKeyPoint) {
    if ($null -eq $PayloadBytes -or $PayloadBytes.Length -eq 0) {
        throw 'The immudb signed payload is empty.'
    }
    $point = ConvertTo-ImmudbPublicKeyPoint $PublicKeyPoint
    if ($SignatureBytes.Length -eq 0) { throw 'The immudb state signature is empty.' }
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        $parameters = New-Object Security.Cryptography.ECParameters
        $parameters.Curve = [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
        $ecPoint = New-Object Security.Cryptography.ECPoint
        $ecPoint.X = [byte[]]$point[1..32]
        $ecPoint.Y = [byte[]]$point[33..64]
        $parameters.Q = $ecPoint
        $ecdsa.ImportParameters($parameters)
        $digest = Get-ImmudbSha256 $PayloadBytes
        $signatureP1363 = ConvertFrom-ImmudbDerSignature $SignatureBytes
        if (-not $ecdsa.VerifyHash($digest, $signatureP1363)) {
            throw 'The immudb state signature is invalid.'
        }
    }
    finally { $ecdsa.Dispose() }
}

function Get-PinnedImmudbPublicKeyBytes([string] $PublicKeyPath) {
    if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
        throw 'The immudb public signing key is missing.'
    }
    $pem = [IO.File]::ReadAllText([IO.Path]::GetFullPath($PublicKeyPath))
    $match = [regex]::Match($pem,
        '-----BEGIN PUBLIC KEY-----(?<body>[A-Za-z0-9+/=\r\n]+)-----END PUBLIC KEY-----')
    if (-not $match.Success) { throw 'The immudb public signing key is not a PUBLIC KEY PEM.' }
    try {
        return ConvertTo-ImmudbPublicKeyPoint ([Convert]::FromBase64String(
            ($match.Groups['body'].Value -replace '\s', '')))
    }
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
    $pinnedPublicKey = Get-PinnedImmudbPublicKeyBytes $PublicKeyPath
    $serverPublicKey = if ($signature.publicKey) {
        ConvertTo-ImmudbPublicKeyPoint (ConvertFrom-Base64Strict (
            [string]$signature.publicKey) 'immudb state public key')
    }
    else { $pinnedPublicKey }
    $keysMatch = $serverPublicKey.Length -eq $pinnedPublicKey.Length
    if ($keysMatch) {
        for ($index = 0; $index -lt $pinnedPublicKey.Length; $index++) {
            if ($serverPublicKey[$index] -ne $pinnedPublicKey[$index]) {
                $keysMatch = $false
                break
            }
        }
    }
    if (-not $keysMatch) {
        throw 'immudb state public key does not match the pinned key.'
    }
    $payload = New-ImmudbStateSigningPayload ([string]$State.db) $txId $hashBytes
    Invoke-ImmudbSignatureVerification $payload $signatureBytes $pinnedPublicKey
    [ordered]@{
        schema = 'fleetory.immudb-state-receipt.v1'
        database = [string]$State.db
        txId = $txId
        txHash = [Convert]::ToBase64String($hashBytes)
        signature = [Convert]::ToBase64String($signatureBytes)
        publicKeySha256 = ConvertTo-ImmudbUpperHex (Get-ImmudbSha256 $pinnedPublicKey)
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
    if (-not (Test-ImmudbAbsolutePath $AnchorPath)) {
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
