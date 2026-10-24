# Fleetory immudb restore acceptance verifier.
# Backup and restore are performed by a separately privileged immudb operator.
# This script only reads the restored endpoint with a read-only bearer token.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri] $Address,
    [Parameter(Mandatory)][string] $PublicKeyPath,
    [Parameter(Mandatory)][string] $AnchorPath,
    [Parameter(Mandatory)][string] $KnownEventId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedValueSha256,
    [string] $ExpectedDatabase = 'defaultdb',
    [long] $ExpectedRevision = 1,
    [string] $ReadOnlyBearerToken = $env:FLEETORY_IMMUDB_RESTORE_READ_TOKEN
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($ReadOnlyBearerToken)) {
    throw 'The read-only immudb bearer token must be supplied through FLEETORY_IMMUDB_RESTORE_READ_TOKEN or the parameter.'
}

# Import the signed-state verifier without running its entry point.
. (Join-Path $PSScriptRoot 'verify-immudb-state.ps1') `
    -Address $Address -PublicKeyPath $PublicKeyPath -AnchorPath $AnchorPath `
    -ExpectedDatabase $ExpectedDatabase -BearerToken $ReadOnlyBearerToken

function ConvertTo-ImmudbRestoreEventKey([Guid] $EventId) {
    if ($EventId -eq [Guid]::Empty) { throw 'The known audit EventId is empty.' }
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
        'fleetory/audit/v1/' + $EventId.ToString('N')))
}

function ConvertFrom-ImmudbRestoreBase64Strict([string] $Value, [string] $Name) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Name is missing." }
    try { $bytes = [Convert]::FromBase64String($Value) }
    catch { throw "$Name is not valid base64." }
    if ($bytes.Length -eq 0) { throw "$Name is empty." }
    return $bytes
}

function Get-ImmudbAuditReadback([uri] $Origin, [string] $Token, [string] $Key) {
    if ($Origin.Scheme -ne 'https') {
        throw 'immudb restore acceptance requires HTTPS.'
    }
    if ([string]::IsNullOrWhiteSpace($Token)) {
        throw 'The read-only immudb bearer token is missing.'
    }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(20)
    try {
        $uri = [uri]::new($Origin, 'api/db/get/' + [uri]::EscapeDataString($Key))
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $uri)
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new(
            'Bearer', $Token)
        try {
            $response = $client.SendAsync($request,
                [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            if ([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -lt 400) {
                throw 'The immudb restore endpoint returned a redirect.'
            }
            if (-not $response.IsSuccessStatusCode) {
                throw 'The restored immudb audit key could not be read.'
            }
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ([Text.Encoding]::UTF8.GetByteCount($body) -gt 16KB) {
                throw 'The restored immudb audit response is too large.'
            }
            try { return $body | ConvertFrom-Json }
            catch { throw 'The restored immudb audit response is invalid JSON.' }
        }
        finally { $request.Dispose() }
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function Test-ImmudbRestoredEvent(
    $Response,
    [Guid] $EventId,
    [long] $ExpectedRevision,
    [string] $ExpectedValueSha256) {
    if ($null -eq $Response) { throw 'The restored immudb audit response is empty.' }
    if ($ExpectedRevision -le 0) { throw 'The expected immudb revision is invalid.' }
    $expectedKey = ConvertTo-ImmudbRestoreEventKey $EventId
    if ([string]$Response.key -cne $expectedKey) {
        throw 'The restored immudb audit key does not match the known EventId.'
    }
    $revision = 0L
    if (-not [long]::TryParse([string]$Response.revision,
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$revision) -or
        $revision -ne $ExpectedRevision) {
        throw 'The restored immudb audit key has an unexpected revision.'
    }
    $valueBytes = ConvertFrom-ImmudbRestoreBase64Strict ([string]$Response.value) `
        'restored immudb audit value'
    $actualHash = ConvertTo-ImmudbUpperHex (Get-ImmudbSha256 $valueBytes)
    if ($actualHash -ine $ExpectedValueSha256) {
        throw 'The restored immudb audit value hash does not match the acceptance record.'
    }
    return [ordered]@{
        eventId = $EventId.ToString('N')
        revision = $revision
        valueSha256 = $actualHash
    }
}

function Invoke-ImmudbRestoreAcceptance(
    [uri] $Origin,
    [string] $PublicKeyPath,
    [string] $AnchorPath,
    [string] $ExpectedDatabase,
    [Guid] $EventId,
    [long] $ExpectedRevision,
    [string] $ExpectedValueSha256,
    [string] $ReadOnlyToken) {
    $receipt = Invoke-ImmudbStateVerification $Origin $PublicKeyPath $AnchorPath `
        $ExpectedDatabase $ReadOnlyToken
    $key = ConvertTo-ImmudbRestoreEventKey $EventId
    $response = Get-ImmudbAuditReadback $Origin $ReadOnlyToken $key
    $event = Test-ImmudbRestoredEvent $response $EventId $ExpectedRevision `
        $ExpectedValueSha256
    return [ordered]@{
        schema = 'fleetory.immudb-restore-acceptance.v1'
        database = $ExpectedDatabase
        receiptTxId = [long]$receipt.txId
        knownEventId = $event.eventId
        revision = $event.revision
        valueSha256 = $event.valueSha256
        acceptedAt = [DateTimeOffset]::UtcNow.ToString('O',
            [Globalization.CultureInfo]::InvariantCulture)
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $eventId = [Guid]::Empty
    if (-not [Guid]::TryParse($KnownEventId, [ref]$eventId) -or
        $eventId -eq [Guid]::Empty) {
        throw 'The known audit EventId is invalid.'
    }
    if ($ExpectedRevision -le 0) { throw 'The expected immudb revision is invalid.' }
    $result = Invoke-ImmudbRestoreAcceptance $Address $PublicKeyPath $AnchorPath `
        $ExpectedDatabase $eventId $ExpectedRevision $ExpectedValueSha256 `
        $ReadOnlyBearerToken
    $result | ConvertTo-Json -Compress -Depth 4
}
