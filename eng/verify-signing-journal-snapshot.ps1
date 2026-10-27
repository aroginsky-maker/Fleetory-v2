#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $SnapshotPath,
    [Parameter(Mandatory)][ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string] $ExpectedSha256,
    [string] $CheckpointPath,
    [ValidatePattern('\A[A-Fa-f0-9]{64}\z')][string] $CheckpointSha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'evidence-file-helpers.ps1')

function Assert-SignerObject($Element, [string[]] $Names) {
    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'Signer evidence requires JSON objects.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in $Element.EnumerateObject()) {
        if (-not $seen.Add($property.Name) -or $Names -cnotcontains $property.Name) {
            throw 'Signer evidence contains duplicate or unknown fields.'
        }
    }
    if ($seen.Count -ne $Names.Count) { throw 'Signer evidence is missing required fields.' }
}

function Get-SignerString($Element) {
    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::String -or [string]::IsNullOrWhiteSpace($Element.GetString())) {
        throw 'Signer evidence requires nonempty strings.'
    }
    return $Element.GetString()
}

function Assert-SignerUtc([string] $Value) {
    $parsed = [DateTimeOffset]::MinValue
    if ($Value -cnotmatch '\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00)\z' -or
        -not [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$parsed) -or $parsed.Offset -ne [TimeSpan]::Zero) {
        throw 'Signer evidence timestamps must be ISO-8601 UTC.'
    }
}

function Read-VerifiedSignerSnapshot([string] $SnapshotPath, [string] $ExpectedSha256) {
    if ([string]::IsNullOrWhiteSpace($SnapshotPath) -or -not [IO.Path]::IsPathFullyQualified($SnapshotPath)) {
        throw 'Signer snapshot path must be absolute.'
    }
    $snapshot = Read-BoundedEvidenceSnapshot ([IO.Path]::GetFullPath($SnapshotPath)) 'Signer snapshot' (8MB + 2)
    if ($snapshot.Sha256 -cne $ExpectedSha256.ToUpperInvariant()) { throw 'Signer snapshot does not match the independently approved SHA-256.' }
    # Native psql can append one LF or CRLF; that suffix belongs to the retained hash.
    $payloadLength = $snapshot.Bytes.Length
    if ($payloadLength -gt 0 -and $snapshot.Bytes[$payloadLength - 1] -eq 10) {
        $payloadLength--
        if ($payloadLength -gt 0 -and $snapshot.Bytes[$payloadLength - 1] -eq 13) { $payloadLength-- }
    }
    if ($payloadLength -gt 8MB) { throw 'Signer JSON payload exceeds 8 MiB.' }
    $document = $null
    try {
        try {
            $text = [Text.UTF8Encoding]::new($false, $true).GetString($snapshot.Bytes)
            $options = [Text.Json.JsonDocumentOptions]::new()
            $options.MaxDepth = 8
            $document = [Text.Json.JsonDocument]::Parse($text, $options)
        }
        catch { throw 'Signer snapshot is not bounded UTF-8 JSON.' }
        $root = $document.RootElement
        Assert-SignerObject $root @('schema', 'observedAt', 'database', 'databaseOperator', 'readOnly', 'snapshotComplete',
            'deliveryVerified', 'executionVerified', 'independentCustodyVerified', 'requests', 'results', 'rejections', 'revocations')
        if ((Get-SignerString ($root.GetProperty('schema'))) -cne 'fleetory.signer-journal-snapshot.v1') {
            throw 'Signer snapshot schema is unsupported.'
        }
        $database = Get-SignerString ($root.GetProperty('database'))
        $operator = Get-SignerString ($root.GetProperty('databaseOperator'))
        $observedAt = Get-SignerString ($root.GetProperty('observedAt'))
        Assert-SignerUtc $observedAt
        foreach ($flag in @('readOnly', 'snapshotComplete')) {
            if ($root.GetProperty($flag).ValueKind -ne [Text.Json.JsonValueKind]::True) { throw 'Signer snapshot confirmations must be JSON true.' }
        }
        foreach ($flag in @('deliveryVerified', 'executionVerified', 'independentCustodyVerified')) {
            if ($root.GetProperty($flag).ValueKind -ne [Text.Json.JsonValueKind]::False) { throw 'Signer snapshot must not assert external delivery or custody.' }
        }
        $columns = [ordered]@{
            requests = @('request_id', 'caller_id', 'client_certificate_sha256', 'target_device_id', 'command_type', 'accepted_at')
            results = @('request_id', 'command_id', 'signing_key_id', 'envelope_sha256', 'recorded_at')
            rejections = @('event_id', 'client_certificate_sha256', 'reason', 'request_id', 'target_device_id', 'recorded_at')
            revocations = @('certificate_sha256', 'event_id', 'incident_reference', 'operator_reference', 'approver_reference',
                'evidence_sha256', 'database_operator', 'revoked_at')
        }
        $counts = [ordered]@{}
        $indexes = [ordered]@{}
        $primaryKeys = @{ requests = 'request_id'; results = 'request_id'; rejections = 'event_id'; revocations = 'certificate_sha256' }
        foreach ($table in $columns.Keys) {
            $rows = $root.GetProperty($table)
            if ($rows.ValueKind -ne [Text.Json.JsonValueKind]::Array -or $rows.GetArrayLength() -gt 5000) {
                throw 'Signer snapshot arrays exceed the schema limits.'
            }
            $counts[$table] = $rows.GetArrayLength()
            $index = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
            foreach ($row in $rows.EnumerateArray()) {
                Assert-SignerObject $row $columns[$table]
                $normalized = [ordered]@{}
                foreach ($field in $columns[$table]) {
                    $value = $row.GetProperty($field)
                    if ($table -ceq 'rejections' -and $field -in @('request_id', 'target_device_id') -and
                        $value.ValueKind -eq [Text.Json.JsonValueKind]::Null) {
                        $normalized[$field] = $null
                        continue
                    }
                    $string = Get-SignerString $value
                    if ($field.EndsWith('_sha256', [StringComparison]::Ordinal) -and $string -cnotmatch '\A[A-F0-9]{64}\z') {
                        throw 'Signer evidence requires uppercase SHA-256 fields.'
                    }
                    if ($field -in @('request_id', 'target_device_id', 'command_id', 'event_id')) {
                        $id = [Guid]::Empty
                        if ($string.Length -ne 36 -or -not [Guid]::TryParseExact($string, 'D', [ref]$id)) { throw 'Signer evidence requires canonical UUID fields.' }
                        $string = $id.ToString('D')
                    }
                    if ($field.EndsWith('_at', [StringComparison]::Ordinal)) {
                        Assert-SignerUtc $string
                        $string = [DateTimeOffset]::Parse($string, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime.ToString('O')
                    }
                    $normalized[$field] = $string
                }
                $canonical = $normalized | ConvertTo-Json -Compress -Depth 3
                $fingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical)))
                if (-not $index.TryAdd($normalized[$primaryKeys[$table]], $fingerprint)) { throw 'Signer evidence contains duplicate row identities.' }
            }
            $indexes[$table] = $index
        }
        return [pscustomobject]@{ Sha256 = $snapshot.Sha256; Bytes = $snapshot.Bytes.Length; Database = $database
            Operator = $operator; ObservedAt = $observedAt; Counts = $counts; Indexes = $indexes }
    }
    finally { if ($null -ne $document) { $document.Dispose() } }
}

if ($PSBoundParameters.ContainsKey('CheckpointPath') -ne $PSBoundParameters.ContainsKey('CheckpointSha256')) {
    throw 'Signer checkpoint path and independently approved SHA-256 must be supplied together.'
}
$current = Read-VerifiedSignerSnapshot $SnapshotPath $ExpectedSha256
$checkpointVerified = $false
$checkpointDigest = $null
if ($PSBoundParameters.ContainsKey('CheckpointPath')) {
    $checkpoint = Read-VerifiedSignerSnapshot $CheckpointPath $CheckpointSha256
    if ($current.Database -cne $checkpoint.Database -or
        [DateTimeOffset]::Parse($current.ObservedAt, [Globalization.CultureInfo]::InvariantCulture) -lt
        [DateTimeOffset]::Parse($checkpoint.ObservedAt, [Globalization.CultureInfo]::InvariantCulture)) {
        throw 'Signer snapshot database or observation time conflicts with the approved checkpoint.'
    }
    foreach ($table in $checkpoint.Indexes.Keys) {
        foreach ($row in $checkpoint.Indexes[$table].GetEnumerator()) {
            $candidate = $null
            if (-not $current.Indexes[$table].TryGetValue($row.Key, [ref]$candidate) -or $candidate -cne $row.Value) {
                throw 'Signer snapshot lost or changed a row from the approved checkpoint.'
            }
        }
    }
    $checkpointDigest = $checkpoint.Sha256
    $checkpointVerified = $true
}
[ordered]@{
    schema = 'fleetory.signer-snapshot-verification.v1'
    snapshotSha256 = $current.Sha256
    snapshotBytes = $current.Bytes
    database = $current.Database
    databaseOperator = $current.Operator
    observedAt = $current.ObservedAt
    rowCounts = $current.Counts
    approvedDigestMatched = $true
    checkpointVerified = $checkpointVerified
    checkpointSha256 = $checkpointDigest
    deliveryVerified = $false
    executionVerified = $false
    independentCustodyVerified = $false
} | ConvertTo-Json -Compress -Depth 4
