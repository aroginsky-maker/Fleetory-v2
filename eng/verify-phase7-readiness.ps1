# Fleetory PHASE 7 deployment-readiness record verifier.
# This operation is read-only and does not contact external systems.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $RecordPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'evidence-file-helpers.ps1')

function Test-ReadinessAbsolutePath([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path -match '^(?:[A-Za-z]:[\\/]|\\\\|/)') { return $true }
    return $false
}

function Assert-ReadinessJsonProperties([string] $Json) {
    # The framework reader preserves members before ConvertFrom-Json can collapse
    # duplicates. It is available on Windows PowerShell 5.1 and PowerShell 7.
    Add-Type -AssemblyName System.Runtime.Serialization
    $quotas = [Xml.XmlDictionaryReaderQuotas]::new()
    $quotas.MaxDepth = 16
    $quotas.MaxStringContentLength = 64KB
    $quotas.MaxArrayLength = 64KB
    $quotas.MaxNameTableCharCount = 64KB
    $reader = [Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader(
        [Text.Encoding]::UTF8.GetBytes($Json), $quotas)
    $objects = @{}
    try {
        while ($reader.Read()) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                if ($null -ne $reader.GetAttribute('__type')) { throw 'JSON serializer metadata is unsupported.' }
                $parentDepth = $reader.Depth - 1
                if ($objects.ContainsKey($parentDepth)) {
                    $name = $reader.GetAttribute('item')
                    if ($null -eq $name) { $name = $reader.LocalName }
                    if (-not $objects[$parentDepth].Add($name)) { throw 'Readiness JSON fields must be unique.' }
                }
                if ($reader.GetAttribute('type') -eq 'object') {
                    $objects[$reader.Depth] = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                }
                if ($reader.IsEmptyElement) { $objects.Remove($reader.Depth) }
            }
            elseif ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement) { $objects.Remove($reader.Depth) }
        }
    }
    finally { $reader.Close() }
}

function Read-ReadinessRecord([string] $Path) {
    if (-not (Test-ReadinessAbsolutePath $Path)) {
        throw 'The readiness record path must be absolute.'
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $snapshot = Read-BoundedEvidenceSnapshot $fullPath 'The readiness record' 64KB
    $bytes = $snapshot.Bytes
    try {
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes).TrimStart([char]0xFEFF)
        if ($json -notmatch '^\s*\{') { throw 'Expected a JSON object.' }
        Assert-ReadinessJsonProperties $json
        $options = @{ InputObject = $json; ErrorAction = 'Stop' }
        # Preserve timestamp lexemes so automatic JSON date conversion cannot
        # normalize a non-UTC or non-ISO input before policy validation.
        if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
            $options.DateKind = 'String'
        }
        $record = ConvertFrom-Json @options
        if (-not $options.ContainsKey('DateKind') -and $PSVersionTable.PSVersion.Major -ge 6) {
            # Older PowerShell Core bundles Json.NET but has no -DateKind.
            $textReader = [IO.StringReader]::new($json)
            $reader = [Newtonsoft.Json.JsonTextReader]::new($textReader)
            try {
                $reader.DateParseHandling = [Newtonsoft.Json.DateParseHandling]::None
                $tokens = [Newtonsoft.Json.Linq.JObject]::Load($reader)
                foreach ($name in @('approvedAt', 'validatedAt', 'expiresAt')) {
                    $token = $tokens.GetValue($name, [StringComparison]::OrdinalIgnoreCase)
                    if ($null -ne $token -and $token.Type -eq [Newtonsoft.Json.Linq.JTokenType]::String) {
                        $record.PSObject.Properties[$name].Value = [string]$token.Value
                    }
                }
            }
            finally { $reader.Close(); $textReader.Dispose() }
        }
    }
    catch { throw 'The readiness record is not an unambiguous UTF-8 JSON object within the nesting limit.' }
    return [pscustomobject]@{ Record = $record; Sha256 = $snapshot.Sha256 }
}

function Get-ReadinessProperty($Object, [string] $Name) {
    if ($Object -isnot [pscustomobject]) { throw 'Readiness fields must belong to a JSON object.' }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "The readiness record field '$Name' is required."
    }
    return $property
}

function Get-RequiredString($Object, [string] $Name) {
    $value = (Get-ReadinessProperty $Object $Name).Value
    if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
        throw "The readiness record field '$Name' must be a non-empty string."
    }
    return $value.Trim()
}

function Get-RequiredObject($Object, [string] $Name) {
    $value = (Get-ReadinessProperty $Object $Name).Value
    if ($value -isnot [pscustomobject]) { throw "The readiness field '$Name' must be a JSON object." }
    return $value
}

function Assert-ReadinessConfirmation($Object, [string] $Name) {
    $value = (Get-ReadinessProperty $Object $Name).Value
    if ($value -isnot [bool] -or -not $value) {
        throw "The readiness confirmation '$Name' must be JSON true."
    }
}

function Get-RequiredActor($Object, [string] $Name) {
    $value = Get-RequiredString $Object $Name
    if ($value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:@/\\-]{0,255}$') {
        throw 'Readiness identities must be stable ASCII identifiers, not display names.'
    }
    return $value
}

function Get-RequiredUtc($Object, [string] $Name) {
    $value = (Get-ReadinessProperty $Object $Name).Value
    $parsed = [DateTimeOffset]::MinValue
    $formats = [string[]]@("yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'")
    if ($value -isnot [string] -or
        $value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$' -or
        -not [DateTimeOffset]::TryParseExact($value, $formats,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        throw "$Name must be an ISO-8601 UTC timestamp ending in Z."
    }
    return $parsed
}

function Get-RequiredReadinessUri($Object, [string] $Name, [string[]] $Schemes) {
    $text = Get-RequiredString $Object $Name
    $uri = $null
    if (-not [uri]::TryCreate($text, [UriKind]::Absolute, [ref]$uri) -or
        $Schemes -notcontains $uri.Scheme -or [string]::IsNullOrEmpty($uri.Host) -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment)) {
        throw "The readiness URI '$Name' must be absolute and contain no credentials, query or fragment."
    }
    return $uri
}

function Get-ReadinessCoverage($Object) {
    $value = (Get-ReadinessProperty $Object 'coveragePercent').Value
    $coverage = 0.0
    $numeric = $value -is [int] -or $value -is [long] -or
        $value -is [double] -or $value -is [decimal]
    if ((-not $numeric -and $value -isnot [string]) -or
        -not [double]::TryParse([Convert]::ToString($value, [Globalization.CultureInfo]::InvariantCulture),
            [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture,
            [ref]$coverage) -or [double]::IsNaN($coverage) -or [double]::IsInfinity($coverage) -or
        $coverage -lt 80.0 -or $coverage -gt 100.0) {
        throw 'The CI coverage percentage must be a finite number between 80 and 100.'
    }
    return $coverage
}

function Test-Phase7Readiness($Record, [DateTimeOffset] $Now = [DateTimeOffset]::UtcNow) {
    if ((Get-RequiredString $Record 'schema') -cne 'fleetory.phase7-readiness.v1') {
        throw 'The readiness record schema is invalid.'
    }
    $environment = Get-RequiredString $Record 'environment'
    $changeReference = Get-RequiredString $Record 'changeReference'
    $requestedBy = Get-RequiredActor $Record 'requestedBy'
    $approvedBy = Get-RequiredActor $Record 'approvedBy'
    $deployedBy = Get-RequiredActor $Record 'deployedBy'
    if ([string]::Equals($requestedBy, $approvedBy, [StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($approvedBy, $deployedBy, [StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($requestedBy, $deployedBy, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Requester, approver and operator must be distinct identities.'
    }
    $approvedAt = Get-RequiredUtc $Record 'approvedAt'
    $validatedAt = Get-RequiredUtc $Record 'validatedAt'
    $expiresAt = Get-RequiredUtc $Record 'expiresAt'
    if ($approvedAt -gt $validatedAt -or $validatedAt -ge $expiresAt) {
        throw 'Readiness record timestamps are not monotonic.'
    }
    $checkedAt = $Now.ToUniversalTime()
    if ($validatedAt -gt $checkedAt -or $expiresAt -le $checkedAt) {
        throw 'The readiness record is not currently valid.'
    }

    $controlNames = @('caPki', 'signer', 'immudbTls', 'wormAnchor', 'recovery')
    $controls = Get-RequiredObject $Record 'controls'
    foreach ($name in $controlNames) {
        Assert-ReadinessConfirmation $controls $name
    }

    $ci = Get-RequiredObject $Record 'ci'
    $runUrl = Get-RequiredString $ci 'runUrl'
    $runUri = Get-RequiredReadinessUri $ci 'runUrl' @('https')
    if ($runUri.Host -ne 'github.com' -or -not $runUri.IsDefaultPort -or
        $runUri.AbsolutePath -cnotmatch '^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[1-9][0-9]*$') {
        throw 'The CI run URL must identify a GitHub Actions run.'
    }
    if ((Get-RequiredString $ci 'sonarQualityGate') -cne 'PASS') {
        throw 'The Sonar Quality Gate is not PASS.'
    }
    $coverage = Get-ReadinessCoverage $ci

    $evidence = (Get-ReadinessProperty $Record 'evidence').Value
    if ($evidence -isnot [array] -or $evidence.Count -eq 0) {
        throw 'A non-empty evidence array is required.'
    }
    $coveredControls = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in $evidence) {
        $kind = Get-RequiredString $item 'kind'
        if ($controlNames -cnotcontains $kind) { throw 'Evidence kind must name a required readiness control.' }
        [void]$coveredControls.Add($kind)
        $hash = Get-RequiredString $item 'sha256'
        if ($hash -notmatch '^[0-9A-Fa-f]{64}$') {
            throw 'Evidence SHA-256 must contain exactly 64 hexadecimal characters.'
        }
        $reference = Get-RequiredReadinessUri $item 'reference' @('https', 'worm', 'siem', 's3', 'gs', 'azblob')
        if ($reference.AbsolutePath -eq '/') { throw 'Evidence reference must identify an object.' }
    }
    foreach ($name in $controlNames) {
        if (-not $coveredControls.Contains($name)) { throw "Evidence for '$name' is required." }
    }

    $rollback = Get-RequiredObject $Record 'rollback'
    if ((Get-RequiredString $rollback 'plan').Length -lt 16) {
        throw 'The rollback plan must be present and validated.'
    }
    Assert-ReadinessConfirmation $rollback 'validated'

    return [ordered]@{
        schema = 'fleetory.phase7-readiness-verification.v1'
        environment = $environment
        changeReference = $changeReference
        requestedBy = $requestedBy
        approvedBy = $approvedBy
        deployedBy = $deployedBy
        checkedAt = $checkedAt.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        expiresAt = $expiresAt.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        evidenceCount = $evidence.Count
        ciRunUrl = $runUrl
        coveragePercent = $coverage
        sonarQualityGate = 'PASS'
        verified = $true
    }
}

$document = Read-ReadinessRecord $RecordPath
$verification = Test-Phase7Readiness $document.Record
$verification['recordSha256'] = $document.Sha256
$verification | ConvertTo-Json -Compress -Depth 5
