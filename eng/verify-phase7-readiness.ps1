# Fleetory PHASE 7 deployment-readiness record verifier.
# This operation is read-only and does not contact external systems.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $RecordPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-ReadinessAbsolutePath([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path -match '^(?:[A-Za-z]:[\\/]|\\\\|/)') { return $true }
    return $false
}

function Read-ReadinessRecord([string] $Path) {
    if (-not (Test-ReadinessAbsolutePath $Path)) {
        throw 'The readiness record path must be absolute.'
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw 'The readiness record does not exist.'
    }
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The readiness record cannot be a symbolic link.'
    }
    if ($item.Length -le 0 -or $item.Length -gt 64KB) {
        throw 'The readiness record size is outside the permitted range.'
    }
    try {
        return ([Text.UTF8Encoding]::new($false, $true).GetString(
            [IO.File]::ReadAllBytes($fullPath)) | ConvertFrom-Json)
    }
    catch { throw 'The readiness record is not valid UTF-8 JSON.' }
}

function Get-RequiredString($Object, [string] $Name) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        throw "The readiness record field '$Name' is required."
    }
    return [string]$property.Value
}

function Get-RequiredUtc([string] $Value, [string] $Name) {
    try {
        $parsed = [DateTimeOffset]::Parse($Value,
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor
             [Globalization.DateTimeStyles]::AdjustToUniversal))
    }
    catch {
        throw "$Name must be an ISO-8601 UTC timestamp."
    }
    if ($parsed.Offset -ne [TimeSpan]::Zero) {
        throw "$Name must be an ISO-8601 UTC timestamp."
    }
    return $parsed
}

function Test-Phase7Readiness($Record) {
    if ([string]$Record.schema -cne 'fleetory.phase7-readiness.v1') {
        throw 'The readiness record schema is invalid.'
    }
    $environment = Get-RequiredString $Record 'environment'
    $changeReference = Get-RequiredString $Record 'changeReference'
    $requestedBy = Get-RequiredString $Record 'requestedBy'
    $approvedBy = Get-RequiredString $Record 'approvedBy'
    $deployedBy = Get-RequiredString $Record 'deployedBy'
    if ($requestedBy -ceq $approvedBy -or $approvedBy -ceq $deployedBy -or
        $requestedBy -ceq $deployedBy) {
        throw 'Requester, approver and operator must be distinct identities.'
    }
    $approvedAt = Get-RequiredUtc (Get-RequiredString $Record 'approvedAt') 'approvedAt'
    $validatedAt = Get-RequiredUtc (Get-RequiredString $Record 'validatedAt') 'validatedAt'
    $expiresAt = Get-RequiredUtc (Get-RequiredString $Record 'expiresAt') 'expiresAt'
    if ($approvedAt -gt $validatedAt -or $validatedAt -ge $expiresAt) {
        throw 'Readiness record timestamps are not monotonic.'
    }

    $controls = $Record.PSObject.Properties['controls'].Value
    if ($null -eq $controls) { throw 'The readiness controls object is required.' }
    foreach ($name in @('caPki', 'signer', 'immudbTls', 'wormAnchor', 'recovery')) {
        $property = $controls.PSObject.Properties[$name]
        if ($null -eq $property -or $property.Value -ne $true) {
            throw "The readiness control '$name' is not confirmed."
        }
    }

    $ci = $Record.PSObject.Properties['ci'].Value
    if ($null -eq $ci) { throw 'The CI evidence object is required.' }
    $runUrl = Get-RequiredString $ci 'runUrl'
    $runUri = [uri]$runUrl
    if ($runUri.Scheme -ne 'https' -or $runUri.Host -ne 'github.com') {
        throw 'The CI run URL must be an HTTPS GitHub URL.'
    }
    if ((Get-RequiredString $ci 'sonarQualityGate') -cne 'PASS') {
        throw 'The Sonar Quality Gate is not PASS.'
    }
    try {
        $coverage = [double]::Parse((Get-RequiredString $ci 'coveragePercent'),
            [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw 'The CI coverage percentage is outside the permitted range.'
    }
    if ($coverage -lt 80.0 -or $coverage -gt 100.0) {
        throw 'The CI coverage percentage is outside the permitted range.'
    }

    $evidence = @($Record.PSObject.Properties['evidence'].Value)
    if ($evidence.Count -eq 0) { throw 'At least one evidence item is required.' }
    foreach ($item in $evidence) {
        [void](Get-RequiredString $item 'kind')
        $hash = Get-RequiredString $item 'sha256'
        if ($hash -notmatch '^[0-9A-Fa-f]{64}$') {
            throw 'Evidence SHA-256 must contain exactly 64 hexadecimal characters.'
        }
        [void](Get-RequiredString $item 'reference')
    }

    $rollback = $Record.PSObject.Properties['rollback'].Value
    if ($null -eq $rollback -or
        (Get-RequiredString $rollback 'plan').Length -lt 16 -or
        $rollback.PSObject.Properties['validated'].Value -ne $true) {
        throw 'The rollback plan must be present and validated.'
    }

    return [ordered]@{
        schema = 'fleetory.phase7-readiness-verification.v1'
        environment = $environment
        changeReference = $changeReference
        requestedBy = $requestedBy
        approvedBy = $approvedBy
        deployedBy = $deployedBy
        evidenceCount = $evidence.Count
        ciRunUrl = $runUrl
        coveragePercent = $coverage
        sonarQualityGate = 'PASS'
        verified = $true
    }
}

$record = Read-ReadinessRecord $RecordPath
Test-Phase7Readiness $record | ConvertTo-Json -Compress -Depth 5
