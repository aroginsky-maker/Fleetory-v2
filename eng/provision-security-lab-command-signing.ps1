param([switch]$ResetEphemeralTrust)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-LabCommandPublicKey([string] $Pem) {
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        $ecdsa.ImportFromPem($Pem)
        if ($ecdsa.KeySize -ne 256) { throw 'The lab public key is not P-256.' }
        return ,$ecdsa.ExportSubjectPublicKeyInfo()
    }
    finally { $ecdsa.Dispose() }
}

function Sync-LabCommandTrust(
    [string] $TrustDirectory, [string] $RetiredDirectory,
    [Guid] $DeviceGuid, [object] $KeyData, [bool] $ResetEphemeralTrust) {
    $version = [int]$KeyData.latest_version
    if ($version -lt 1) { throw 'OpenBao returned an invalid key version.' }
    $prefix = ('{0:N}-fleetory-lab-command-v' -f $DeviceGuid)
    $currentPath = Join-Path $TrustDirectory "$prefix$version.spki"
    $latestKey = $KeyData.keys.PSObject.Properties[[string]$version]
    if ($null -eq $latestKey) { throw 'OpenBao omitted the latest public key.' }
    $publicKey = Get-LabCommandPublicKey ([string]$latestKey.Value.public_key)
    New-Item -ItemType Directory -Path $TrustDirectory -Force | Out-Null
    if (([IO.File]::GetAttributes($TrustDirectory) -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The lab command trust directory must not be a symbolic link.'
    }

    $stalePaths = [Collections.Generic.List[string]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $TrustDirectory |
        Where-Object { $_.Name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })) {
        if ($file.PSIsContainer -or
            ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Lab command trust entry is not a regular file: $($file.Name)"
        }
        $versionText = $file.Name.Substring($prefix.Length)
        $match = [regex]::Match($versionText, '^([1-9][0-9]*)\.spki$')
        if (-not $match.Success) { throw "Unexpected lab command trust file: $($file.Name)" }
        $knownVersion = $match.Groups[1].Value
        $versionKey = $KeyData.keys.PSObject.Properties[$knownVersion]
        if ($null -eq $versionKey) {
            $stalePaths.Add($file.FullName)
            continue
        }
        $expected = Get-LabCommandPublicKey ([string]$versionKey.Value.public_key)
        $actual = [byte[]][IO.File]::ReadAllBytes($file.FullName)
        if (-not [Linq.Enumerable]::SequenceEqual($actual, [byte[]]$expected)) {
            $stalePaths.Add($file.FullName)
        }
    }
    if ($stalePaths.Count -gt 0 -and -not $ResetEphemeralTrust) {
        throw 'Existing Agent trust differs from the OpenBao key ring. Use -ResetEphemeralTrust only after a disposable lab restart.'
    }
    foreach ($stalePath in $stalePaths) {
        New-Item -ItemType Directory -Path $RetiredDirectory -Force | Out-Null
        $retiredPath = Join-Path $RetiredDirectory ("{0:yyyyMMddHHmmss}-{1}.spki" -f `
            [DateTimeOffset]::UtcNow, [Guid]::NewGuid().ToString('N'))
        Move-Item -LiteralPath $stalePath -Destination $retiredPath
        Write-Host "Archived stale ephemeral lab trust key: $retiredPath"
    }

    if (-not (Test-Path -LiteralPath $currentPath)) {
        [IO.File]::WriteAllBytes($currentPath, [byte[]]$publicKey)
    }
    return $currentPath
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$labDirectory = Join-Path (Split-Path -Parent $repoRoot) 'work/security-lab'
$signerDirectory = Join-Path (Split-Path -Parent $repoRoot) 'work/security-lab-signer'
$envPath = Join-Path $labDirectory 'lab.env'
$deviceIdPath = Join-Path $labDirectory 'certs/agent-device-id'
$trustDirectory = Join-Path $labDirectory 'agent-trust'
if (-not (Test-Path -LiteralPath $envPath) -or
    -not (Test-Path -LiteralPath $deviceIdPath)) {
    throw 'Start the security lab and provision Agent certificates first.'
}

$settings = @{}
foreach ($entry in [IO.File]::ReadAllLines($envPath)) {
    $parts = $entry.Split('=', 2)
    if ($parts.Count -eq 2) { $settings[$parts[0]] = $parts[1] }
}
$rootToken = $settings['FLEETORY_LAB_OPENBAO_TOKEN']
if ([string]::IsNullOrWhiteSpace($rootToken)) { throw 'The lab OpenBao token is missing.' }
$headers = @{ 'X-Vault-Token' = $rootToken }
$base = 'http://127.0.0.1:8200/v1/'
$mounts = Invoke-RestMethod -Uri ($base + 'sys/mounts') -Headers $headers -TimeoutSec 10
if (-not $mounts.PSObject.Properties.Name.Contains('transit/')) {
    Invoke-RestMethod -Method Post -Uri ($base + 'sys/mounts/transit') -Headers $headers `
        -ContentType 'application/json' -Body '{"type":"transit"}' -TimeoutSec 10 | Out-Null
}

$keyName = 'fleetory-lab-command'
Invoke-RestMethod -Method Post -Uri ($base + "transit/keys/$keyName") -Headers $headers `
    -ContentType 'application/json' `
    -Body '{"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false}' `
    -TimeoutSec 10 | Out-Null
$key = Invoke-RestMethod -Uri ($base + "transit/keys/$keyName") -Headers $headers -TimeoutSec 10
if ($key.data.type -ne 'ecdsa-p256' -or $key.data.exportable -or
    $key.data.allow_plaintext_backup) {
    throw 'The lab signing key is not a non-exportable P-256 key.'
}
$deviceId = [Guid]::Empty
if (-not [Guid]::TryParseExact([IO.File]::ReadAllText($deviceIdPath).Trim(), 'D',
    [ref] $deviceId) -or $deviceId -eq [Guid]::Empty) {
    throw 'The lab Agent DeviceId is invalid.'
}
$retiredDirectory = Join-Path $signerDirectory 'retired-trust'
$trustPath = Sync-LabCommandTrust $trustDirectory $retiredDirectory `
    $deviceId $key.data $ResetEphemeralTrust.IsPresent
$keyId = "fleetory-lab-command-v$($key.data.latest_version)"

$policy = @'
path "transit/sign/fleetory-lab-command/sha2-256" {
  capabilities = ["update"]
}
path "transit/keys/fleetory-lab-command" {
  capabilities = ["read"]
}
'@
$policyBody = @{ policy = $policy } | ConvertTo-Json -Compress
Invoke-RestMethod -Method Put -Uri ($base + 'sys/policies/acl/fleetory-command-signer') `
    -Headers $headers -ContentType 'application/json' -Body $policyBody -TimeoutSec 10 | Out-Null
$tokenBody = @{
    policies = @('fleetory-command-signer')
    no_default_policy = $true
    renewable = $false
    ttl = '1h'
    explicit_max_ttl = '1h'
    orphan = $true
} | ConvertTo-Json -Compress
$issued = Invoke-RestMethod -Method Post -Uri ($base + 'auth/token/create') `
    -Headers $headers -ContentType 'application/json' -Body $tokenBody -TimeoutSec 10
$signerToken = $issued.auth.client_token
if ([string]::IsNullOrWhiteSpace($signerToken)) { throw 'OpenBao did not issue a signing token.' }
New-Item -ItemType Directory -Path $signerDirectory -Force | Out-Null
$tokenPath = Join-Path $signerDirectory 'command-signer-token'
$previousToken = if (Test-Path -LiteralPath $tokenPath) {
    [IO.File]::ReadAllText($tokenPath)
} else { $null }
if ($previousToken) {
    try {
        $revokeBody = @{ token = $previousToken } | ConvertTo-Json -Compress
        Invoke-RestMethod -Method Post -Uri ($base + 'auth/token/revoke') -Headers $headers `
            -ContentType 'application/json' -Body $revokeBody -TimeoutSec 10 | Out-Null
    }
    catch { Write-Warning 'Previous signer token could not be revoked; it expires within one hour.' }
}
[IO.File]::WriteAllText($tokenPath, $signerToken, [Text.UTF8Encoding]::new($false))
if ($env:OS -eq 'Windows_NT') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $protectedPaths = @($trustDirectory, $signerDirectory, $tokenPath)
    $protectedPaths += @(Get-ChildItem -LiteralPath $trustDirectory -File |
        Select-Object -ExpandProperty FullName)
    if (Test-Path -LiteralPath $retiredDirectory) {
        $protectedPaths += $retiredDirectory
        $protectedPaths += @(Get-ChildItem -LiteralPath $retiredDirectory -File |
            Select-Object -ExpandProperty FullName)
    }
    foreach ($path in $protectedPaths) {
        $grant = if ($path -in @($trustDirectory, $signerDirectory, $retiredDirectory)) {
            "${identity}:(OI)(CI)F"
        } else { "${identity}:F" }
        & icacls $path /inheritance:r /grant:r $grant | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not restrict command signing file ACL.' }
    }
}
else {
    & chmod 700 $trustDirectory $signerDirectory
    Get-ChildItem -LiteralPath $trustDirectory -File | ForEach-Object {
        & chmod 600 $_.FullName
    }
    & chmod 600 $tokenPath
    $retiredDirectory = Join-Path $signerDirectory 'retired-trust'
    if (Test-Path -LiteralPath $retiredDirectory) {
        & chmod 700 $retiredDirectory
        Get-ChildItem -LiteralPath $retiredDirectory -File | ForEach-Object {
            & chmod 600 $_.FullName
        }
    }
}

Write-Host "Lab Transit key $keyId is non-exportable; Agent trust file: $trustPath"
Write-Host 'A one-hour sign-only token was placed outside the Server token directory and Git.'
