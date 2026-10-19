param([switch]$ResetEphemeralTrust)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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
$version = [int]$key.data.latest_version
$versionName = [string]$version
$pem = $key.data.keys.$versionName.public_key
$deviceId = [Guid]::Empty
if (-not [Guid]::TryParseExact([IO.File]::ReadAllText($deviceIdPath).Trim(), 'D',
    [ref] $deviceId) -or $deviceId -eq [Guid]::Empty) {
    throw 'The lab Agent DeviceId is invalid.'
}
$keyId = "fleetory-lab-command-v$version"
$trustPath = Join-Path $trustDirectory ("{0:N}-$keyId.spki" -f $deviceId)
$ecdsa = [Security.Cryptography.ECDsa]::Create()
try {
    $ecdsa.ImportFromPem($pem)
    if ($ecdsa.KeySize -ne 256) { throw 'The lab public key is not P-256.' }
    $publicKey = $ecdsa.ExportSubjectPublicKeyInfo()
}
finally { $ecdsa.Dispose() }
New-Item -ItemType Directory -Path $trustDirectory -Force | Out-Null
if (Test-Path -LiteralPath $trustPath) {
    if (-not [Linq.Enumerable]::SequenceEqual(
        [byte[]][IO.File]::ReadAllBytes($trustPath), [byte[]]$publicKey)) {
        if (-not $ResetEphemeralTrust) {
            throw 'The existing Agent trust key differs from OpenBao. Use -ResetEphemeralTrust only after a lab OpenBao dev-mode restart.'
        }
        $retiredDirectory = Join-Path $signerDirectory 'retired-trust'
        New-Item -ItemType Directory -Path $retiredDirectory -Force | Out-Null
        $retiredPath = Join-Path $retiredDirectory ("{0:yyyyMMddHHmmss}-{1}.spki" -f `
            [DateTimeOffset]::UtcNow, [Guid]::NewGuid().ToString('N'))
        Move-Item -LiteralPath $trustPath -Destination $retiredPath
        [IO.File]::WriteAllBytes($trustPath, $publicKey)
        Write-Host "Archived stale ephemeral lab trust key: $retiredPath"
    }
}
else { [IO.File]::WriteAllBytes($trustPath, $publicKey) }

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
    $protectedPaths = @($trustDirectory, $trustPath, $signerDirectory, $tokenPath)
    $retiredDirectory = Join-Path $signerDirectory 'retired-trust'
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
    & chmod 600 $trustPath $tokenPath
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
