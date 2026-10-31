$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$workspace = Split-Path -Parent $repoRoot
$labDirectory = Join-Path $workspace 'work/security-lab'
$signerDirectory = Join-Path $workspace 'work/security-lab-signer'
$trustDirectory = Join-Path $labDirectory 'agent-trust'
$deviceId = [IO.File]::ReadAllText(
    (Join-Path $labDirectory 'certs/agent-device-id')).Trim()
$deviceGuid = [Guid]::ParseExact($deviceId, 'D')
if ($deviceGuid -eq [Guid]::Empty) { throw 'The lab DeviceId is invalid.' }

& (Join-Path $PSScriptRoot 'provision-security-lab-command-signing.ps1')
$settings = @{}
foreach ($entry in [IO.File]::ReadAllLines((Join-Path $labDirectory 'lab.env'))) {
    $parts = $entry.Split('=', 2)
    if ($parts.Count -eq 2) { $settings[$parts[0]] = $parts[1] }
}
$rootToken = $settings['FLEETORY_LAB_OPENBAO_TOKEN']
if ([string]::IsNullOrWhiteSpace($rootToken)) { throw 'The lab OpenBao token is missing.' }
$headers = @{ 'X-Vault-Token' = $rootToken }
$keyUri = 'http://127.0.0.1:8200/v1/transit/keys/fleetory-lab-command'
$before = Invoke-RestMethod -Uri $keyUri -Headers $headers -TimeoutSec 10
$oldVersion = [int]$before.data.latest_version
$oldKeyId = "fleetory-lab-command-v$oldVersion"
$oldTrustPath = Join-Path $trustDirectory ("{0:N}-$oldKeyId.spki" -f $deviceGuid)
if (-not (Test-Path -LiteralPath $oldTrustPath -PathType Leaf)) {
    throw 'The prior Agent trust key was not provisioned.'
}

Invoke-RestMethod -Method Post -Uri ($keyUri + '/rotate') -Headers $headers `
    -TimeoutSec 10 | Out-Null
$after = Invoke-RestMethod -Uri $keyUri -Headers $headers -TimeoutSec 10
$newVersion = [int]$after.data.latest_version
if ($newVersion -ne $oldVersion + 1) {
    throw "Unexpected Transit version after rotation: $newVersion."
}
& (Join-Path $PSScriptRoot 'provision-security-lab-command-signing.ps1')

$checkProject = Join-Path $PSScriptRoot 'CommandSigningLabCheck/CommandSigningLabCheck.csproj'
& dotnet run --project $checkProject -c Release -- `
    $labDirectory $signerDirectory $deviceId $oldVersion $oldTrustPath Accepted
if ($LASTEXITCODE -ne 0) { throw 'Overlapping Agent trust check failed.' }

$retiredDirectory = Join-Path $signerDirectory 'retired-trust'
$trustRoot = [IO.Path]::GetFullPath($trustDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
$source = [IO.Path]::GetFullPath($oldTrustPath)
$signerRoot = [IO.Path]::GetFullPath($signerDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
$targetDirectory = [IO.Path]::GetFullPath($retiredDirectory)
$comparison = if ($env:OS -eq 'Windows_NT') {
    [StringComparison]::OrdinalIgnoreCase
} else { [StringComparison]::Ordinal }
if (-not $source.StartsWith($trustRoot, $comparison) -or
    -not $targetDirectory.StartsWith($signerRoot, $comparison)) {
    throw 'The trust retirement path escaped the security lab.'
}
New-Item -ItemType Directory -Path $retiredDirectory -Force | Out-Null
$retiredPath = Join-Path $retiredDirectory ("{0:yyyyMMddHHmmss}-{1}-{2}.spki" -f `
    [DateTimeOffset]::UtcNow, $oldKeyId, [Guid]::NewGuid().ToString('N'))
Move-Item -LiteralPath $oldTrustPath -Destination $retiredPath
if ($env:OS -eq 'Windows_NT') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls $retiredDirectory /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict retired trust directory.' }
    & icacls $retiredPath /inheritance:r /grant:r "${identity}:F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict retired trust file.' }
}
else {
    & chmod 700 $retiredDirectory
    & chmod 600 $retiredPath
}

& dotnet run --project $checkProject -c Release -- `
    $labDirectory $signerDirectory $deviceId $oldVersion $retiredPath UnknownKey
if ($LASTEXITCODE -ne 0) { throw 'Retired-key rejection check failed.' }
Write-Host "PASS: Transit v$oldVersion to v$newVersion overlap and Agent retirement; archived key: $retiredPath"