param([switch]$ResetEphemeralTrust)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$workspace = Split-Path -Parent $repoRoot
$labDirectory = Join-Path $workspace 'work/security-lab'
$signerDirectory = Join-Path $workspace 'work/security-lab-signer'
$deviceIdPath = Join-Path $labDirectory 'certs/agent-device-id'

& (Join-Path $PSScriptRoot 'provision-security-lab-command-signing.ps1') `
    -ResetEphemeralTrust:$ResetEphemeralTrust
if ($LASTEXITCODE -ne 0) { throw 'Lab command signing provisioning failed.' }

$deviceId = [IO.File]::ReadAllText($deviceIdPath).Trim()
& dotnet run --project (Join-Path $PSScriptRoot 'CommandSigningLabCheck/CommandSigningLabCheck.csproj') `
    -c Release -- $labDirectory $signerDirectory $deviceId
if ($LASTEXITCODE -ne 0) { throw 'Live command signing check failed.' }
