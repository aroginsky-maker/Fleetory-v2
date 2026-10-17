$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$labDirectory = Join-Path (Split-Path -Parent $repoRoot) 'work/security-lab'
$certDirectory = Join-Path $labDirectory 'certs'
$envPath = Join-Path $labDirectory 'lab.env'
$composePath = Join-Path $repoRoot 'infra/security-lab/compose.yaml'
if (-not (Test-Path -LiteralPath $envPath)) { throw 'Start the security lab first.' }
New-Item -ItemType Directory -Path $certDirectory -Force | Out-Null

function Issue-LabCertificate {
    param(
        [string] $Service,
        [string] $Provisioner,
        [string] $Subject,
        [string[]] $San,
        [string] $Stem
    )

    $suffix = [Guid]::NewGuid().ToString('N')
    $remoteCrt = "/tmp/fleetory-$suffix.crt"
    $remoteKey = "/tmp/fleetory-$suffix.key"
    $arguments = @('compose', '--env-file', $envPath, '-f', $composePath,
        'exec', '-T', $Service, 'step', 'ca', 'certificate', $Subject,
        $remoteCrt, $remoteKey, '--ca-url', 'https://localhost:9000',
        '--root', '/home/step/certs/root_ca.crt', '--provisioner', $Provisioner,
        '--provisioner-password-file', '/home/step/secrets/password')
    foreach ($entry in $San) { $arguments += @('--san', $entry) }
    & docker @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Certificate issuance failed for $Service." }

    $container = "fleetory-security-lab-$Service-1"
    & docker cp "${container}:$remoteCrt" (Join-Path $certDirectory "$Stem.crt") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Certificate copy failed for $Service." }
    & docker cp "${container}:$remoteKey" (Join-Path $certDirectory "$Stem.key") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Key copy failed for $Service." }
}

function Get-OrCreate-LabIdentity {
    param([string] $Name)

    $path = Join-Path $certDirectory $Name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $value = [IO.File]::ReadAllText($path).Trim()
        $parsed = [Guid]::Empty
        if ([Guid]::TryParseExact($value, 'D', [ref] $parsed) -and
            $parsed -ne [Guid]::Empty) {
            return $parsed.ToString('D')
        }
        throw "The existing $Name is not a valid identity."
    }

    return [Guid]::NewGuid().ToString('D')
}

$deviceId = Get-OrCreate-LabIdentity 'agent-device-id'
$adminId = Get-OrCreate-LabIdentity 'admin-person-id'
Issue-LabCertificate 'agent-ca' 'fleetory-agent-lab' '127.0.0.1' `
    @('127.0.0.1', 'localhost') 'agent-server'
Issue-LabCertificate 'agent-ca' 'fleetory-agent-lab' 'Fleetory Agent Lab' `
    @( "urn:fleetory:device:$deviceId" ) 'agent-client'
Issue-LabCertificate 'admin-ca' 'fleetory-admin-lab' '127.0.0.1' `
    @('127.0.0.1', 'localhost') 'admin-server'
Issue-LabCertificate 'admin-ca' 'fleetory-admin-lab' 'Fleetory Admin Lab' `
    @( "urn:fleetory:admin:$adminId" ) 'admin-client'

foreach ($service in @('agent', 'admin')) {
    $container = "fleetory-security-lab-$service-ca-1"
    & docker cp "${container}:/home/step/certs/root_ca.crt" `
        (Join-Path $certDirectory "$service-root.crt") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Root copy failed for $service." }
    & docker cp "${container}:/home/step/certs/intermediate_ca.crt" `
        (Join-Path $certDirectory "$service-intermediate.crt") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Intermediate copy failed for $service." }
}

[IO.File]::WriteAllText((Join-Path $certDirectory 'agent-device-id'), $deviceId)
[IO.File]::WriteAllText((Join-Path $certDirectory 'admin-person-id'), $adminId)
if ($env:OS -eq 'Windows_NT') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls $certDirectory /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict certificate directory ACL.' }
    foreach ($file in Get-ChildItem -LiteralPath $certDirectory -File) {
        & icacls $file.FullName /inheritance:r /grant:r "${identity}:F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not restrict certificate ACL.' }
    }
}
else {
    & chmod 700 $certDirectory
    foreach ($file in Get-ChildItem -LiteralPath $certDirectory -File) {
        & chmod 600 $file.FullName
    }
}

$settings = @{}
foreach ($entry in [IO.File]::ReadAllLines($envPath)) {
    $separator = $entry.IndexOf('=')
    if ($separator -gt 0) { $settings[$entry.Substring(0, $separator)] = $entry.Substring($separator + 1) }
}
$token = $settings['FLEETORY_LAB_OPENBAO_TOKEN']
foreach ($service in @('agent', 'admin')) {
    $values = @{
        "$service-gateway-root-ca" = [IO.File]::ReadAllText(
            (Join-Path $certDirectory "$service-root.crt"))
        "$service-gateway-server-cert" = [IO.File]::ReadAllText(
            (Join-Path $certDirectory "$service-server.crt")) + "`n" +
            [IO.File]::ReadAllText((Join-Path $certDirectory "$service-intermediate.crt"))
        "$service-gateway-server-key" = [IO.File]::ReadAllText(
            (Join-Path $certDirectory "$service-server.key"))
    }
    foreach ($item in $values.GetEnumerator()) {
        $body = @{ data = @{ value = $item.Value } } | ConvertTo-Json -Compress -Depth 4
        try {
            Invoke-RestMethod -Method Post `
                -Uri "http://127.0.0.1:8200/v1/secret/data/fleetory/$($item.Key)" `
                -Headers @{ 'X-Vault-Token' = $token } `
                -ContentType 'application/json' -Body $body -TimeoutSec 10 | Out-Null
        }
        catch { throw "OpenBao TLS material write failed for $service." }
    }
}

Write-Host 'Issued separate Agent/Admin lab certificates and stored gateway materials in OpenBao.'
Write-Host "Client certificates and private keys are in $certDirectory outside Git."
