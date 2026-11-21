$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'PowerShell 7 or later is required to validate certificate/private-key pairs.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$labDirectory = Join-Path (Split-Path -Parent $repoRoot) 'work/security-lab'
$certDirectory = Join-Path $labDirectory 'certs'
$envPath = Join-Path $labDirectory 'lab.env'
$composePath = Join-Path $repoRoot 'infra/security-lab/compose.yaml'
if (-not (Test-Path -LiteralPath $envPath)) { throw 'Start the security lab first.' }
New-Item -ItemType Directory -Path $certDirectory -Force | Out-Null

function Protect-LabCertificateDirectory([string] $Directory) {
    if ($env:OS -eq 'Windows_NT') {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $Directory /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not restrict certificate directory ACL.' }
        foreach ($file in Get-ChildItem -LiteralPath $Directory -File) {
            & icacls $file.FullName /inheritance:r /grant:r "${identity}:F" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not restrict certificate ACL.' }
        }
    }
    else {
        & chmod 700 $Directory
        if ($LASTEXITCODE -ne 0) { throw 'Could not restrict certificate directory.' }
        foreach ($file in Get-ChildItem -LiteralPath $Directory -File) {
            & chmod 600 $file.FullName
            if ($LASTEXITCODE -ne 0) { throw 'Could not restrict certificate file.' }
        }
    }
}

# Protect the parent before docker cp can create any private key in it.
Protect-LabCertificateDirectory $certDirectory

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
    $stagedCrt = Join-Path $certDirectory "$Stem.$suffix.crt.pending"
    $stagedKey = Join-Path $certDirectory "$Stem.$suffix.key.pending"
    $activeCrt = Join-Path $certDirectory "$Stem.crt"
    $activeKey = Join-Path $certDirectory "$Stem.key"
    $arguments = @('compose', '--env-file', $envPath, '-f', $composePath,
        'exec', '-T', $Service, 'step', 'ca', 'certificate', $Subject,
        $remoteCrt, $remoteKey, '--ca-url', 'https://localhost:9000',
        '--root', '/home/step/certs/root_ca.crt', '--provisioner', $Provisioner,
        '--provisioner-password-file', '/home/step/secrets/password')
    foreach ($entry in $San) { $arguments += @('--san', $entry) }
    $container = "fleetory-security-lab-$Service-1"
    try {
        try {
            & docker @arguments | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Certificate issuance failed for $Service." }
            & docker cp "${container}:$remoteCrt" $stagedCrt | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Certificate copy failed for $Service." }
            & docker cp "${container}:$remoteKey" $stagedKey | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Key copy failed for $Service." }
        }
        finally {
            & docker exec $container rm -f -- $remoteCrt $remoteKey | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Temporary CA container key cleanup failed for $Service." }
        }

        $pair = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
            $stagedCrt, $stagedKey)
        $pair.Dispose()

        $oldCertificateExists = Test-Path -LiteralPath $activeCrt -PathType Leaf
        $oldKeyExists = Test-Path -LiteralPath $activeKey -PathType Leaf
        if ($oldCertificateExists -ne $oldKeyExists) {
            throw "Existing $Stem certificate pair is incomplete."
        }

        $archiveCrt = $null
        $archiveKey = $null
        if ($oldCertificateExists) {
            $history = Join-Path $certDirectory 'history'
            New-Item -ItemType Directory -Path $history -Force | Out-Null
            Protect-LabCertificateDirectory $history
            $timestamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ',
                [Globalization.CultureInfo]::InvariantCulture)
            $archive = Join-Path $history "$Stem-$timestamp-$suffix"
            New-Item -ItemType Directory -Path $archive | Out-Null
            Protect-LabCertificateDirectory $archive
            $archiveCrt = Join-Path $archive "$Stem.crt"
            $archiveKey = Join-Path $archive "$Stem.key"
            Copy-Item -LiteralPath $activeCrt -Destination $archiveCrt
            Copy-Item -LiteralPath $activeKey -Destination $archiveKey
            Protect-LabCertificateDirectory $archive
        }

        try {
            Move-Item -LiteralPath $stagedCrt -Destination $activeCrt -Force
            Move-Item -LiteralPath $stagedKey -Destination $activeKey -Force
            Protect-LabCertificateDirectory $certDirectory
        }
        catch {
            if ($archiveCrt -and $archiveKey) {
                Copy-Item -LiteralPath $archiveCrt -Destination $activeCrt -Force
                Copy-Item -LiteralPath $archiveKey -Destination $activeKey -Force
            }
            else {
                Remove-Item -LiteralPath $activeCrt, $activeKey -Force -ErrorAction SilentlyContinue
            }
            throw
        }
    }
    finally {
        Remove-Item -LiteralPath $stagedCrt, $stagedKey -Force -ErrorAction SilentlyContinue
    }
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
Protect-LabCertificateDirectory $certDirectory

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
