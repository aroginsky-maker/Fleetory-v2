$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$labDirectory = Join-Path (Split-Path -Parent $repoRoot) 'work/security-lab'
$envPath = Join-Path $labDirectory 'lab.env'
$composePath = Join-Path $repoRoot 'infra/security-lab/compose.yaml'

function New-LabSecret {
    $bytes = New-Object byte[] 24
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    return [BitConverter]::ToString($bytes).Replace('-', '')
}

New-Item -ItemType Directory -Path $labDirectory -Force | Out-Null
if (-not (Test-Path -LiteralPath $envPath)) {
    $entries = @(
        "FLEETORY_LAB_AGENT_CA_PASSWORD=$(New-LabSecret)",
        "FLEETORY_LAB_ADMIN_CA_PASSWORD=$(New-LabSecret)",
        "FLEETORY_LAB_KEYCLOAK_ADMIN_PASSWORD=$(New-LabSecret)",
        "FLEETORY_LAB_OPENBAO_TOKEN=$(New-LabSecret)",
        "FLEETORY_LAB_IMMUDB_PASSWORD=$(New-LabSecret)",
        "FLEETORY_LAB_POSTGRES_PASSWORD=$(New-LabSecret)"
    )
    [System.IO.File]::WriteAllLines($envPath, $entries, [System.Text.UTF8Encoding]::new($false))
}

$entries = [System.IO.File]::ReadAllLines($envPath)
$legacyPassword = $entries | Where-Object { $_.StartsWith('FLEETORY_LAB_IMMUDB_PASSWORD_BASE64=') } |
    Select-Object -First 1
if ($legacyPassword) {
    $actualPassword = $legacyPassword.Split('=', 2)[1]
    $entries = @($entries | Where-Object {
        -not $_.StartsWith('FLEETORY_LAB_IMMUDB_PASSWORD_BASE64=') -and
        -not $_.StartsWith('FLEETORY_LAB_IMMUDB_PASSWORD=')
    }) + "FLEETORY_LAB_IMMUDB_PASSWORD=$actualPassword"
    [System.IO.File]::WriteAllLines($envPath, $entries, [System.Text.UTF8Encoding]::new($false))
}
if (-not ($entries | Where-Object { $_.StartsWith('FLEETORY_LAB_POSTGRES_PASSWORD=') })) {
    [System.IO.File]::AppendAllText($envPath,
        "FLEETORY_LAB_POSTGRES_PASSWORD=$(New-LabSecret)`n", [System.Text.UTF8Encoding]::new($false))
    $entries = [System.IO.File]::ReadAllLines($envPath)
}

$settings = @{}
foreach ($entry in $entries) {
    $separator = $entry.IndexOf('=')
    if ($separator -gt 0) { $settings[$entry.Substring(0, $separator)] = $entry.Substring($separator + 1) }
}
$tokenFile = Join-Path $labDirectory 'openbao-token'
[System.IO.File]::WriteAllText($tokenFile, $settings['FLEETORY_LAB_OPENBAO_TOKEN'],
    [System.Text.UTF8Encoding]::new($false))
if ($env:OS -eq 'Windows_NT') {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls $labDirectory /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict lab directory ACL.' }
    foreach ($path in @($envPath, $tokenFile)) {
        & icacls $path /inheritance:r /grant:r "${identity}:F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not restrict lab credential ACL.' }
    }
}
else {
    & chmod 700 $labDirectory
    & chmod 600 $envPath
    & chmod 600 $tokenFile
}

& docker compose --env-file $envPath -f $composePath config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Security lab compose configuration is invalid.' }

& docker compose --env-file $envPath -f $composePath up -d
if ($LASTEXITCODE -ne 0) { throw 'Security lab did not start.' }

$healthUri = 'http://127.0.0.1:8200/v1/sys/health'
$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    try {
        $response = Invoke-RestMethod -Uri $healthUri -TimeoutSec 2
        if ($response.initialized -and -not $response.sealed) { $ready = $true; break }
    }
    catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) { throw 'OpenBao did not become ready.' }

$connectionString = "Host=127.0.0.1;Port=5440;Database=fleetory_lab;Username=fleetory;Password=$($settings['FLEETORY_LAB_POSTGRES_PASSWORD'])"
$body = @{ data = @{ value = $connectionString } } | ConvertTo-Json -Compress -Depth 4
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8200/v1/secret/data/fleetory/fleetory-postgresql' `
    -Headers @{ 'X-Vault-Token' = $settings['FLEETORY_LAB_OPENBAO_TOKEN'] } `
    -ContentType 'application/json' -Body $body -TimeoutSec 10 | Out-Null

Write-Host 'Fleetory security lab started on loopback ports 9002, 9003, 8088, 8200, 5433 and 5440.'
Write-Host "Lab credentials are stored in $envPath"
