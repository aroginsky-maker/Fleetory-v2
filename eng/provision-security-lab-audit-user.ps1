$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$labDirectory = Join-Path (Split-Path -Parent $repoRoot) 'work/security-lab'
$envPath = Join-Path $labDirectory 'lab.env'
if (-not (Test-Path -LiteralPath $envPath)) {
    throw 'Start the security lab first.'
}

$settings = @{}
foreach ($entry in [IO.File]::ReadAllLines($envPath)) {
    $separator = $entry.IndexOf('=')
    if ($separator -gt 0) {
        $settings[$entry.Substring(0, $separator)] = $entry.Substring($separator + 1)
    }
}
foreach ($required in @('FLEETORY_LAB_IMMUDB_PASSWORD', 'FLEETORY_LAB_AUDIT_WRITER_PASSWORD',
        'FLEETORY_LAB_OPENBAO_TOKEN')) {
    if ([string]::IsNullOrWhiteSpace($settings[$required])) {
        throw "Missing $required in the private lab configuration."
    }
}

function ConvertTo-Base64Utf8([string] $value) {
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value))
}

function Get-ImmudbToken([string] $username, [string] $password) {
    $body = @{
        user = ConvertTo-Base64Utf8 $username
        password = ConvertTo-Base64Utf8 $password
    } | ConvertTo-Json -Compress
    $response = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8090/api/login' `
        -ContentType 'application/json' -Body $body -TimeoutSec 10
    if ([string]::IsNullOrWhiteSpace($response.token)) {
        throw 'immudb did not issue a token.'
    }
    return $response.token
}

$username = 'fleetory_audit_writer'
$adminToken = Get-ImmudbToken 'immudb' $settings['FLEETORY_LAB_IMMUDB_PASSWORD']
$adminHeaders = @{ Authorization = "Bearer $adminToken" }
$users = Invoke-RestMethod -Uri 'http://127.0.0.1:8090/api/user/list' `
    -Headers $adminHeaders -TimeoutSec 10
$writer = @($users.users | Where-Object {
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.user)) -eq $username
})
if ($writer.Count -gt 1) { throw 'immudb returned duplicate audit writer accounts.' }
if ($writer.Count -eq 0) {
    $body = @{
        user = ConvertTo-Base64Utf8 $username
        password = ConvertTo-Base64Utf8 $settings['FLEETORY_LAB_AUDIT_WRITER_PASSWORD']
        permission = 2
        database = 'defaultdb'
    } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8090/api/user' `
        -Headers $adminHeaders -ContentType 'application/json' -Body $body -TimeoutSec 10 | Out-Null
    $users = Invoke-RestMethod -Uri 'http://127.0.0.1:8090/api/user/list' `
        -Headers $adminHeaders -TimeoutSec 10
    $writer = @($users.users | Where-Object {
        [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.user)) -eq $username
    })
}
if ($writer.Count -ne 1 -or -not $writer[0].active -or
    @($writer[0].permissions).Count -ne 1 -or
    $writer[0].permissions[0].database -ne 'defaultdb' -or
    [int]$writer[0].permissions[0].permission -ne 2) {
    throw 'The immudb audit writer account has unexpected permissions.'
}

# A stale local password must stop provisioning; silently resetting it would hide drift.
$writerToken = Get-ImmudbToken $username $settings['FLEETORY_LAB_AUDIT_WRITER_PASSWORD']
$writerHeaders = @{ Authorization = "Bearer $writerToken" }
$visibleUsers = Invoke-RestMethod -Uri 'http://127.0.0.1:8090/api/user/list' `
    -Headers $writerHeaders -TimeoutSec 10
if (@($visibleUsers.users).Count -ne 1 -or
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(
        $visibleUsers.users[0].user)) -ne $username) {
    throw 'The audit writer can see unexpected immudb users.'
}

$secretBody = @{ data = @{ value = $settings['FLEETORY_LAB_AUDIT_WRITER_PASSWORD'] } } |
    ConvertTo-Json -Compress -Depth 4
Invoke-RestMethod -Method Post `
    -Uri 'http://127.0.0.1:8200/v1/secret/data/fleetory/audit-immudb-password' `
    -Headers @{ 'X-Vault-Token' = $settings['FLEETORY_LAB_OPENBAO_TOKEN'] } `
    -ContentType 'application/json' -Body $secretBody -TimeoutSec 10 | Out-Null
Write-Host 'immudb audit writer provisioned with read/write access to defaultdb.'
