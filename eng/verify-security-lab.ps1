param([switch] $AuditPipeline)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$labDirectory = Join-Path (Split-Path -Parent $repoRoot) 'work/security-lab'
$tokenFile = Join-Path $labDirectory 'openbao-token'
$serverDll = Join-Path $repoRoot 'src/Fleetory.Server/bin/Debug/net10.0/Fleetory.Server.dll'
$stdoutPath = Join-Path $labDirectory 'fleetory-server.stdout.log'
$stderrPath = Join-Path $labDirectory 'fleetory-server.stderr.log'
$healthUri = 'http://127.0.0.1:5088/health/ready'

if (-not (Test-Path -LiteralPath $serverDll) -or -not (Test-Path -LiteralPath $tokenFile)) {
    throw 'Build Fleetory.Server and start the security lab first.'
}

$env:FLEETORY_Fleetory__Secrets__Provider = 'OpenBao'
$env:FLEETORY_Fleetory__Secrets__Address = 'http://127.0.0.1:8200/'
$env:FLEETORY_Fleetory__Secrets__TokenDirectory = $labDirectory
if ($AuditPipeline) {
    $env:FLEETORY_Fleetory__AuditExport__Enabled = 'true'
    $env:FLEETORY_Fleetory__AuditExport__Sink = 'Immudb'
    $env:FLEETORY_Fleetory__AuditExport__Address = 'http://127.0.0.1:8090/'
    $env:FLEETORY_Fleetory__AuditExport__Username = 'immudb'
}

$server = $null
try {
    $server = Start-Process -FilePath 'dotnet' -ArgumentList @(
        ('"' + $serverDll + '"'), '--environment=Development',
        '--urls=http://127.0.0.1:5088') -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

    $healthy = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Seconds 1
        if ($server.HasExited) { break }
        try {
            $response = Invoke-WebRequest -Uri $healthUri -TimeoutSec 2
            if ($response.StatusCode -eq 200) { $healthy = $true; break }
        }
        catch { }
    }

    if (-not $healthy) {
        throw "Fleetory did not become ready with OpenBao. See $stderrPath"
    }

    Write-Host 'Fleetory /health/ready returned 200 with OpenBao-backed PostgreSQL configuration.'
    if ($AuditPipeline) {
        $eventId = [guid]::NewGuid().ToString()
        $sql = "INSERT INTO platform.audit_events (event_id, actor_subject_id, actor_kind, action, correlation_id, occurred_at, recorded_at) VALUES ('$eventId', 'system:lab', 2, 'audit.export.e2e', '$eventId', now(), now()); INSERT INTO platform.audit_export_queue (audit_event_id, enqueued_at, next_attempt_at) VALUES ('$eventId', now(), now());"
        & docker exec fleetory-security-lab-postgres-1 psql -v ON_ERROR_STOP=1 -U fleetory -d fleetory_lab -q -c $sql
        if ($LASTEXITCODE -ne 0) { throw 'Could not seed the lab audit outbox.' }

        $pending = 1
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            Start-Sleep -Milliseconds 500
            $pending = & docker exec fleetory-security-lab-postgres-1 psql -At -U fleetory -d fleetory_lab -c "SELECT count(*) FROM platform.audit_export_queue WHERE audit_event_id='$eventId'"
            if ($LASTEXITCODE -ne 0) { throw 'Could not query the lab audit outbox.' }
            if ($pending -eq '0') { break }
        }
        if ($pending -ne '0') { throw 'The audit worker did not drain the lab outbox.' }

        $envPath = Join-Path $labDirectory 'lab.env'
        $password = (Get-Content -LiteralPath $envPath |
            Where-Object { $_.StartsWith('FLEETORY_LAB_IMMUDB_PASSWORD=') } |
            Select-Object -First 1).Split('=', 2)[1]
        $login = @{
            user = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('immudb'))
            password = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($password))
        } | ConvertTo-Json -Compress
        $auth = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8090/api/login' `
            -ContentType 'application/json' -Body $login
        $key = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
            'fleetory/audit/v1/' + $eventId.Replace('-', '')))
        $entry = Invoke-RestMethod -Uri ('http://127.0.0.1:8090/api/db/get/' +
            [Uri]::EscapeDataString($key)) -Headers @{ Authorization = "Bearer $($auth.token)" }
        $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($entry.value)) |
            ConvertFrom-Json
        if ($payload.eventId -ne $eventId.Replace('-', '') -or
            $payload.Action -ne 'audit.export.e2e' -or $entry.revision -ne '1') {
            throw 'immudb readback did not match the PostgreSQL audit event.'
        }
        Write-Host 'PostgreSQL outbox -> Fleetory worker -> immudb readback passed.'
    }
}
finally {
    if ($null -ne $server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        $server.WaitForExit()
    }
    Remove-Item Env:FLEETORY_Fleetory__Secrets__Provider -ErrorAction SilentlyContinue
    Remove-Item Env:FLEETORY_Fleetory__Secrets__Address -ErrorAction SilentlyContinue
    Remove-Item Env:FLEETORY_Fleetory__Secrets__TokenDirectory -ErrorAction SilentlyContinue
    if ($AuditPipeline) {
        Remove-Item Env:FLEETORY_Fleetory__AuditExport__Enabled,Env:FLEETORY_Fleetory__AuditExport__Sink,Env:FLEETORY_Fleetory__AuditExport__Address,Env:FLEETORY_Fleetory__AuditExport__Username -ErrorAction SilentlyContinue
    }
}
