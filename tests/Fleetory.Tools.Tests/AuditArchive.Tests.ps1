#Requires -Version 7.3
# Real isolated PostgreSQL SELECT and Linux filesystem/CLI contracts; synthetic data only.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source (Join-Path $repo 'eng/verify-quality.ps1') -Names @()
$work = Join-Path $repo ('artifacts/audit-archive-' + [Guid]::NewGuid().ToString('N'))
$name = 'fleetory-audit-test-' + [Guid]::NewGuid().ToString('N')
$python = 'python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159'
$postgres = 'postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336'
$created = $false
$utf8 = [Text.UTF8Encoding]::new($false)

function Invoke-TestDocker([string[]] $Arguments) {
    $output = & docker @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Audit archive fixture Docker operation failed: ' + ($output -join "`n")) }
    return ($output -join "`n").Trim()
}

try {
    [void](New-Item -ItemType Directory -Path $work)
    foreach ($image in @($python, $postgres)) {
        & docker image inspect $image *> $null
        if ($LASTEXITCODE -ne 0) { $null = Invoke-TestDocker @('pull', $image) }
    }
    $null = Invoke-TestDocker @('run', '--detach', '--name', $name, '--network', 'none', '--memory', '256m',
        '--cpus', '0.50', '--tmpfs', '/var/lib/postgresql:rw,nosuid,size=96m',
        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', $postgres)
    $created = $true
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & docker exec $name pg_isready -U postgres *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Disposable audit database did not become ready.' }
    $sql = @'
CREATE SCHEMA platform;
CREATE TABLE platform.audit_events (
 event_id uuid PRIMARY KEY, actor_subject_id text NOT NULL, actor_kind integer NOT NULL,
 action text NOT NULL, target_type text, target_id text, correlation_id text NOT NULL,
 occurred_at timestamptz NOT NULL, recorded_at timestamptz NOT NULL, context_json jsonb,
 future_sensitive_column text DEFAULT 'fixture-private-future-column');
CREATE TABLE platform.audit_export_queue (audit_event_id uuid);
INSERT INTO platform.audit_events
 (event_id,actor_subject_id,actor_kind,action,correlation_id,occurred_at,recorded_at,context_json)
SELECT ('00000000-0000-4000-8000-' || lpad(i::text,12,'0'))::uuid,
 'fixture-owner',1,'fixture.audit','fixture-'||i,now(),now(),
 jsonb_build_object('message','Проверка 审计','value',(9007199254740991.0+i)::numeric)
FROM generate_series(1,2) i;
INSERT INTO platform.audit_export_queue SELECT event_id FROM platform.audit_events LIMIT 1;
'@
    $sql | & docker exec -i $name psql -X -q -U postgres -v ON_ERROR_STOP=1 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic audit initialization failed.' }
    $moduleBind = 'type=bind,source=' + (Join-Path $repo 'eng/pilot') + ',target=/tool,readonly'
    $query = Invoke-TestDocker @('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--mount', $moduleBind, $python, 'python', '-c', 'import sys;sys.path.insert(0,"/tool");import audit_archive;print(audit_archive.SQL)')
    $snapshot = $query | & docker exec -i -e 'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000' `
        $name psql -X -q -A -t -U postgres -v ON_ERROR_STOP=1 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Actual read-only audit SELECT failed.' }
    [IO.File]::WriteAllText((Join-Path $work 'snapshot.json'), ($snapshot -join "`n"), $utf8)
    $rewrite = "UPDATE platform.audit_events SET context_json=jsonb_set(context_json,'{value}','9007199254740993.0'::jsonb) WHERE event_id='00000000-0000-4000-8000-000000000001';"
    $null = Invoke-TestDocker @('exec', $name, 'psql', '-X', '-q', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', $rewrite)
    $rewritten = $query | & docker exec -i -e 'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000' `
        $name psql -X -q -A -t -U postgres -v ON_ERROR_STOP=1 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Actual rewritten-context SELECT failed.' }
    [IO.File]::WriteAllText((Join-Path $work 'rewritten.json'), ($rewritten -join "`n"), $utf8)
    & docker exec -e 'PGOPTIONS=-c default_transaction_read_only=on' $name psql -X -q -U postgres `
        -v ON_ERROR_STOP=1 -c 'DELETE FROM platform.audit_events;' *> $null
    if ($LASTEXITCODE -eq 0) { throw 'Fixture transaction unexpectedly permitted writes.' }
    $remaining = Invoke-TestDocker @('exec', $name, 'psql', '-X', '-q', '-A', '-t', '-U', 'postgres',
        '-c', 'SELECT count(*) FROM platform.audit_events;')
    if ($remaining -cne '2') { throw 'Read-only verification changed audit history.' }
    $bind = 'type=bind,source=' + $repo + ',target=/repo,readonly'
    $fixtureBind = 'type=bind,source=' + $work + ',target=/fixture,readonly'
    $output = Invoke-TestDocker @('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--cap-add', 'CHOWN', '--memory', '256m', '--cpus', '1',
        '--tmpfs', '/tmp:rw,nosuid,noexec,size=768m,mode=1777',
        '--tmpfs', '/lowspace:rw,nosuid,noexec,size=16m,mode=1777', '--mount', $bind, '--mount', $fixtureBind,
        '--tmpfs', '/srv:rw,nosuid,noexec,size=16m,mode=0755',
        '--tmpfs', '/etc/systemd:rw,nosuid,noexec,size=4m,mode=0755',
        '-e', 'ARCHIVE_SQL_FIXTURE=/fixture/snapshot.json', '-e', 'PYTHONDONTWRITEBYTECODE=1',
        '-e', 'PYTHONPATH=/repo/eng/pilot', $python, 'python', '/repo/tests/Fleetory.Tools.Tests/audit_archive_tests.py')
    Write-Output $output
    Write-Output 'AUDIT ARCHIVE TESTS PASS: real PostgreSQL read-only snapshot, explicit columns, archive continuity, private Linux files, concurrency and portable checkpoint restore; synthetic data only.'
}
finally {
    if ($created) { & docker rm -f -v $name *> $null }
    Remove-FleetoryTestArtifacts -Work $work -RepoRoot $repo
}
$global:LASTEXITCODE = 0
