#requires -Version 7.3
param([string]$Python='',[ValidateSet('none','after-stores')][string]$FailurePoint='none')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'PgDataRoundtripPolicy.Tests.ps1')
foreach($helper in @('PilotNativeProcess.ps1','../../eng/pilot/ProviderRecoveryTransport.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1','NativeSignerFixture.ps1','NativeJournalFixture.ps1','NativeWorkerRuntime.ps1')){. (Join-Path $PSScriptRoot $helper)}
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if(-not $Python){$Python=(Get-Command $(if($IsLinux){'python3'}else{'python'})).Source}
$fixtureId=[Guid]::NewGuid().ToString('N')
$publicRoot=Join-Path $repo ('artifacts/native-pg-data-'+$fixtureId)
$stores=@();$imageId=$null;$proof=$null;$stage='publish';$cleaning=$false;$lastOperation='none';$lastExit=0;$lastClass='none';$watch=[Diagnostics.Stopwatch]::StartNew()
$passwords=@{source=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();target=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();wrong=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()}
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[switch]$AllowFailure){
    Assert-PgData ($cleaning -or $watch.Elapsed.TotalSeconds -lt 600) 'fixture-deadline'
    $r=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments)) $InputBytes 60}
        else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes 60}
    $script:lastOperation=$Arguments[0];$script:lastExit=$r.ExitCode;$script:lastClass='unclassified'
    foreach($kind in @('syntax error','does not exist','Permission denied','No such file','not running','not found','connection refused')){if($r.Stderr.Contains($kind)){$script:lastClass=$kind.Replace(' ','-');break}}
    if($r.Stderr -cmatch 'ERROR:\s+([0-9A-Z]{5})\b'){$script:lastClass='sqlstate-'+$Matches[1]}
    if($r.Stderr -cmatch 'LOCATION:\s+([A-Za-z0-9_]{1,64}),'){$script:lastClass+='-'+$Matches[1]}
    foreach($value in $passwords.Values){Assert-PgData (-not $r.Stdout.Contains($value) -and -not $r.Stderr.Contains($value)) 'credential-canary'}
    if(-not $AllowFailure){Assert-PgData ($r.ExitCode -eq 0) 'docker-operation'}
    return $r
}
function Owned($s,[switch]$Cleanup){
    $i=@((Invoke-Docker @('inspect',$s.Id)).Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-PgData ($i.Count -eq 1) 'store-inspection'
    Assert-NativeJournal $i[0] $s.Id $s.Session $imageId $s.Started -CleanupOnly:$Cleanup
}
function Sql($s,[string]$Database,[string]$Text,[switch]$AllowFailure){
    Assert-PgData ($Database -cin @('postgres','fleetory')) 'database'
    Owned $s
    return Invoke-Docker @('exec','-i',$s.Id,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',$Database) ([Text.Encoding]::UTF8.GetBytes("\set VERBOSITY verbose`n"+$Text)) -AllowFailure:$AllowFailure
}
function Ledger{
    $value=@{scope='owned fresh PostgreSQL fixtures only';imageId=$imageId;stage=$stage;stores=$stores}
    [IO.File]::WriteAllText((Join-Path $publicRoot 'owned-stores.json'),($value|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
}
function Start-Pg($s){
    Owned $s
    $null=Invoke-Docker @('exec','-d',$s.Id,'postgres','-D','/var/lib/postgresql/18/recovery','-c','listen_addresses=',
        '-c','unix_socket_directories=/var/run/postgresql','-c','hba_file=/tmp/hba.conf','-c','password_encryption=scram-sha-256',
        '-c','shared_buffers=32MB','-c','max_connections=15','-c','log_statement=none','-c','log_min_error_statement=panic')
    $ready=$false
    for($n=0;$n -lt 40;$n++){$r=Invoke-Docker @('exec',$s.Id,'pg_isready','-q','-U','postgres') -AllowFailure;if($r.ExitCode -eq 0){$ready=$true;break};Start-Sleep -Milliseconds 200}
    Assert-PgData $ready 'postgres-ready'
}
function New-Store([string]$Role){
    $session=[Guid]::NewGuid().ToString('D');$name='fleetory-native-journal-'+$session.Replace('-','')
    $missing=Invoke-Docker @('inspect',$name) -AllowFailure
    Assert-PgData ($missing.ExitCode -ne 0 -and ($missing.Stderr+$missing.Stdout) -match '(?i)no such (object|container)') 'fresh-store-name'
    $s=@{Id=$null;Session=$session;Started=[DateTimeOffset]::UtcNow;Claimed=$true;Role=$Role;Name=$name}
    $script:stores+=,$s
    Ledger
    $s.Id=(Invoke-Docker (Get-NativeJournalArguments $session)).Stdout.Trim();Ledger;Owned $s
    $null=Invoke-Docker @('exec',$s.Id,'initdb','-D','/var/lib/postgresql/18/recovery','--auth-local=peer','--auth-host=reject','--no-instructions')
    $hba="local all postgres peer`nlocal fleetory fleetory_server scram-sha-256`nlocal all all reject`nhost all all 0.0.0.0/0 reject`nhost all all ::/0 reject`n"
    $null=Invoke-Docker @('exec','-i',$s.Id,'/bin/sh','-c','umask 077; cat > /tmp/hba.conf') ([Text.Encoding]::UTF8.GetBytes($hba))
    Start-Pg $s
    $null=Sql $s 'postgres' ("SET password_encryption='scram-sha-256';CREATE ROLE fleetory_migrator NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;CREATE ROLE fleetory_server LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '"+$passwords[$Role]+"';")
    New-Database $s
    return $s
}
function New-Database($s){
    $null=Sql $s 'postgres' 'CREATE DATABASE fleetory OWNER fleetory_migrator;REVOKE ALL ON DATABASE fleetory FROM PUBLIC;GRANT CONNECT ON DATABASE fleetory TO fleetory_server;'
}
function Inventory($s){return Read-PgDataInventory (Sql $s 'fleetory' $script:inventorySql).StdoutBytes}
function Restore-Target{
    $null=Sql $target 'postgres' 'DROP DATABASE fleetory;'
    New-Database $target
    Owned $target
    $r=Invoke-Docker (Get-PgDataRestoreArguments $target.Id) $script:captured
    Assert-PgData ([string]::IsNullOrWhiteSpace($r.Stdout) -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'quiet-restore'
    $actual=Inventory $target
    Assert-PgData ($actual.Sha256 -ceq $script:expected.Sha256) 'restored-inventory'
    $script:restores++
}
function Runtime([string]$Password,[string]$Query){
    Owned $target
    $value='localhost:5432:fleetory:fleetory_server:'+$Password+"`n"
    $null=Invoke-Docker @('exec','-i',$target.Id,'/bin/sh','-c','umask 077; cat > /tmp/pgpass; chmod 0600 /tmp/pgpass') ([Text.Encoding]::UTF8.GetBytes($value))
    Assert-PgData ((Invoke-Docker @('exec',$target.Id,'stat','-c','%a:%u:%h','/tmp/pgpass')).Stdout.Trim() -ceq '600:999:1') 'password-slot'
    return Invoke-Docker @('exec','-i','-e','PGPASSFILE=/tmp/pgpass','-e','PGCONNECT_TIMEOUT=3',$target.Id,'psql','-XqAt','-w','-v','ON_ERROR_STOP=1','-U','fleetory_server','-h','/var/run/postgresql','-d','fleetory') ([Text.Encoding]::UTF8.GetBytes("\set VERBOSITY sqlstate`n"+$Query)) -AllowFailure
}
try{
    $null=New-Item -ItemType Directory -Path $publicRoot
    $published=Publish-NativeProbe $repo 'ServerBackendProbe' $publicRoot
    $schemaResult=Invoke-NativeBytes 'dotnet' @((Join-Path $published 'ServerBackendProbe.dll'),'restore-schema') -TimeoutSeconds 60
    Assert-PgData ($schemaResult.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($schemaResult.Stderr)) 'offline-schema'
    $schema=$schemaResult.Stdout|ConvertFrom-Json -AsHashtable
    Assert-PgData ($schema.category -ceq 'restore-schema' -and $schema.databaseOpened -eq $false -and $schema.httpHostStarted -eq $false -and $schema.issuerActivated -eq $false -and $schema.sql.Length -gt 0 -and $schema.sql.Length -le 131072) 'offline-schema-scope'
    $stage='stores'
    $image=@((Invoke-Docker @('image','inspect',$script:nativeJournalImage)).Stdout|ConvertFrom-Json -AsHashtable)[0];$imageId=[string]$image.Id
    $source=New-Store 'source';$target=New-Store 'target'
    if($FailurePoint -ceq 'after-stores'){
        Write-Output 'PG DATA INJECTED FAILURE AFTER STORES'
        throw 'Intentional fresh PostgreSQL fixture failure.'
    }
    $seed=@'
INSERT INTO core.devices(device_id,display_name,updated_at) VALUES(gen_random_uuid(),'synthetic-device-one','2026-01-01Z'),(gen_random_uuid(),'synthetic-device-two','2026-01-02Z');
INSERT INTO platform.person_projections(person_id,display_name,updated_at) VALUES(gen_random_uuid(),'synthetic-person-one','2026-01-01Z'),(gen_random_uuid(),'synthetic-person-two','2026-01-02Z');
INSERT INTO platform.audit_events(event_id,actor_subject_id,actor_kind,action,correlation_id,occurred_at,recorded_at,context_json) SELECT gen_random_uuid(),'fixture:nonempty',1,'Fixture.Read.'||n,'fixture-'||n,'2026-01-01Z','2026-01-01Z','{"fixture":"not-approval"}'::jsonb FROM generate_series(1,4) n;
ALTER DEFAULT PRIVILEGES IN SCHEMA core,platform GRANT SELECT ON TABLES TO fleetory_server;
RESET ROLE;
GRANT USAGE ON SCHEMA core,platform TO fleetory_server;
GRANT SELECT ON ALL TABLES IN SCHEMA core,platform TO fleetory_server;
GRANT SELECT(display_name) ON core.devices TO fleetory_server;
GRANT INSERT ON platform.audit_events TO fleetory_server;
'@
    $stage='schema-seed';$null=Sql $source 'fleetory' ("SET ROLE fleetory_migrator;`n"+$schema.sql+"`n"+$seed)
    $script:inventorySql=Get-Content -LiteralPath (Join-Path $repo 'eng/pilot/server_pg_inventory.sql') -Raw
    $stage='source-inventory';$script:expected=Inventory $source
    $stage='capture';Owned $source
    $dump=(Invoke-Docker @('exec',$source.Id,'pg_dump','-Fc','--compress=0','--no-password','-U','postgres','-d','fleetory')).StdoutBytes
    $pin=Get-PgDataHash $dump;Assert-PgDataPacket $dump $pin
    Assert-PgData ((Inventory $source).Sha256 -ceq $expected.Sha256) 'stable-source-window'
    $capture=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'generated_pg_capture.py')) $dump 30
    Assert-PgData ($capture.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($capture.Stderr)) 'capsule-transport'
    $c=$capture.Stdout|ConvertFrom-Json -AsHashtable
    Assert-PgData ($c.schema -ceq 'fleetory.generated-pg-capture.v1' -and $c.sourceReplacementRejected -eq $true -and $c.capturedBytesSurviveReplacement -eq $true -and $c.componentReportsAreSyntheticFixtures -eq $true -and $c.originalInventoryV2Verified -eq $false -and $c.auditBackupRestored -eq $false) 'capsule-scope'
    $script:captured=[Convert]::FromBase64String($c.dumpBase64);Assert-PgDataPacket $captured $pin
    Assert-PgData ($c.dumpSha256 -ceq $pin -and $captured.Length -eq $dump.Length) 'captured-equality'
    $stage='native-format';Owned $target
    $list=Invoke-Docker (Get-PgDataRestoreArguments $target.Id -List) $captured
    Assert-PgData ($list.StdoutBytes.Length -le 65536 -and $list.Stdout -cmatch '(?m)^;[ \t]+dbname: fleetory\r?$') 'native-format-list'
    $truncated=[byte[]]::new(64);[Array]::Copy($captured,$truncated,64)
    $bad=Invoke-Docker (Get-PgDataRestoreArguments $target.Id -List) $truncated -AllowFailure
    Assert-PgData ($bad.ExitCode -ne 0 -and $bad.Stderr -match '(?i)too short|could not read|end of file') 'truncated-native-format'
    $stage='atomic-refusal'
    $null=Sql $target 'postgres' 'REVOKE ALL ON DATABASE fleetory FROM fleetory_server;DROP ROLE fleetory_server;'
    $bad=Invoke-Docker (Get-PgDataRestoreArguments $target.Id) $captured -AllowFailure
    Assert-PgData ($bad.ExitCode -ne 0 -and $bad.Stderr -match 'role "fleetory_server" does not exist') 'missing-role-restore-refusal'
    Assert-PgData ((Sql $target 'fleetory' "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('core','platform');").Stdout.Trim() -ceq '0') 'atomic-rollback'
    $null=Sql $target 'postgres' ("CREATE ROLE fleetory_server LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '"+$passwords.target+"';")
    $script:restores=0;Restore-Target
    $stage='readback'
    $readSql="SELECT jsonb_build_array(current_user,session_user,current_database(),(SELECT count(*) FROM core.devices),(SELECT count(*) FROM platform.person_projections),(SELECT count(*) FROM platform.audit_events),(SELECT count(*) FROM platform.audit_export_queue));"
    $read=Runtime $passwords.target $readSql
    Assert-PgData ($read.ExitCode -eq 0 -and (($read.Stdout|ConvertFrom-Json) -join '|') -ceq 'fleetory_server|fleetory_server|fleetory|2|2|4|0') 'runtime-readback'
    $bad=Runtime $passwords.wrong 'SELECT 1;'
    Assert-PgData ($bad.ExitCode -eq 2 -and $bad.Stderr -match 'password authentication failed') 'wrong-password'
    $bad=Runtime $passwords.target 'DELETE FROM platform.audit_events;'
    Assert-PgData ($bad.ExitCode -eq 3 -and $bad.Stderr -match 'ERROR:\s+42501\b') 'append-only-runtime'
    $mutations=@(
        @{Name='row';Sql="UPDATE platform.audit_events SET action='tampered';";Undo=''},
        @{Name='column';Sql='ALTER TABLE core.devices DROP COLUMN display_name;';Undo=''},
        @{Name='table-acl';Sql='REVOKE SELECT ON core.devices FROM fleetory_server;';Undo=''},
        @{Name='column-acl';Sql='GRANT UPDATE(display_name) ON core.devices TO fleetory_server;';Undo=''},
        @{Name='default-acl';Sql='SET ROLE fleetory_migrator;ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT UPDATE ON TABLES TO fleetory_server;RESET ROLE;';Undo=''},
        @{Name='owner';Sql='ALTER TABLE core.devices OWNER TO fleetory_server;';Undo=''},
        @{Name='membership';Sql='GRANT fleetory_migrator TO fleetory_server;';Undo='REVOKE fleetory_migrator FROM fleetory_server;'},
        @{Name='role-capability';Sql='ALTER ROLE fleetory_server CREATEROLE;';Undo='ALTER ROLE fleetory_server NOCREATEROLE;'}
    )
    $stage='mutations'
    foreach($m in $mutations){
        $null=Sql $target 'fleetory' $m.Sql
        try{
            $changed=Inventory $target
            Assert-PgData ($changed.Sha256 -cne $expected.Sha256) ('undetected-'+$m.Name)
            if($m.Name -ceq 'row'){Assert-PgData ($changed.Catalog -ceq $expected.Catalog -and $changed.Rows -eq $expected.Rows) 'same-count-row-detection'}
            else{Assert-PgData ($changed.Catalog -cne $expected.Catalog) ('catalog-'+$m.Name)}
        }finally{if($m.Undo){$null=Sql $target 'fleetory' $m.Undo}}
        Restore-Target
    }
    $stage='restart';Owned $target
    $null=Invoke-Docker @('exec',$target.Id,'pg_ctl','-D','/var/lib/postgresql/18/recovery','stop','-m','fast','-w','-t','15')
    Start-Pg $target
    Assert-PgData ((Inventory $target).Sha256 -ceq $expected.Sha256) 'restart-inventory'
    $read=Runtime $passwords.target $readSql;Assert-PgData ($read.ExitCode -eq 0 -and (($read.Stdout|ConvertFrom-Json) -join '|') -ceq 'fleetory_server|fleetory_server|fleetory|2|2|4|0') 'restart-runtime-readback'
    Assert-PgData ((Inventory $source).Sha256 -ceq $expected.Sha256) 'source-unchanged'
    $proof=[ordered]@{schema='fleetory.native-pg-data-roundtrip.v1';verified=$true;scope='fresh PostgreSQL application-schema fixture only';inventoryAlgorithm='fleetory.server-pg-roundtrip.v1';tables=18;rows=$expected.Rows;dumpBytes=$captured.Length;dumpSha256=$pin;inventorySha256=$expected.Sha256;currentSchemaSqlSha256=Get-PgDataHash ([Text.Encoding]::UTF8.GetBytes($schema.sql));sourceWindowStable=$true;sourceUnchanged=$true;capturedBytesSurviveSourceReplacement=$true;schemaDataOwnersTableColumnAndDefaultAclsMatched=$true;roleCapabilitiesMembershipsAndDatabaseAclsMatched=$true;mutationRefusals=$mutations.Count;nativeTruncationRefused=$true;lateAclFailureRolledBackAtomically=$true;runtimeReadbackSessions=2;runtimeWrongPasswordRefused=$true;runtimeDeleteDenied42501=$true;coldRestores=$restores;restartPreservedInventoryAndLogin=$true;clusterRolesAndDatabaseBootstrapRecreated=$true;originalInventoryV2Verified=$false;componentReportsAreSyntheticFixtures=$true;auditBackupRestored=$false;serverStarted=$false;originalInputsRead=$false;sourceVpsAccessed=$false;originalPkiOrProviderUsed=$false;sourcePasswordsRecovered=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}catch{
    if($_.Exception.Message -cmatch '^(?:PostgreSQL data|Native signer) fixture refused: ([a-z0-9-]{1,64})\z'){[Console]::Error.WriteLine('Native PostgreSQL category='+$Matches[1]+'; operation='+$lastOperation+';exit='+$lastExit+';class='+$lastClass)}
    [Console]::Error.WriteLine('Native PostgreSQL data fixture failed at '+$stage+'; type='+$_.Exception.GetType().Name+'; line='+$_.InvocationInfo.ScriptLineNumber+'. No SQL, dump, credential or table contents logged.')
    throw 'Native PostgreSQL data roundtrip failed.'
}finally{
    $cleaning=$true
    $failures=@()
    foreach($s in $stores){try{if($s.Claimed){$lookup=if($s.Id){$s.Id}else{$s.Name};$r=Invoke-Docker @('inspect',$lookup) -AllowFailure;if($r.ExitCode -eq 0){if(-not $s.Id){$s.Id=@($r.Stdout|ConvertFrom-Json -AsHashtable)[0].Id};Owned $s -Cleanup;$null=Invoke-Docker @('rm','-f','-v',$s.Id);$r=Invoke-Docker @('inspect',$s.Id) -AllowFailure};Assert-PgData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'cleanup-absence'}}catch{$failures+='store'}}
    if(-not $failures.Count){try{Remove-NativePublicPayload $repo $publicRoot}catch{$failures+='public-payload'}}
    $passwords.Clear();$dump=$captured=$capture=$c=$null;$watch.Stop()
    if($failures.Count){throw 'Native PostgreSQL owned cleanup unverified.'}
    @{schema='fleetory.native-pg-cleanup.v1';fixtureId=$fixtureId;ids=@($stores|ForEach-Object {$_.Id});cleanupVerified=$true;originalInputsRead=$false}|ConvertTo-Json -Depth 4 -Compress
}
if($FailurePoint -ceq 'none'){
    $fault=Invoke-NativeBytes ([Environment]::ProcessPath) @('-NoLogo','-NoProfile','-NonInteractive','-File',$PSCommandPath,'-Python',$Python,'-FailurePoint','after-stores') -TimeoutSeconds 120
    Assert-PgData ($fault.ExitCode -ne 0 -and $fault.Stdout.Contains('PG DATA INJECTED FAILURE AFTER STORES') -and $fault.Stderr.Contains('Native PostgreSQL data roundtrip failed.')) 'fault-injected-exit'
    # Hashtable serialization order is not an identity; select by parsed schema.
    $cleanups=@($fault.Stdout -split '\r?\n'|Where-Object {$_.StartsWith('{')}|ForEach-Object {$_|ConvertFrom-Json -AsHashtable}|Where-Object {$_.schema -ceq 'fleetory.native-pg-cleanup.v1'})
    Assert-PgData ($cleanups.Count -eq 1 -and $cleanups[0].cleanupVerified -eq $true -and $cleanups[0].originalInputsRead -eq $false -and $cleanups[0].fixtureId -cmatch '^[a-f0-9]{32}\z' -and @($cleanups[0].ids).Count -eq 2) 'fault-cleanup-record'
    foreach($id in $cleanups[0].ids){
        Assert-PgData ($id -cmatch '^[a-f0-9]{64}\z') 'fault-owned-id'
        $gone=Invoke-Docker @('inspect',$id) -AllowFailure
        Assert-PgData ($gone.ExitCode -ne 0 -and ($gone.Stderr+$gone.Stdout) -match '(?i)no such (object|container)') 'fault-owned-absence'
    }
    Assert-PgData (-not (Test-Path -LiteralPath (Join-Path $repo ('artifacts/native-pg-data-'+$cleanups[0].fixtureId)))) 'fault-payload-absence'
    $proof.faultCleanupVerified=$true;$proof.faultCleanupContainers=2
}
$proof.cleanupVerified=$true;$proof|ConvertTo-Json -Depth 8 -Compress -WarningAction Stop
$global:LASTEXITCODE=0
