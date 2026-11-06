#requires -Version 7.3
param([string]$Python='',[ValidateSet('none','after-stores')][string]$FailurePoint='none')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($helper in @('PilotNativeProcess.ps1','../../eng/pilot/ProviderRecoveryTransport.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1',
    '../../eng/pilot/PgDataRoundtripPolicy.ps1','PilotDisposableTls.ps1','NativeSignerFixture.ps1','NativeJournalFixture.ps1','NativeWorkerRuntime.ps1','NativePairFixture.ps1')){. (Join-Path $PSScriptRoot $helper)}
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if(-not $Python){$Python=(Get-Command $(if($IsLinux){'python3'}else{'python'})).Source}
$fixture=[Guid]::NewGuid().ToString('D');$root=Join-Path $repo ('artifacts/native-pg-v2-'+$fixture)
$state=@{Fixture=$fixture;Root=$root;Image='';ImageId=$null;PgImageId=$null;Sides=[Collections.Generic.List[object]]::new();Audits=[Collections.Generic.List[object]]::new();Canaries=[Collections.Generic.List[string]]::new();Tls=$null}
$watch=[Diagnostics.Stopwatch]::StartNew();$cleaning=$false;$stage='publish';$proof=$null;$restores=0;$lastClass='none'
$sqls=@{};$expected=@{};$captured=@{};$pins=@{}
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
    Assert-Pair ($cleaning -or $watch.Elapsed.TotalSeconds -lt 600) 'v2-deadline'
    $r=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments)) $InputBytes $TimeoutSeconds}else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    foreach($secret in $state.Canaries){Assert-Pair (-not ($r.Stdout+$r.Stderr).Contains($secret,[StringComparison]::Ordinal)) 'v2-canary'}
    $script:lastClass=if($r.Stderr -cmatch 'ERROR:\s+([A-Z0-9]{5})\b'){'sqlstate-'+$Matches[1]}elseif($r.Stderr -match 'certificate verify failed|certificate signature failure|provider signature failure|unable to get local issuer certificate'){'tls-chain'}else{'unclassified'}
    if(-not $AllowFailure){Assert-Pair ($r.ExitCode -eq 0) 'v2-docker'}
    return $r
}
. (Join-Path $PSScriptRoot 'NativePgV2Fixture.ps1')

try{
    $null=New-Item -ItemType Directory -Path $root
    $published=Publish-NativeProbe $repo 'ServerBackendProbe' $root
    $schema=Invoke-NativeBytes 'dotnet' @((Join-Path $published 'ServerBackendProbe.dll'),'restore-schema') -TimeoutSeconds 60
    Assert-Pair ($schema.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($schema.Stderr)) 'v2-offline-schema'
    $schema=$schema.Stdout|ConvertFrom-Json -AsHashtable
    Assert-Pair ($schema.databaseOpened -eq $false -and $schema.httpHostStarted -eq $false -and $schema.sql.Length -gt 0 -and $schema.sql.Length -le 131072) 'v2-schema-scope'
    foreach($database in @('fleetory','fleetory_signer')){
        $r=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/pg_inventory_v2.py'),'sql','--database',$database) -TimeoutSeconds 10
        Assert-Pair ($r.ExitCode -eq 0 -and $r.StdoutBytes.Length -le 131072 -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'v2-sql-generator'
        $sqls[$database]=$r.Stdout
    }
    $state.PgImageId=@((Invoke-Docker @('image','inspect',$script:nativeJournalImage)).Stdout|ConvertFrom-Json -AsHashtable)[0].Id
    $state.Tls=New-PilotDisposableTlsMaterial
    foreach($line in ($state.Tls.ServerPrivateKeyPem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$state.Canaries.Add($line.Substring(0,40))}}
    $source=New-PairSide $state 'source';$target=New-PairSide $state 'target'
    foreach($side in @($source,$target)){
        $side.Secrets.signer=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();$state.Canaries.Add($side.Secrets.signer)
        $null=V2-Sql $side 'postgres' ("CREATE ROLE fleetory_signer_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;CREATE ROLE fleetory_signer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+$side.Secrets.signer+"';")
        V2-NewDatabase $side 'fleetory_signer'
        Write-PairFile $state $side 'postgres' '/tmp/hba.conf' "local all postgres peer`nlocal all all reject`nhostssl fleetory fleetory_server 127.0.0.1/32 scram-sha-256`nhostssl fleetory_signer fleetory_signer 127.0.0.1/32 scram-sha-256`nhost all all 0.0.0.0/0 reject`nhost all all ::/0 reject`n"
        $null=Invoke-Docker @('exec',$side.Id,'pg_ctl','-D','/var/lib/postgresql/18/recovery','reload')
    }
    if($FailurePoint -ceq 'after-stores'){Write-Output 'V2 INJECTED FAILURE AFTER STORES';throw 'Intentional v2 fixture failure.'}
    $stage='seed'
    $null=V2-Sql $source 'fleetory' ("SET ROLE fleetory_migrator;`n"+$schema.sql+"`nRESET ROLE;`n"+(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'PgInventoryV2Seed.sql') -Raw))
    $null=V2-Sql $source 'fleetory_signer' ("SET ROLE fleetory_signer_owner;`n"+(Get-Content -LiteralPath (Join-Path $repo 'eng/provision-signing-journal.sql') -Raw)+"`nRESET ROLE;`n"+(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'PgInventoryV2SignerSeed.sql') -Raw))
    $stage='capture'
    foreach($database in @('fleetory','fleetory_signer')){
        $expected[$database]=V2-Read $source $database
        Assert-Pair ($expected[$database].generatedRolePolicyAccepted -eq $true -and $expected[$database].inventory.totalRows -eq $(if($database -ceq 'fleetory'){24}else{5})) 'v2-source-profile'
        Read-PairStore $state $source 'postgres'
        $dump=(Invoke-Docker @('exec',$source.Id,'pg_dump','-Fc','--compress=0','--no-password','-U','postgres','-d',$database)).StdoutBytes
        $pins[$database]=Get-PgDataHash $dump;Assert-PgDataPacket $dump $pins[$database]
        $captured[$database]=[byte[]]$dump.Clone();[Array]::Clear($dump)
        Assert-PgDataPacket $captured[$database] $pins[$database]
        V2-Same (V2-Read $source $database) $expected[$database]
        $list=Invoke-Docker (V2-RestoreArguments $database -List) $captured[$database]
        Assert-Pair ($list.Stdout -cmatch ('(?m)^;[ \t]+dbname: '+$database+'\r?$')) 'v2-native-format'
        $truncated=[byte[]]::new(64);[Array]::Copy($captured[$database],$truncated,64)
        $bad=Invoke-Docker (V2-RestoreArguments $database -List) $truncated -AllowFailure
        Assert-Pair ($bad.ExitCode -ne 0 -and $bad.Stderr -match '(?i)too short|could not read|end of file') 'v2-truncated-native-format'
    }
    $stage='atomic-refusal'
    $null=V2-Sql $target 'postgres' 'REVOKE CONNECT ON DATABASE fleetory FROM fleetory_server;DROP ROLE fleetory_server;'
    $bad=Invoke-Docker (V2-RestoreArguments 'fleetory') $captured.fleetory -AllowFailure
    Assert-Pair ($bad.ExitCode -ne 0 -and $bad.Stderr.Contains('role "fleetory_server" does not exist')) 'v2-missing-role-refused'
    Assert-Pair ((V2-Sql $target 'fleetory' "SELECT count(*) FROM pg_namespace WHERE nspname IN ('core','platform');").Stdout.Trim() -ceq '0') 'v2-atomic-rollback'
    $null=V2-Sql $target 'postgres' ("CREATE ROLE fleetory_server LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+$target.Secrets.database+"';")
    V2-Restore 'fleetory';V2-Restore 'fleetory_signer'
    $stage='legacy-mutations'
    $mutations=@(
        @{Sql="UPDATE platform.audit_events SET action='changed';";Undo='';Data=$true},
        @{Sql='ALTER TABLE core.devices DROP COLUMN display_name;';Undo='';Data=$false},
        @{Sql='REVOKE SELECT ON core.devices FROM fleetory_server;';Undo='';Data=$false},
        @{Sql='GRANT UPDATE(display_name) ON core.devices TO fleetory_server;';Undo='';Data=$false},
        @{Sql='SET ROLE fleetory_migrator;ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT UPDATE ON TABLES TO fleetory_server;RESET ROLE;';Undo='';Data=$false},
        @{Sql='ALTER TABLE core.devices OWNER TO fleetory_server;';Undo='';Data=$false},
        @{Sql='GRANT fleetory_migrator TO fleetory_server;';Undo='REVOKE fleetory_migrator FROM fleetory_server;';Data=$false},
        @{Sql='ALTER ROLE fleetory_server CREATEROLE;';Undo='ALTER ROLE fleetory_server NOCREATEROLE;';Data=$false}
    )
    foreach($mutation in $mutations){
        $null=V2-Sql $target 'fleetory' $mutation.Sql
        try{$changed=V2-Read $target 'fleetory';Assert-Pair ($changed.inventory.inventorySha256 -cne $expected.fleetory.inventory.inventorySha256) 'v2-mutation-detected';Assert-Pair (($changed.inventory.securitySha256 -ceq $expected.fleetory.inventory.securitySha256) -eq $mutation.Data) 'v2-security-scope'}
        finally{if($mutation.Undo){$null=V2-Sql $target 'fleetory' $mutation.Undo}}
        V2-Restore 'fleetory'
    }
    $stage='additional-mutations'
    $additional=@(
        @{Sql='ALTER ROLE fleetory_migrator LOGIN;';Undo='ALTER ROLE fleetory_migrator NOLOGIN;'},
        @{Sql='ALTER ROLE fleetory_server CONNECTION LIMIT 1;';Undo='ALTER ROLE fleetory_server CONNECTION LIMIT -1;'},
        @{Sql="ALTER ROLE fleetory_server SET search_path='public';";Undo='ALTER ROLE fleetory_server RESET search_path;'},
        @{Sql='CREATE ROLE fixture_v2_extra NOLOGIN;GRANT fleetory_server TO fixture_v2_extra;';Undo='REVOKE fleetory_server FROM fixture_v2_extra;DROP ROLE fixture_v2_extra;'},
        @{Sql="ALTER ROLE fleetory_server IN DATABASE fleetory SET statement_timeout='1s';";Undo='ALTER ROLE fleetory_server IN DATABASE fleetory RESET statement_timeout;'}
    )
    foreach($mutation in $additional){
        $null=V2-Sql $target 'fleetory' $mutation.Sql
        try{$changed=V2-Read $target 'fleetory';Assert-Pair ($changed.inventory.inventorySha256 -ceq $expected.fleetory.inventory.inventorySha256 -and $changed.inventory.securitySha256 -ceq $expected.fleetory.inventory.securitySha256 -and $changed.additionalSecuritySha256 -cne $expected.fleetory.additionalSecuritySha256 -and $changed.generatedRolePolicyAccepted -eq $false) 'v2-omission-covered'}
        finally{$null=V2-Sql $target 'fleetory' $mutation.Undo}
        V2-Same (V2-Read $target 'fleetory') $expected.fleetory
    }
    $stage='unsupported-refusal'
    $null=V2-Sql $target 'fleetory' 'CREATE FUNCTION public.fixture_v2_function() RETURNS integer LANGUAGE sql AS $$SELECT 1$$;'
    V2-Read $target 'fleetory' -Refusal
    $null=V2-Sql $target 'fleetory' 'DROP FUNCTION public.fixture_v2_function();'
    $stage='runtime'
    $wrong=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32));$state.Canaries.Add($wrong)
    $wrongCa=New-PilotDisposableTlsMaterial
    foreach($database in @('fleetory','fleetory_signer')){
        $password=if($database -ceq 'fleetory'){$target.Secrets.database}else{$target.Secrets.signer}
        $runtime=if($database -ceq 'fleetory'){'fleetory_server'}else{'fleetory_signer'}
        $query="SELECT jsonb_build_array(current_user,session_user,current_database(),(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()));"
        $r=V2-Runtime $database $password $query
        Assert-Pair ($r.ExitCode -eq 0 -and (($r.Stdout|ConvertFrom-Json)-join '|') -ceq ($runtime+'|'+$runtime+'|'+$database+'|True')) 'v2-runtime-tls-scram'
        $bad=V2-Runtime $database $wrong 'SELECT 1;';Assert-Pair ($bad.ExitCode -eq 2 -and $bad.Stderr -match '28P01|password authentication failed') 'v2-runtime-password'
        $bad=V2-Runtime $database $password 'SELECT 1;' 'disable';Assert-Pair ($bad.ExitCode -eq 2 -and $bad.Stderr -match 'no encryption|SSL off') 'v2-runtime-plaintext'
        Write-PairFile $state $target 'postgres' '/tmp/ca.pem' $wrongCa.RootCertificatePem
        try{
            $bad=V2-Runtime $database $password 'SELECT 1;'
            Assert-Pair ($bad.ExitCode -eq 2 -and $lastClass -ceq 'tls-chain') 'v2-runtime-ca'
        }
        finally{Write-PairFile $state $target 'postgres' '/tmp/ca.pem' $state.Tls.RootCertificatePem}
        $table=if($database -ceq 'fleetory'){'platform.audit_events'}else{'signer.signing_requests'}
        $bad=V2-Runtime $database $password ('DELETE FROM '+$table+';');Assert-Pair ($bad.ExitCode -eq 3 -and $bad.Stderr -match '\b42501\b') 'v2-runtime-delete'
        V2-Same (V2-Read $target $database) $expected[$database]
    }
    $stage='restart';Read-PairStore $state $target 'postgres'
    $null=Invoke-Docker @('exec',$target.Id,'pg_ctl','-D','/var/lib/postgresql/18/recovery','stop','-m','fast','-w','-t','15');Start-PairPostgres $state $target
    foreach($database in @('fleetory','fleetory_signer')){
        V2-Same (V2-Read $target $database) $expected[$database];V2-Same (V2-Read $source $database) $expected[$database]
        $password=if($database -ceq 'fleetory'){$target.Secrets.database}else{$target.Secrets.signer}
        $runtime=if($database -ceq 'fleetory'){'fleetory_server'}else{'fleetory_signer'}
        $r=V2-Runtime $database $password $query
        Assert-Pair ($r.ExitCode -eq 0 -and (($r.Stdout|ConvertFrom-Json)-join '|') -ceq ($runtime+'|'+$runtime+'|'+$database+'|True')) 'v2-restart-authentication'
    }
    $proof=@{schema='fleetory.native-pg-v2-fixture.v1';verified=$true;scope='generated PostgreSQL v2 profiles only';applicationTables=18;applicationRows=24;signerTables=4;signerRows=5;applicationRoles=4;legacyMutationDetections=$mutations.Count;historicalOmissionDetections=$additional.Count;unsupportedFunctionRefused=$true;nativeRestores=$restores;missingRoleAtomicRollback=$true;truncatedNativeFormatsRefused=2;runtimeTlsScramLogins=4;wrongPasswordRefusals=2;plaintextRefusals=2;wrongCaRefusals=2;runtimeDeleteDenials=2;restartAuthenticationVerified=$true;restartBothInventoriesUnchanged=$true;sourceObservedStable=$true;globalAtomicSnapshotClaimed=$false;sourceUnchanged=$true;capturedDumpBuffersFrozen=$true;originalInputsRead=$false;sourceVpsAccessed=$false;originalPkiOrProviderUsed=$false;sourcePasswordsRecovered=$false;serverStarted=$false;auditRestored=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false;untrustedArchiveSandboxVerified=$false}
}catch{
    if($_.Exception.Message -cmatch '^Native pair refused: ([a-z0-9-]{1,64})\z'){[Console]::Error.WriteLine('PostgreSQL v2 refusal category='+$Matches[1])}
    [Console]::Error.WriteLine('Generated PostgreSQL v2 fixture failed at '+$stage+'; type='+$_.Exception.GetType().Name+'; line='+$_.InvocationInfo.ScriptLineNumber+'; class='+$lastClass+'. No SQL, transcript, rows or credentials logged.')
    throw 'Generated PostgreSQL v2 fixture failed.'
}finally{
    $cleaning=$true;$failures=@()
    foreach($side in $state.Sides){try{
        $lookup=if($side.Id){$side.Id}else{$side.Name};$r=Invoke-Docker @('inspect',$lookup) -AllowFailure
        if($r.ExitCode -eq 0){if(-not $side.Id){$side.Id=@($r.Stdout|ConvertFrom-Json -AsHashtable)[0].Id};Read-PairStore $state $side 'postgres' -Cleanup;$null=Invoke-Docker @('rm','-f','-v',$side.Id);$r=Invoke-Docker @('inspect',$side.Id) -AllowFailure}
        Assert-Pair ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'v2-cleanup'
    }catch{$failures+='store'}}
    if(-not $failures.Count){try{Remove-NativePublicPayload $repo $root}catch{$failures+='payload'}}
    $state.Tls=$null;$state.Canaries.Clear();foreach($side in $state.Sides){$side.Secrets.Clear()};$captured.Clear();$dump=$null;$watch.Stop()
    if($failures.Count){throw 'Generated PostgreSQL v2 cleanup unverified; owned ledger retained.'}
    @{schema='fleetory.native-pg-v2-cleanup.v1';fixture=$fixture;ids=@($state.Sides|ForEach-Object {$_.Id});cleanupVerified=$true;originalInputsRead=$false}|ConvertTo-Json -Compress
}
if($FailurePoint -ceq 'none'){
    $fault=Invoke-NativeBytes ([Environment]::ProcessPath) @('-NoLogo','-NoProfile','-NonInteractive','-File',$PSCommandPath,'-Python',$Python,'-FailurePoint','after-stores') -TimeoutSeconds 120
    Assert-Pair ($fault.ExitCode -ne 0 -and $fault.Stdout.Contains('V2 INJECTED FAILURE AFTER STORES') -and $fault.Stderr.Contains('Generated PostgreSQL v2 fixture failed.')) 'v2-injected-exit'
    $records=@($fault.Stdout -split '\r?\n'|Where-Object {$_.StartsWith('{')}|ForEach-Object {$_|ConvertFrom-Json -AsHashtable}|Where-Object {$_.schema -ceq 'fleetory.native-pg-v2-cleanup.v1'})
    Assert-Pair ($records.Count -eq 1 -and $records[0].cleanupVerified -eq $true -and $records[0].originalInputsRead -eq $false -and @($records[0].ids).Count -eq 2 -and $records[0].fixture -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z') 'v2-fault-record'
    foreach($id in $records[0].ids){Assert-Pair ($id -cmatch '^[a-f0-9]{64}\z') 'v2-fault-id';$r=Invoke-Docker @('inspect',$id) -AllowFailure;Assert-Pair ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'v2-fault-absence'}
    Assert-Pair (-not (Test-Path -LiteralPath (Join-Path $repo ('artifacts/native-pg-v2-'+$records[0].fixture)))) 'v2-fault-payload'
    $proof.faultCleanupVerified=$true;$proof.faultCleanupContainers=2
}
$proof.cleanupVerified=$true;$proof|ConvertTo-Json -Compress -Depth 8
$global:LASTEXITCODE=0
