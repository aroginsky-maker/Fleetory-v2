#requires -Version 7.3
param([string]$Python='',[ValidateSet('none','after-stores')][string]$FailurePoint='none',[ValidateSet('legacy','v2')][string]$Profile='legacy')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($helper in @('PilotNativeProcess.ps1','../../eng/pilot/ProviderRecoveryTransport.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1',
    '../../eng/pilot/PgDataRoundtripPolicy.ps1','../../eng/pilot/ImmuDataRoundtripPolicy.ps1','PilotDisposableTls.ps1',
    'NativeSignerFixture.ps1','NativeJournalFixture.ps1','NativeAuditFixture.ps1','NativeWorkerRuntime.ps1','NativePairFixture.ps1','NativePgV2Fixture.ps1','NativeV2PairWorkflow.ps1')){. (Join-Path $PSScriptRoot $helper)}
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if(-not $Python){$Python=(Get-Command $(if($IsLinux){'python3'}else{'python'})).Source}
$fixture=[Guid]::NewGuid().ToString('D');$root=Join-Path $repo ('artifacts/native-pair-'+$fixture)
$state=@{Fixture=$fixture;Root=$root;Image=('fleetory-native-pair-'+$fixture.Replace('-','')+':fixture');ImageId=$null;PgImageId=$null;ProbeHash=$null;
    Sides=[Collections.Generic.List[object]]::new();Audits=[Collections.Generic.List[object]]::new();Canaries=[Collections.Generic.List[string]]::new();Tls=$null;GatewayTls=@{};SigningPem=$null}
$watch=[Diagnostics.Stopwatch]::StartNew();$cleaning=$false;$imageClaimed=$false;$stage='publish';$proof=$null;$lastClass='none';$lastExit=0
$oldBuildKit=$env:DOCKER_BUILDKIT;$env:DOCKER_BUILDKIT='0'
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
    Assert-Pair ($cleaning -or $watch.Elapsed.TotalSeconds -lt 600) 'fixture-deadline'
    $result=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments -ClassicBuilder:($Arguments[0] -ceq 'build'))) $InputBytes $TimeoutSeconds}
        else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    $script:lastExit=$result.ExitCode;$script:lastClass='unclassified'
    foreach($kind in @('syntax error','does not exist','permission denied','no such file','authentication failed','connection refused')){if(($result.Stdout+$result.Stderr).Contains($kind,[StringComparison]::OrdinalIgnoreCase)){$script:lastClass=$kind.Replace(' ','-');break}}
    if($result.Stderr -cmatch 'ERROR:\s+([A-Z0-9]{5})\b'){$script:lastClass='sqlstate-'+$Matches[1]}
    foreach($secret in $state.Canaries){Assert-Pair (-not ($result.Stdout+$result.Stderr).Contains($secret,[StringComparison]::Ordinal)) 'credential-canary'}
    if(-not $AllowFailure){Assert-Pair ($result.ExitCode -eq 0) 'docker-operation'}
    return $result
}
function Pg-Inventory($Side){return Read-PgDataInventory (Pair-Sql $state $Side 'fleetory' $script:inventorySql).StdoutBytes}
function Get-PairPoint($Side){
    $v=Invoke-PairProbe $state $Side 'pair-read'
    Assert-Pair ($v.fixture -ceq $fixture -and $v.eventCount -eq 4 -and $v.fieldsPerEvent -eq 10 -and $v.queueRows -eq 0 -and
        $v.postgresRuntimeTlsVerified -eq $true -and $v.nativeSinkSerializationVerified -eq $true -and $v.eventsSha256 -cmatch '^[a-f0-9]{64}\z') 'pair-readback'
    $receipt=New-ImmudbStateReceipt $v.state 'fleetoryaudit' (Join-Path $root 'state-public.pem')
    Assert-Pair ($receipt.txId -eq 4) 'audit-transactions'
    return [ordered]@{eventsSha256=$v.eventsSha256;auditTx=4;auditHash=[Convert]::ToHexString([Convert]::FromBase64String($receipt.txHash));
        auditKeyFingerprint=$receipt.publicKeySha256;tables=18;rows=23;queueRows=0;events=4;fields=10}
}
function Same-Point($Actual,$Expected){Assert-Pair (($Actual|ConvertTo-Json -Depth 6 -Compress) -ceq ($Expected|ConvertTo-Json -Depth 6 -Compress)) 'signed-pair-point'}
function Restore-Pg{
    $null=Pair-Sql $state $target 'postgres' 'DROP DATABASE fleetory;'
    New-PairDatabase $state $target
    Read-PairStore $state $target 'postgres'
    $null=Invoke-Docker (Get-PgDataRestoreArguments $target.Id) $script:pgCaptured
    Assert-Pair ((Pg-Inventory $target).Sha256 -ceq $script:sourceInventory.Sha256) 'native-postgres-inventory'
    $script:pgRestores++
}
function Restore-Audit{
    Read-PairStore $state $target.Audit 'audit'
    $null=Invoke-Docker (Get-ImmuDataCliArguments $target.Audit.Id 'verify') $script:auditCaptured
    $null=Invoke-Docker (Get-ImmuDataCliArguments $target.Audit.Id 'restore') $script:auditCaptured
    $null=Invoke-PairProbe $state $target 'pair-users'
    Write-PairHostFiles $state $target
    $script:auditRestores++
}
try{
    $null=New-Item -ItemType Directory -Path $root
    $published=Publish-NativeProbe $repo 'ServerBackendProbe' $root
    $state.ProbeHash=(Get-FileHash -LiteralPath (Join-Path $published 'ServerBackendProbe.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
    $offline=Invoke-NativeBytes 'dotnet' @((Join-Path $published 'ServerBackendProbe.dll'),'restore-schema') -TimeoutSeconds 60
    Assert-Pair ($offline.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($offline.Stderr)) 'offline-schema'
    $schema=$offline.Stdout|ConvertFrom-Json -AsHashtable
    Assert-Pair ($schema.category -ceq 'restore-schema' -and $schema.databaseOpened -eq $false -and $schema.sql.Length -gt 0 -and $schema.sql.Length -le 131072) 'offline-schema-profile'
    $cliImage='codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'
    $stage='build'
    foreach($image in @($cliImage,$script:nativeAuditSourceImage,$script:nativeSignerImage,$script:nativeJournalImage)){
        $r=Invoke-Docker @('image','inspect',$image) -AllowFailure
        if($r.ExitCode -ne 0){$null=Invoke-Docker @('pull',$image) -TimeoutSeconds 120}
    }
    $state.PgImageId=@((Invoke-Docker @('image','inspect',$script:nativeJournalImage)).Stdout|ConvertFrom-Json -AsHashtable)[0].Id
    $absent=Invoke-Docker @('image','inspect',$state.Image) -AllowFailure
    Assert-Pair ($absent.ExitCode -ne 0 -and ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|image)') 'fresh-build-name'
    $imageClaimed=$true
    $dockerfile="FROM $($script:nativeAuditSourceImage) AS upstream`nFROM $cliImage AS cli`nFROM $($script:nativeSignerImage)`nCOPY --from=upstream /usr/sbin/immudb /usr/sbin/immudb`nCOPY --from=cli /usr/local/bin/immuadmin /usr/local/bin/immuadmin`nCOPY publish/ /tool/`nLABEL fleetory.native-pair.build=$fixture`nUSER 3322:3322`n"
    [IO.File]::WriteAllText((Join-Path $root 'Dockerfile'),$dockerfile,[Text.UTF8Encoding]::new($false))
    $public=Invoke-NativeBytes 'tar' @('-cf','-','-C',$root,'Dockerfile','publish') -TimeoutSeconds 60
    Assert-Pair ($public.ExitCode -eq 0 -and $public.StdoutBytes.Length -gt 0 -and $public.StdoutBytes.Length -le 16777216) 'public-build-context'
    $null=Invoke-Docker @('build','--network','none','--pull=false','--tag',$state.Image,'-') $public.StdoutBytes -TimeoutSeconds 120
    $public=$null
    $built=@((Invoke-Docker @('image','inspect',$state.Image)).Stdout|ConvertFrom-Json -AsHashtable)
    Assert-Pair ($built.Count -eq 1 -and $built[0].Config.Labels['fleetory.native-pair.build'] -ceq $fixture) 'build-identity';$state.ImageId=$built[0].Id
    $state.Tls=New-PilotDisposableTlsMaterial -IncludeClient
    foreach($role in @('agent','admin')){$state.GatewayTls[$role]=New-PilotDisposableTlsMaterial}
    if($Profile -ceq 'v2'){
        $state.SigningPems=@{}
        foreach($role in @('source','target')){
            $key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
            try{$state.SigningPems[$role]=$key.ExportECPrivateKeyPem();[IO.File]::WriteAllText((Join-Path $root ($role+'-public.pem')),$key.ExportSubjectPublicKeyInfoPem(),[Text.UTF8Encoding]::new($false))}finally{$key.Dispose()}
        }
    }else{
    $key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    try{$state.SigningPem=$key.ExportECPrivateKeyPem();[IO.File]::WriteAllText((Join-Path $root 'state-public.pem'),$key.ExportSubjectPublicKeyInfoPem(),[Text.UTF8Encoding]::new($false))}finally{$key.Dispose()}
    }
    foreach($pem in @($state.Tls.ServerPrivateKeyPem,$state.Tls.ClientPrivateKeyPem,$state.SigningPem,$state.GatewayTls.agent.ServerPrivateKeyPem,$state.GatewayTls.admin.ServerPrivateKeyPem)){foreach($line in ($pem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$state.Canaries.Add($line.Substring(0,40))}}}
    if($Profile -ceq 'v2'){foreach($pem in $state.SigningPems.Values){foreach($line in ($pem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$state.Canaries.Add($line.Substring(0,40))}}}}
    . (Join-Path $repo 'eng/verify-immudb-state.ps1') -Address 'https://127.0.0.1:8090' -PublicKeyPath (Join-Path $root 'state-public.pem') -AnchorPath (Join-Path $root 'unused-anchor')
    $stage='stores';$source=New-PairSide $state 'source';$target=New-PairSide $state 'target'
    New-PairAudit $state $source;New-PairAudit $state $target
    if($FailurePoint -ceq 'after-stores'){Write-Output 'PAIR INJECTED FAILURE AFTER STORES';throw 'Intentional fresh pair failure.'}
    if($Profile -ceq 'v2'){$proof=Invoke-V2PairWorkflow}else{
    $stage='seed'
    $grants='RESET ROLE;GRANT USAGE ON SCHEMA core,platform TO fleetory_server;GRANT SELECT ON ALL TABLES IN SCHEMA core,platform TO fleetory_server;GRANT INSERT ON platform.audit_events,platform.audit_export_queue TO fleetory_server;GRANT UPDATE,DELETE ON platform.audit_export_queue TO fleetory_server;'
    $null=Pair-Sql $state $source 'fleetory' ("SET ROLE fleetory_migrator;`n"+$schema.sql+"`n"+$grants)
    $seed=Invoke-PairProbe $state $source 'pair-seed-sql'
    Assert-Pair ($seed.fixture -ceq $fixture -and $seed.sql.Length -gt 0 -and $seed.sql.Length -le 16384 -and @($seed.eventIds).Count -eq 4) 'coherent-model'
    $null=Pair-Sql $state $source 'fleetory' $seed.sql
    $null=Invoke-PairProbe $state $source 'audit-prepare';$null=Invoke-PairProbe $state $source 'pair-publish'
    $script:inventorySql=Get-Content -LiteralPath (Join-Path $repo 'eng/pilot/server_pg_inventory.sql') -Raw
    $script:sourceInventory=Pg-Inventory $source
    $before=Get-PairPoint $source
    $stage='capture';Read-PairStore $state $source 'postgres';Read-PairStore $state $source.Audit 'audit'
    $pg=(Invoke-Docker @('exec',$source.Id,'pg_dump','-Fc','--compress=0','--no-password','-U','postgres','-d','fleetory')).StdoutBytes
    $audit=(Invoke-Docker (Get-ImmuDataCliArguments $source.Audit.Id 'backup')).StdoutBytes
    $pgPin=Get-PgDataHash $pg;$auditPin=Get-ImmuDataHash $audit
    Assert-PgDataPacket $pg $pgPin;Assert-ImmuDataPacket $audit $auditPin
    $after=Get-PairPoint $source;Same-Point $after $before
    Assert-Pair ((Pg-Inventory $source).Sha256 -ceq $sourceInventory.Sha256) 'observed-stable-postgres'
    $manifest=[ordered]@{schema='fleetory.fresh-native-server-pair.v1';scope='generated-only-no-original-approval';fixture=$fixture;probeSha256=$state.ProbeHash;
        images=@{postgres=$state.PgImageId;audit=$state.ImageId};sourceContainers=@{postgres=$source.Id;audit=$source.Audit.Id};postgresInventorySha256=$sourceInventory.Sha256;
        point=$before;capture=@{before=$before;after=$after};artifacts=@{postgres=@{bytes=$pg.Length;sha256=$pgPin};audit=@{bytes=$audit.Length;sha256=$auditPin}}}
    $manifestBytes=[Text.Encoding]::UTF8.GetBytes(($manifest|ConvertTo-Json -Depth 12 -Compress));$manifestPin=Get-PgDataHash $manifestBytes
    $packet=[Text.Encoding]::UTF8.GetBytes((@{manifestBase64=[Convert]::ToBase64String($manifestBytes);postgresBase64=[Convert]::ToBase64String($pg);auditBase64=[Convert]::ToBase64String($audit)}|ConvertTo-Json -Compress))
    $capture=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/fresh_server_pair.py'),'--pin',$manifestPin,'--fixture',$fixture) $packet 30
    Assert-Pair ($capture.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($capture.Stderr)) 'pair-admission'
    $captured=$capture.Stdout|ConvertFrom-Json -AsHashtable
    Assert-Pair ($captured.schema -ceq $manifest.schema -and $captured.fixture -ceq $fixture -and $captured.manifestSha256 -ceq $manifestPin -and
        $captured.generatedOnly -eq $true -and $captured.externalApprovalVerified -eq $false -and $captured.originalInventoryV2Verified -eq $false) 'pair-admission-scope'
    $script:pgCaptured=[Convert]::FromBase64String($captured.postgresBase64);$script:auditCaptured=[Convert]::FromBase64String($captured.auditBase64)
    Assert-PgDataPacket $pgCaptured $pgPin;Assert-ImmuDataPacket $auditCaptured $auditPin
    # Destroy the caller's source arrays. Restore may consume only the two captured packets.
    [Array]::Clear($pg);[Array]::Clear($audit);$packet=$capture=$captured=$null
    $stage='restore';$script:pgRestores=0;$script:auditRestores=0
    Read-PairStore $state $target 'postgres';$null=Invoke-Docker (Get-PgDataRestoreArguments $target.Id -List) $pgCaptured
    Restore-Pg;Restore-Audit;Same-Point (Get-PairPoint $target) $before
    $id=$seed.eventIds[0]
    $mutations=@(
        @{Name='eventId';Set="event_id='11111111-1111-4111-8111-111111111111'"},
        @{Name='actorSubjectId';Set="actor_subject_id='changed'"},@{Name='actorKind';Set='actor_kind=2'},@{Name='Action';Set="action='changed'"},
        @{Name='targetType';Set="target_type='changed'"},@{Name='targetId';Set="target_id='changed'"},@{Name='correlationId';Set="correlation_id='changed'"},
        @{Name='occurredAt';Set="occurred_at='1971-01-01Z'"},@{Name='recordedAt';Set="recorded_at='1971-01-01Z'"},@{Name='context';Set="context_json='{}'::jsonb"}
    )
    $stage='field-refusals'
    foreach($m in $mutations){
        $null=Pair-Sql $state $target 'fleetory' ('UPDATE platform.audit_events SET '+$m.Set+" WHERE event_id='"+$id+"';")
        $null=Invoke-PairProbe $state $target 'pair-host' -Refusal
        Assert-Pair ((Invoke-PairProbe $state $target 'pair-closed').closedPorts -eq 3) 'refused-host-closed'
        Restore-Pg
    }
    $stage='audit-refusal';$null=Invoke-PairProbe $state $target 'pair-audit-drift'
    $null=Invoke-PairProbe $state $target 'pair-host' -Refusal
    Assert-Pair ((Invoke-PairProbe $state $target 'pair-closed').closedPorts -eq 3) 'audit-refused-host-closed'
    Remove-PairAudit $state $target.Audit
    New-PairAudit $state $target;Restore-Audit;Same-Point (Get-PairPoint $target) $before
    $stage='native-host';$hostFirst=Invoke-PairProbe $state $target 'pair-host'
    Assert-Pair ($hostFirst.applicationStarts -eq 1 -and $hostFirst.applicationStops -eq 1 -and $hostFirst.readiness -ceq 'Healthy' -and $hostFirst.workerStopped -eq $true -and $hostFirst.nonemptyDataUnchanged -eq $true -and $hostFirst.issuerActivated -eq $false) 'native-host-lifecycle'
    Same-Point (Get-PairPoint $target) $before
    Assert-Pair ((Pg-Inventory $target).Sha256 -ceq $sourceInventory.Sha256) 'native-host-inventory-unchanged'
    $stage='restart';Read-PairStore $state $target 'postgres';Read-PairStore $state $target.Audit 'audit'
    $null=Invoke-Docker @('exec',$target.Id,'pg_ctl','-D','/var/lib/postgresql/18/recovery','stop','-m','fast','-w','-t','15')
    Start-PairPostgres $state $target
    $pidText=(Invoke-Docker @('exec',$target.Audit.Id,'/bin/cat','/tmp/immudb.pid')).Stdout.Trim()
    Assert-Pair ($pidText -cmatch '^[1-9][0-9]{0,7}\z') 'audit-pid'
    $null=Invoke-Docker @('exec',$target.Audit.Id,'/bin/kill','-TERM',$pidText)
    $stopped=$false
    for($n=0;$n -lt 40;$n++){$r=Invoke-Docker @('exec',$target.Audit.Id,'/bin/kill','-0',$pidText) -AllowFailure;if($r.ExitCode -ne 0){$stopped=$true;break};Start-Sleep -Milliseconds 200}
    Assert-Pair $stopped 'audit-stopped';Start-PairAudit $state $target
    Same-Point (Get-PairPoint $target) $before
    $hostSecond=Invoke-PairProbe $state $target 'pair-host'
    Assert-Pair ($hostSecond.applicationStarts -eq 1 -and $hostSecond.applicationStops -eq 1 -and $hostSecond.nonemptyDataUnchanged -eq $true -and $hostSecond.workerStopped -eq $true) 'restarted-native-host'
    Same-Point (Get-PairPoint $target) $before;Same-Point (Get-PairPoint $source) $before
    Assert-Pair ((Pg-Inventory $target).Sha256 -ceq $sourceInventory.Sha256 -and (Pg-Inventory $source).Sha256 -ceq $sourceInventory.Sha256) 'final-inventories'
    $proof=[ordered]@{schema='fleetory.native-server-pair.v1';verified=$true;scope='generated-only paired native restore and Server lifecycle';events=4;fieldsPerEvent=10;tables=18;rows=23;auditTransactions=4;
        postgresBytes=$pgCaptured.Length;auditBytes=$auditCaptured.Length;postgresSha256=$pgPin;auditSha256=$auditPin;manifestSha256=$manifestPin;probeSha256=$state.ProbeHash;eventsSha256=$before.eventsSha256;
        sourceObservedStableWindow=$true;globalAtomicSnapshotClaimed=$false;capturedBothImmutable=$true;nativeSinkSerializationVerified=$true;schemaDataAndSecurityInventoryMatched=$true;nativePgRestores=$pgRestores;nativeAuditRestores=$auditRestores;
        crossFieldHostRefusals=$mutations.Count;extraAuditKeyHostRefused=$true;refusedHostsNeverListened=$true;nativeApplicationStarts=2;nativeApplicationStops=2;targetRuntimeTlsVerified=$true;targetCredentialsRecreated=$true;
        restartAndHostReadbackVerified=$true;postHostDataAndAuditTipUnchanged=$true;sourceUnchanged=$true;componentApprovalFixturesUsed=$false;placeholderArtifactsUsed=$false;externalApprovalVerified=$false;originalInventoryV2Verified=$false;
        originalInputsRead=$false;sourceVpsAccessed=$false;originalPkiOrProviderUsed=$false;humanLoginVerified=$false;issuerActivated=$false;productionTokenIssued=$false;sessionTokenRevocationVerified=$false;untrustedArchiveSandboxVerified=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
    }
}catch{
    if($_.Exception.Message -cmatch '^(?:Native pair|Native signer|PostgreSQL data|Audit data) (?:fixture )?refused: ([a-z0-9-]{1,64})\z'){[Console]::Error.WriteLine('Native pair category='+$Matches[1]+'; exit='+$lastExit+'; class='+$lastClass)}
    [Console]::Error.WriteLine('Native pair failed at '+$stage+'; type='+$_.Exception.GetType().Name+'; line='+$_.InvocationInfo.ScriptLineNumber+'. No rows, packet, SQL or credential logged.')
    throw 'Native Server pair recovery failed.'
}finally{
    $cleaning=$true;$failures=@()
    foreach($a in @($state.Audits.ToArray())|Sort-Object Started -Descending){try{Remove-PairAudit $state $a}catch{$failures+='audit'}}
    foreach($s in @($state.Sides.ToArray())|Sort-Object Started -Descending){try{
        $lookup=if($s.Id){$s.Id}else{$s.Name};$r=Invoke-Docker @('inspect',$lookup) -AllowFailure
        if($r.ExitCode -eq 0){if(-not $s.Id){$s.Id=@($r.Stdout|ConvertFrom-Json -AsHashtable)[0].Id};Read-PairStore $state $s 'postgres' -Cleanup;$null=Invoke-Docker @('rm','-f','-v',$s.Id);$r=Invoke-Docker @('inspect',$s.Id) -AllowFailure}
        Assert-Pair ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'postgres-cleanup'
    }catch{$failures+='postgres'}}
    if(-not $failures.Count -and $imageClaimed){try{
        $r=Invoke-Docker @('image','inspect',$state.Image) -AllowFailure
        if($r.ExitCode -eq 0){$i=@($r.Stdout|ConvertFrom-Json -AsHashtable);Assert-Pair ($i.Count -eq 1 -and $i[0].Config.Labels['fleetory.native-pair.build'] -ceq $fixture -and ($null -eq $state.ImageId -or $i[0].Id -ceq $state.ImageId)) 'build-cleanup-owner';$null=Invoke-Docker @('image','rm',$state.Image);$r=Invoke-Docker @('image','inspect',$state.Image) -AllowFailure}
        Assert-Pair ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'build-cleanup'
    }catch{$failures+='image'}}
    if(-not $failures.Count){try{Remove-NativePublicPayload $repo $root}catch{$failures+='payload'}}
    $env:DOCKER_BUILDKIT=$oldBuildKit;if($state.ContainsKey('SigningPems')){$state.SigningPems.Clear()};$state.SigningPem=$state.Tls=$null;$state.GatewayTls.Clear();$state.Canaries.Clear();foreach($s in $state.Sides){$s.Secrets.Clear()};$pg=$audit=$pgCaptured=$auditCaptured=$capture=$captured=$packet=$null;$watch.Stop()
    if($failures.Count){throw 'Native pair owned cleanup unverified; resource ledger retained.'}
    @{schema='fleetory.native-pair-cleanup.v1';fixture=$fixture;cleanupVerified=$true;ids=@($state.Sides|ForEach-Object {$_.Id})+@($state.Audits|ForEach-Object {$_.Id});image=$state.Image;aliases=@($state.Audits|ForEach-Object {$_.Image});originalInputsRead=$false}|ConvertTo-Json -Compress
}
if($FailurePoint -ceq 'none'){
    $fault=Invoke-NativeBytes ([Environment]::ProcessPath) @('-NoLogo','-NoProfile','-NonInteractive','-File',$PSCommandPath,'-Python',$Python,'-FailurePoint','after-stores','-Profile',$Profile) -TimeoutSeconds 120
    Assert-Pair ($fault.ExitCode -ne 0 -and $fault.Stdout.Contains('PAIR INJECTED FAILURE AFTER STORES') -and $fault.Stderr.Contains('Native Server pair recovery failed.')) 'injected-failure-exit'
    $records=@($fault.Stdout -split '\r?\n'|Where-Object {$_.StartsWith('{')}|ForEach-Object {$_|ConvertFrom-Json -AsHashtable}|Where-Object {$_.schema -ceq 'fleetory.native-pair-cleanup.v1'})
    Assert-Pair ($records.Count -eq 1 -and $records[0].cleanupVerified -eq $true -and $records[0].originalInputsRead -eq $false -and @($records[0].ids).Count -eq 4 -and @($records[0].aliases).Count -eq 2) 'fault-cleanup-record'
    Assert-Pair ($records[0].fixture -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z' -and $records[0].image -ceq ('fleetory-native-pair-'+$records[0].fixture.Replace('-','')+':fixture')) 'fault-image-identity'
    foreach($id in $records[0].ids){Assert-Pair ($id -cmatch '^[a-f0-9]{64}\z') 'fault-id';$r=Invoke-Docker @('inspect',$id) -AllowFailure;Assert-Pair ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'fault-container-absence'}
    foreach($name in @($records[0].image)+@($records[0].aliases)){Assert-Pair ($name -cmatch '^fleetory-native-(pair|audit)-[a-f0-9]{32}:fixture\z') 'fault-alias';$r=Invoke-Docker @('image','inspect',$name) -AllowFailure;Assert-Pair ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'fault-image-absence'}
    Assert-Pair (-not (Test-Path -LiteralPath (Join-Path $repo ('artifacts/native-pair-'+$records[0].fixture)))) 'fault-payload-absence'
    $proof.faultCleanupVerified=$true;$proof.faultCleanupContainers=4
}
$proof.cleanupVerified=$true;$proof|ConvertTo-Json -Compress -Depth 8
$global:LASTEXITCODE=0
