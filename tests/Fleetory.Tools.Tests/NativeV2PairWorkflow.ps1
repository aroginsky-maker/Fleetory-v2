#requires -Version 7.3
# Generated composition inside the existing owned pair controller; no external endpoints/paths.
function Get-V2CompositionPoint($Side){
    $pg=@{};foreach($db in @('fleetory','fleetory_signer')){$pg[$db]=V2-Read $Side $db}
    $v=Invoke-PairProbe $state $Side 'v2pair-read'
    Assert-Pair ($v.fixture -ceq $fixture -and $v.events -eq 4 -and $v.keys -eq 5 -and $v.transactions -eq 5 -and $v.completeKeysetVerified -eq $true -and $v.allFiveNativeTransactionsVerified -eq $true) 'v2-composed-native-readback'
    $receipt=New-ImmudbStateReceipt $v.state 'fleetoryaudit' (Join-Path $root ($Side.Role+'-public.pem'))
    return @{postgres=$pg;audit=@{database=$receipt.database;tx=[int]$receipt.txId;txHash=[Convert]::ToHexString([Convert]::FromBase64String($receipt.txHash));keyFingerprint=$receipt.publicKeySha256;historySha256=$v.historySha256;events=4;keys=5;transactions=5}}
}
function Same-V2Source($Actual,$Expected){
    $a=[System.Text.Json.Nodes.JsonNode]::Parse(($Actual|ConvertTo-Json -Depth 20 -Compress))
    $b=[System.Text.Json.Nodes.JsonNode]::Parse(($Expected|ConvertTo-Json -Depth 20 -Compress))
    Assert-Pair ([System.Text.Json.Nodes.JsonNode]::DeepEquals($a,$b)) 'v2-composed-source-stability'
}
function Test-V2Composition([switch]$Refusal){
    $point=Get-V2CompositionPoint $target
    $body=[Text.Encoding]::UTF8.GetBytes((@{source=$script:v2Expected;target=$point}|ConvertTo-Json -Depth 24 -Compress))
    $r=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/v2_server_composition.py'),'compare') $body 20
    Assert-Pair ([string]::IsNullOrWhiteSpace($r.Stderr)) 'v2-composition-comparison-process'
    $v=$r.Stdout|ConvertFrom-Json -AsHashtable
    if($Refusal){Assert-Pair ($r.ExitCode -eq 1 -and $v.category -ceq 'generated-composition-mismatch' -and $v.executionAuthorized -eq $false) 'v2-composition-typed-refusal'}
    else{Assert-Pair ($r.ExitCode -eq 0 -and $v.category -ceq 'matching-generated-composition' -and $v.executionAuthorized -eq $false -and $v.signaturesVerified -eq $false) 'v2-composition-matching'}
}
function Start-V2CompositionHost{
    Test-V2Composition
    $script:v2HostCalls++
    $v=Invoke-PairProbe $state $target 'v2pair-host'
    Assert-Pair ($v.applicationStarts -eq 1 -and $v.applicationStops -eq 1 -and $v.readiness -ceq 'Healthy' -and $v.workerStopped -eq $true -and $v.nonemptyDataUnchanged -eq $true -and $v.issuerActivated -eq $false) 'v2-native-host'
    Test-V2Composition
}
function Assert-V2RefusedPorts{
    Assert-Pair ((Invoke-PairProbe $state $target 'pair-closed').closedPorts -eq 3 -and $script:v2HostCalls -eq 0) 'v2-refused-before-host-start'
}
function Invoke-V2PairWorkflow{
    $script:stage='v2-bootstrap';$script:sqls=@{};$script:captured=@{};$script:pins=@{};$script:expected=@{};$script:restores=0;$script:auditRestores=0;$script:v2HostCalls=0
    foreach($db in @('fleetory','fleetory_signer')){
        $r=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/pg_inventory_v2.py'),'sql','--database',$db) -TimeoutSeconds 10
        Assert-Pair ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr) -and $r.StdoutBytes.Length -le 131072) 'v2-composed-sql-generator';$script:sqls[$db]=$r.Stdout
    }
    foreach($side in @($source,$target)){
        $side.Secrets.signer=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();$state.Canaries.Add($side.Secrets.signer)
        $null=V2-Sql $side 'postgres' ("CREATE ROLE fleetory_signer_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;CREATE ROLE fleetory_signer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+$side.Secrets.signer+"';")
        V2-NewDatabase $side 'fleetory_signer'
        Write-PairFile $state $side 'postgres' '/tmp/hba.conf' "local all postgres peer`nlocal all all reject`nhostssl fleetory fleetory_server 127.0.0.1/32 scram-sha-256`nhostssl fleetory_signer fleetory_signer 127.0.0.1/32 scram-sha-256`nhost all all 0.0.0.0/0 reject`nhost all all ::/0 reject`n"
        $null=Invoke-Docker @('exec',$side.Id,'pg_ctl','-D','/var/lib/postgresql/18/recovery','reload')
    }
    $script:stage='v2-seed'
    $null=V2-Sql $source 'fleetory' ("SET ROLE fleetory_migrator;`n"+$schema.sql+"`nRESET ROLE;`n"+(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'PgInventoryV2Seed.sql') -Raw))
    $null=V2-Sql $source 'fleetory_signer' ("SET ROLE fleetory_signer_owner;`n"+(Get-Content -LiteralPath (Join-Path $repo 'eng/provision-signing-journal.sql') -Raw)+"`nRESET ROLE;`n"+(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'PgInventoryV2SignerSeed.sql') -Raw))
    $seed=Invoke-PairProbe $state $source 'v2pair-seed-sql'
    Assert-Pair ($seed.fixture -ceq $fixture -and $seed.sql.Length -le 16384 -and @($seed.eventIds).Count -eq 4) 'v2-composed-event-model'
    $null=V2-Sql $source 'fleetory' ($seed.sql+'GRANT INSERT,UPDATE,DELETE ON platform.audit_export_queue TO fleetory_server;')
    $null=Invoke-PairProbe $state $source 'v2pair-publish'
    $script:v2Expected=Get-V2CompositionPoint $source;$script:expected=$v2Expected.postgres
    $script:stage='v2-capture';$artifacts=@{}
    foreach($entry in @(@('application','fleetory'),@('signer','fleetory_signer'))){
        Read-PairStore $state $source 'postgres';$artifacts[$entry[0]]=(Invoke-Docker @('exec',$source.Id,'pg_dump','-Fc','--compress=0','--no-password','-U','postgres','-d',$entry[1])).StdoutBytes
    }
    Read-PairStore $state $source.Audit 'audit';$artifacts.audit=(Invoke-Docker (Get-ImmuDataCliArguments $source.Audit.Id 'backup')).StdoutBytes
    $after=Get-V2CompositionPoint $source;Same-V2Source $after $v2Expected
    $artifactMeta=@{};foreach($name in $artifacts.Keys){$artifactMeta[$name]=@{bytes=$artifacts[$name].Length;sha256=(Get-PgDataHash $artifacts[$name])}}
    $manifest=@{schema='fleetory.generated-v2-server-composition.v1';scope='generated-only-no-original-approval';fixture=$fixture;probeSha256=$state.ProbeHash;images=@{postgres=$state.PgImageId;audit=$state.ImageId};sourceContainers=@{postgres=$source.Id;audit=$source.Audit.Id};point=$v2Expected;capture=@{before=$v2Expected;after=$after};artifacts=$artifactMeta}
    $manifestBytes=[Text.Encoding]::UTF8.GetBytes(($manifest|ConvertTo-Json -Depth 25 -Compress));$manifestPin=Get-PgDataHash $manifestBytes
    $body=@{manifestBase64=[Convert]::ToBase64String($manifestBytes)};foreach($name in $artifacts.Keys){$body[$name+'Base64']=[Convert]::ToBase64String($artifacts[$name])}
    $r=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/v2_server_composition.py'),'capture','--pin',$manifestPin,'--fixture',$fixture) ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Compress))) 30
    Assert-Pair ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'v2-composed-capture'
    $v=$r.Stdout|ConvertFrom-Json -AsHashtable;Assert-Pair ($v.generatedOnly -eq $true -and $v.executionAuthorized -eq $false -and $v.signaturesVerified -eq $false -and $v.originalInputsVerified -eq $false) 'v2-composed-capture-scope'
    $script:captured.fleetory=[Convert]::FromBase64String($v.applicationBase64);$script:captured.fleetory_signer=[Convert]::FromBase64String($v.signerBase64);$script:auditCaptured=[Convert]::FromBase64String($v.auditBase64)
    foreach($e in @(@('application','fleetory'),@('signer','fleetory_signer'))){$script:pins[$e[1]]=$artifactMeta[$e[0]].sha256;Assert-PgDataPacket $captured[$e[1]] $pins[$e[1]]}
    Assert-ImmuDataPacket $auditCaptured $artifactMeta.audit.sha256
    foreach($blob in $artifacts.Values){[Array]::Clear($blob)};$body=$v=$r=$null
    $script:stage='v2-restore';V2-Restore 'fleetory';V2-Restore 'fleetory_signer';Restore-Audit;Test-V2Composition
    $script:stage='v2-native-data-refusals'
    foreach($change in @("action='changed'","context_json='{}'::jsonb","event_id='11111111-1111-4111-8111-111111111111'")){
        $null=V2-Sql $target 'fleetory' ('UPDATE platform.audit_events SET '+$change+" WHERE event_id='"+$seed.eventIds[0]+"';")
        $null=Invoke-PairProbe $state $target 'v2pair-host' -Refusal;Assert-V2RefusedPorts;V2-Restore 'fleetory'
    }
    $script:stage='v2-coordinator-refusals'
    $cases=@(@{Name='signer';Db='fleetory_signer';Sql="UPDATE signer.signing_rejections SET reason='Duplicate';";Restore='fleetory_signer'},
        @{Name='acl';Db='fleetory';Sql='GRANT INSERT ON core.devices TO fleetory_server;';Restore='fleetory'},
        @{Name='role';Db='postgres';Sql='ALTER ROLE fleetory_server CONNECTION LIMIT 5;';Undo='ALTER ROLE fleetory_server CONNECTION LIMIT -1;'})
    foreach($case in $cases){
        $script:stage='v2-coordinator-'+$case.Name
        $null=V2-Sql $target $case.Db $case.Sql;Test-V2Composition -Refusal;Assert-V2RefusedPorts
        if($case.ContainsKey('Undo')){$null=V2-Sql $target $case.Db $case.Undo}else{V2-Restore $case.Restore}
        Test-V2Composition
    }
    $script:stage='v2-audit-refusal';$null=Invoke-PairProbe $state $target 'pair-audit-drift'
    $null=Invoke-PairProbe $state $target 'v2pair-host' -Refusal;Assert-V2RefusedPorts
    Remove-PairAudit $state $target.Audit;New-PairAudit $state $target;Restore-Audit;Test-V2Composition
    $script:stage='v2-runtime'
    foreach($db in @('fleetory','fleetory_signer')){
        $query=if($db -ceq 'fleetory'){'SELECT count(*) FROM platform.audit_events;'}else{'SELECT count(*) FROM signer.signing_rejections;'}
        $password=if($db -ceq 'fleetory'){$target.Secrets.database}else{$target.Secrets.signer}
        $r=V2-Runtime $db $password $query;Assert-Pair ($r.ExitCode -eq 0 -and $r.Stdout.Trim() -ceq $(if($db -ceq 'fleetory'){'4'}else{'3'})) 'v2-composed-runtime-login'
    }
    $script:stage='v2-host';Start-V2CompositionHost
    $script:stage='v2-restart';Read-PairStore $state $target 'postgres';Read-PairStore $state $target.Audit 'audit'
    $null=Invoke-Docker @('exec',$target.Id,'pg_ctl','-D','/var/lib/postgresql/18/recovery','stop','-m','fast','-w','-t','15');Start-PairPostgres $state $target
    $pidText=(Invoke-Docker @('exec',$target.Audit.Id,'/bin/cat','/tmp/immudb.pid')).Stdout.Trim();Assert-Pair ($pidText -cmatch '^[1-9][0-9]{0,7}\z') 'v2-audit-pid'
    $null=Invoke-Docker @('exec',$target.Audit.Id,'/bin/kill','-TERM',$pidText);$stopped=$false
    for($n=0;$n -lt 40;$n++){$r=Invoke-Docker @('exec',$target.Audit.Id,'/bin/kill','-0',$pidText) -AllowFailure;if($r.ExitCode -ne 0){$stopped=$true;break};Start-Sleep -Milliseconds 200}
    Assert-Pair $stopped 'v2-audit-stop';Start-PairAudit $state $target;Start-V2CompositionHost;Same-V2Source (Get-V2CompositionPoint $source) $v2Expected
    return @{schema='fleetory.native-v2-server-composition.v1';verified=$true;scope='generated three-archive composition and native Server lifecycle';applicationTables=18;applicationRows=24;signerTables=4;signerRows=5;auditEvents=4;auditKeys=5;auditTransactions=5;applicationRoles=4;nativePgRestores=$restores;nativeAuditRestores=$auditRestores;nativeFieldHostRefusals=3;extraAuditKeyHostRefused=$true;coordinatorSecuritySignerRefusals=3;refusedPortsClosed=$true;applicationStartsOnlyAfterCoordinatorPreflight=$true;nativeApplicationStarts=$v2HostCalls;nativeApplicationStops=$v2HostCalls;runtimeTlsScramLogins=2;sourceTargetSigningIdentitiesDistinct=$true;bothOwnPublicPinsVerified=$true;originalKeyContinuityClaimed=$false;fullV2AndSupplementalInventoryCompared=$true;completeAuditHistoryCompared=$true;postgresAuditTenFieldsVerified=$true;capturedThreeNativeArchivesFrozen=$true;manifestSha256=$manifestPin;artifactPins=$artifactMeta;probeSha256=$state.ProbeHash;restartAndPostHostInventoriesUnchanged=$true;sourceObservedStableAndUnchanged=$true;normalCleanupContainers=($state.Sides.Count+$state.Audits.Count);globalAtomicSnapshotClaimed=$false;originalInputsRead=$false;sourceVpsAccessed=$false;originalPkiOrProviderUsed=$false;sourcePasswordsRecovered=$false;humanLoginVerified=$false;issuerActivated=$false;productionTokenIssued=$false;independentInclusionProofsVerified=$false;untrustedArchiveSandboxVerified=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
