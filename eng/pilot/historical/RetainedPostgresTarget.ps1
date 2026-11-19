#requires -Version 7.3
# Fixed PostgreSQL data-stage owner. Receives frozen private-pipe bytes, never source paths or adopted IDs.
function Invoke-RetainedPostgresTarget([string]$Repository,[string]$Python,[hashtable]$Payload,[hashtable]$Expected,
    [ValidateSet('complete','after-acquire','lease-expired')][string]$Flow='complete'){
    $pilot=Join-Path $Repository 'eng/pilot'
    foreach($helper in @('HistoricalRecoveryCoordinator.ps1','HistoricalRecoveryInFlight.ps1')){. (Join-Path $pilot $helper)}
    . (Join-Path $Repository 'tests/Fleetory.Tools.Tests/NativeAuditDataFixture.ps1')
    $plan=@{nonce=[Guid]::NewGuid().ToString('D')}
    $comparisonPython=$Python;$comparisonPythonHash=Get-ImmuDataHash ([IO.File]::ReadAllBytes($Python))
    $workerNames=@('historical_audit_observation','audit_observation','audit_process_fence','audit_process_posix',
        'audit_process_windows','audit_control_identity','recovery_files','fresh_server_pair','audit_archive')
    $codeSnapshot=@{comparisonSourcePins=($workerNames|ForEach-Object {(Get-FileHash -LiteralPath (Join-Path $pilot ($_+'.py')) -Algorithm SHA256).Hash.ToLowerInvariant()}) -join ','}
    $copy=@{};$captureJson=$Payload.capture|ConvertTo-Json -Depth 12 -Compress
    $capturePin=Get-ImmuDataHash ([Text.Encoding]::UTF8.GetBytes($captureJson))
    Assert-ImmuData ($Payload.schema -ceq 'fleetory.retained-service-private-payload.v1' -and $Payload.executionAuthorized -eq $false -and
        $Payload.capture.verifiedArtifacts -eq 4 -and $Payload.capture.frozenBytes -eq $true -and
        $Payload.capture.executionAuthorized -eq $false -and $Payload.capture.fullSystemRecoveryVerified -eq $false) 'retained-pg-payload'
    $kinds=@('application-postgres','signer-postgres','audit-immudb','audit-export');[long]$bytes=0
    foreach($kind in $kinds){
        $copy[$kind]=[Convert]::FromBase64String($Payload.packets[$kind]);$bytes+=$copy[$kind].Length
        Assert-ImmuData ((Get-ImmuDataHash $copy[$kind]) -ceq $Payload.packetSha256[$kind]) 'retained-pg-private-packet-pin'
    }
    Assert-ImmuData ($bytes -gt 0 -and $bytes -le 16777216 -and $copy.Count -eq 4 -and
        $Payload.packets.Count -eq 4 -and $Payload.packetSha256.Count -eq 4) 'retained-pg-private-packet-bound'
    foreach($kind in $kinds[0..2]){Assert-ImmuData ($Payload.packetSha256[$kind] -ceq $Payload.capture.artifactPins[$kind]) 'retained-pg-artifact-pin'}
    Assert-ImmuData ($Payload.packetSha256['audit-export'] -ceq $Expected.fleetory.inventory.audit.snapshotSha256) 'retained-pg-expected-snapshot'
    Assert-PgDataPacket $copy['application-postgres'] $Payload.packetSha256['application-postgres']
    Assert-PgDataPacket $copy['signer-postgres'] $Payload.packetSha256['signer-postgres']
    $image=@((Invoke-Docker @('image','inspect',$script:nativeJournalImage)).Stdout|ConvertFrom-Json -AsHashtable)
    Assert-ImmuData ($image.Count -eq 1 -and $image[0].Id -cmatch '^sha256:[a-f0-9]{64}\z') 'retained-pg-base-image'
    $context=@{Fixture=$plan.nonce;ImageName=$script:nativeJournalImage;ImageId=$image[0].Id;LifetimeSeconds=3300;
        Stores=[Collections.Generic.List[object]]::new()}
    $store=@{Session=$plan.nonce;Name=('fleetory-native-journal-'+$plan.nonce.Replace('-',''));Role='retained-postgres-target';
        Started=[DateTimeOffset]::UtcNow;Id=$null}
    $context.Stores.Add($store);$client=${function:Invoke-Docker};$peer=$null;$proof=$null
    $meter=@{restores=0;sql=0;remove=0;copiedClaimsRefused=0;removeReplayRefused=$false;bootstrapped=$false}
    $clock=[Diagnostics.Stopwatch]::StartNew();$inventories=@{}
    function New-IndependentControllerStart([string]$ModeFlow,[string]$Mode){
        $start=New-HistoricalChildStart $comparisonPython
        $start.WorkingDirectory=$pilot
        foreach($part in @('-I','-S','-B',(Join-Path $pilot 'historical_audit_observation.py'),$Mode,$ModeFlow,
            $plan.nonce,$comparisonPythonHash,$codeSnapshot.comparisonSourcePins)){$start.ArgumentList.Add($part)}
        return $start
    }
    function Read-RetainedPg([switch]$CleanupOnly){
        $identifier=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
        $reply=Invoke-AuditDataContainerOperation $context $store 'Inspect' @('inspect',$identifier)
        Assert-ImmuData ($reply.ExitCode -eq 0) 'retained-pg-inspection'
        $items=@($reply.Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
        Assert-ImmuData ($items.Count -eq 1) 'retained-pg-single-object'
        Assert-NativeJournal $items[0] $identifier $store.Session $context.ImageId $store.Started -CleanupOnly:$CleanupOnly
        return $identifier
    }
    function Invoke-RetainedPgNative([string[]]$Arguments,[byte[]]$InputBytes=$null){
        Assert-ImmuData ($clock.Elapsed.TotalSeconds -lt 90 -and $null -ne $peer -and -not $peer.holder.HasExited) 'retained-pg-live-work'
        $identifier=Read-RetainedPg
        Assert-ImmuData ($Arguments.Count -ge 2 -and $Arguments[0] -ceq 'exec' -and $Arguments -ccontains $identifier) 'retained-pg-own-command'
        return Invoke-Docker $Arguments $InputBytes 15
    }
    function Pg-Sql([ValidateSet('postgres','fleetory','fleetory_signer')][string]$Database,[string]$Sql){
        $identifier=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client);$meter.sql++
        return Invoke-RetainedPgNative @('exec','-i','-e','PGCLIENTENCODING=UTF8',$identifier,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',$Database) ([Text.Encoding]::UTF8.GetBytes($Sql))
    }
    function Remove-OwnedHistoricalResources{
        if([Fleetory.Pilot.AuditContainerCustody]::Closed($context,$store,$client)){return}
        $identifier=Read-RetainedPg -CleanupOnly
        $meter.remove++
        $null=Invoke-AuditDataContainerOperation $context $store 'Remove' @('rm','--force',$identifier)
        $null=Invoke-AuditDataContainerOperation $context $store 'ConfirmRemoval' @('inspect',$identifier)
        $script:cleanup=$true
    }
    try{
        $peer=Open-HistoricalRecoveryCoordinator $Flow
        Enter-HistoricalCoordinatorAllocation $peer
        $store.Id=Invoke-AuditDataContainerOperation $context $store 'Create' (Get-NativeJournalArguments $store.Session)
        $identifier=Read-RetainedPg
        foreach($variant in @(@{context=$context.Clone();store=$store},@{context=$context;store=$store.Clone()})){
            try{$null=[Fleetory.Pilot.AuditContainerCustody]::Id($variant.context,$variant.store,$client)}
            catch [InvalidOperationException]{$meter.copiedClaimsRefused++;continue}
            throw 'Copied PostgreSQL resource claim accepted.'
        }
        $commitment=[Text.Encoding]::UTF8.GetBytes(($plan.nonce,$context.ImageId,$identifier,$capturePin,
            $Payload.packetSha256['application-postgres'],$Payload.packetSha256['signer-postgres'],
            ($Expected|ConvertTo-Json -Depth 20 -Compress) -join '|'))
        $peer.projection=Get-ImmuDataHash $commitment;$peer.lease=[Diagnostics.Stopwatch]::StartNew()
        Send-HistoricalCoordinatorFrame $peer ('owned:'+$peer.projection)
        Receive-HistoricalCoordinatorFrame $peer ('received:'+$peer.projection)
        if($Flow -ceq 'after-acquire'){
            $proof=Finish-HistoricalRecoveryCoordinator $peer 'terminate'
        }elseif($Flow -ceq 'lease-expired'){
            $proof=Remove-ExpiredHistoricalCoordinatorResources $peer
        }else{
            Read-HistoricalCoordinatorWork $peer
            Assert-ImmuData ($peer.lease.Elapsed.TotalSeconds -lt 5) 'retained-pg-work-admission'
            $peer.workAdmitted=$true
            $null=Invoke-RetainedPgNative @('exec',$identifier,'initdb','-D','/var/lib/postgresql/18/recovery','--auth-local=peer','--auth-host=reject','--no-instructions')
            $null=Invoke-RetainedPgNative @('exec','-d',$identifier,'postgres','-D','/var/lib/postgresql/18/recovery',
                '-c','listen_addresses=','-c','unix_socket_directories=/var/run/postgresql','-c','shared_buffers=32MB',
                '-c','max_connections=20','-c','password_encryption=scram-sha-256','-c','log_statement=none','-c','log_min_error_statement=panic')
            $ready=$false
            for($n=0;$n-lt40;$n++){
                $r=Invoke-Docker @('exec',$identifier,'pg_isready','-q','-U','postgres') $null 5 -AllowFailure
                if($r.ExitCode-eq0){$ready=$true;break};Start-Sleep -Milliseconds 100
            }
            Assert-ImmuData $ready 'retained-pg-ready';$meter.bootstrapped=$true
            $roles=''
            foreach($role in @('fleetory_migrator','fleetory_server','fleetory_signer_owner','fleetory_signer')){
                $login=if($role-cin@('fleetory_server','fleetory_signer')){'LOGIN'}else{'NOLOGIN'}
                $roles+='CREATE ROLE '+$role+' '+$login+' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;'
            }
            $null=Pg-Sql 'postgres' $roles
            foreach($database in @('fleetory','fleetory_signer')){
                $owner=if($database-ceq'fleetory'){'fleetory_migrator'}else{'fleetory_signer_owner'}
                $runtime=if($database-ceq'fleetory'){'fleetory_server'}else{'fleetory_signer'}
                $kind=if($database-ceq'fleetory'){'application-postgres'}else{'signer-postgres'}
                $null=Pg-Sql 'postgres' ("CREATE DATABASE $database OWNER $owner;REVOKE ALL ON DATABASE $database FROM PUBLIC;GRANT CONNECT ON DATABASE $database TO $runtime;")
                $null=Invoke-RetainedPgNative @('exec','-i',$identifier,'pg_restore','--exit-on-error','--single-transaction',
                    '--no-password',('--role='+$owner),'--username=postgres',('--dbname='+$database)) $copy[$kind]
                $meter.restores++
                $sql=Invoke-NativeBytes $Python @('-B',(Join-Path $pilot 'pg_inventory_v2.py'),'sql','--database',$database) -TimeoutSeconds 10
                Assert-ImmuData ($sql.ExitCode-eq0-and[string]::IsNullOrWhiteSpace($sql.Stderr)) 'retained-pg-readback-sql'
                $native=Pg-Sql $database $sql.Stdout
                $decoded=Invoke-NativeBytes $Python @('-B',(Join-Path $pilot 'pg_inventory_v2.py'),'readback','--database',$database) $native.StdoutBytes 10
                Assert-ImmuData ($decoded.ExitCode-eq0-and[string]::IsNullOrWhiteSpace($decoded.Stderr)) 'retained-pg-readback-parser'
                $value=$decoded.Stdout|ConvertFrom-Json -AsHashtable -Depth 20
                foreach($field in @('inventorySha256','securitySha256')){
                    Assert-ImmuData ($value.inventory[$field]-ceq$Expected[$database].inventory[$field]) 'retained-pg-inventory'
                }
                Assert-ImmuData ($value.additionalSecuritySha256-ceq$Expected[$database].additionalSecuritySha256) 'retained-pg-role-state'
                $inventories[$database]=$value
            }
            $proof=Finish-HistoricalRecoveryCoordinator $peer 'completed'
        }
    }finally{
        try{Close-HistoricalRecoveryCoordinator $peer}finally{
            if($null-ne$store.Id){Remove-OwnedHistoricalResources}
            foreach($blob in $copy.Values){[Array]::Clear($blob)}
        }
    }
    Assert-ImmuData ([Fleetory.Pilot.AuditContainerCustody]::Closed($context,$store,$client)-and$meter.remove-eq1) 'retained-pg-cleanup'
    $replay=@{calls=0}
    $operation=[Func[Tuple[int,byte[],byte[]]]]{
        $replay.calls++
        return [Tuple[int,byte[],byte[]]]::new(0,[byte[]]::new(0),[byte[]]::new(0))
    }.GetNewClosure()
    try{[Fleetory.Pilot.AuditContainerCustody]::Remove($context,$store,$client,$operation)}catch{
        if($_.Exception.GetBaseException() -isnot [InvalidOperationException]){throw}
        $meter.removeReplayRefused=$true
    }
    Assert-ImmuData ($meter.removeReplayRefused-and$replay.calls-eq0-and$meter.remove-eq1) 'retained-pg-removal-replay'
    return @{schema='fleetory.retained-postgres-target.v1';flow=$Flow;verified=$true;coordinator=$proof;containerId=$store.Id;
        inputCaptureSha256=$capturePin;frozenFourInputsBound=$true;nativePgRestores=$meter.restores;inventories=$inventories;
        copiedClaimsRefused=$meter.copiedClaimsRefused;cleanupVerified=$true;ownRemovalCalls=$meter.remove;baseImageRemoved=$false;
        removalReplayRefusedBeforeNativeCall=$true;baseImageId=$context.ImageId;unknownCreateOutcomeRecoveryVerified=$false;
        independentCreatorDeathCleanupVerified=$false;runtimeLoginVerified=$false;nativeAuditRestored=$false;serverStarted=$false;
        originalUseAuthenticated=$false;executionAuthorized=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
