#requires -Version 7.3
# Fixed PostgreSQL data-stage owner. Receives frozen private-pipe bytes, never source paths or adopted IDs.
function Invoke-RetainedPostgresTarget([string]$Repository,[string]$Python,[hashtable]$Payload,[hashtable]$Expected,
    [ValidateSet('complete','after-acquire','lease-expired','after-work','lease-after-work','inspection-exit','inflight-sql-exit','inflight-restore-exit')][string]$Flow='complete',$AuditStage=$null){
    $pilot=Join-Path $Repository 'eng/pilot'
    foreach($helper in @('HistoricalRecoveryCoordinator.ps1','HistoricalRecoveryInFlight.ps1')){. (Join-Path $pilot $helper)}
    . (Join-Path $Repository 'tests/Fleetory.Tools.Tests/NativeAuditDataFixture.ps1')
    . (Join-Path $pilot 'historical/RetainedAuditNamespace.ps1')
    . (Join-Path $pilot 'historical/RetainedCoupledAudit.ps1')
    . (Join-Path $pilot 'historical/RetainedServerStage.ps1')
    . (Join-Path $pilot 'historical/RetainedConfiguration.ps1')
    . (Join-Path $pilot 'historical/RetainedInFlightSql.ps1')
    . (Join-Path $pilot 'historical/RetainedInFlightRestore.ps1')
    $serverEnabled=$null -ne $AuditStage -and $AuditStage.ContainsKey('ServerEnabled') -and $AuditStage.ServerEnabled
    $configuration=if($null -ne $AuditStage){New-RetainedConfiguration $AuditStage.Material $serverEnabled $AuditStage.Historical}else{$null}
    $configurationPin=if($null -ne $configuration){$configuration.Sha256}else{Get-ImmuDataHash ([Text.Encoding]::UTF8.GetBytes('postgres-only.v1'))}
    if($null -ne $AuditStage -and $AuditStage.ContainsKey('ExpectedConfigurationSha256')){
        Assert-ImmuData ($configurationPin -ceq $AuditStage.ExpectedConfigurationSha256) 'retained-service-configuration-commitment'
    }
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
    $context.Stores.Add($store);$client=${function:Invoke-Docker};$peer=$null;$proof=$null;$auditContext=$null;$auditStore=$null;$auditProof=$null;$serverProof=$null
    $meter=@{restores=0;sql=0;remove=0;auditRemove=0;copiedClaimsRefused=0;removeReplayRefused=$false;bootstrapped=$false;
        nativeDispatches=0;workInspections=0;controllerLossObserved=$false;workLossProof=$null;configurationWrites=0;configurationDriftRefusals=0;configurationReadonlyRefusals=0}
    foreach($entry in @{schemaRestores=0;dataRestoreAttempts=0;restoreLockVerified=$false;processObservationChecks=0;inflightPending=$false;inflightObserved=$false;inflightObservationCalls=0;inflightObserver=$null;inflightBirth=$null;inflightNativePid=0;inflightClientExited=$false;lateWorkRefusals=0}.GetEnumerator()){$meter[$entry.Key]=$entry.Value}
    $clock=[Diagnostics.Stopwatch]::StartNew();$inventories=@{}
    function New-IndependentControllerStart([string]$ModeFlow,[string]$Mode){
        $start=New-HistoricalChildStart $comparisonPython
        $start.WorkingDirectory=$pilot
        foreach($part in @('-I','-S','-B',(Join-Path $pilot 'historical/retained_source_bootstrap.py'),'historical-observation',$Mode,$ModeFlow,
            $plan.nonce,$comparisonPythonHash,$codeSnapshot.comparisonSourcePins)){$start.ArgumentList.Add($part)}
        return $start
    }
    function Read-RetainedPg([switch]$CleanupOnly){
        $identifier=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
        $reply=Invoke-AuditDataContainerOperation $context $store 'Inspect' @('inspect',$identifier) -TimeoutSeconds 5
        Assert-ImmuData ($reply.ExitCode -eq 0) 'retained-pg-inspection'
        $items=@($reply.Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
        Assert-ImmuData ($items.Count -eq 1) 'retained-pg-single-object'
        Assert-NativeJournal $items[0] $identifier $store.Session $context.ImageId $store.Started -CleanupOnly:$CleanupOnly
        return $identifier
    }
    function Confirm-RetainedLiveWork([Threading.CancellationToken]$Token=$peer.cancel.Token){
        if($null -ne $AuditStage -and $AuditStage.ContainsKey('AdmissionPeer')){Confirm-RetainedServiceUseLive $AuditStage.AdmissionPeer $Token}
        Assert-ImmuData ($clock.Elapsed.TotalSeconds -lt 75 -and $null -ne $peer -and -not $peer.holder.HasExited -and
            $peer.workAdmitted -and $peer.workRequests -eq 1 -and -not $peer.expiredLiveCleanup -and $peer.workStatusRequests -lt 256) 'retained-work-window'
        Send-IndependentFrame $peer.input ([Text.Encoding]::ASCII.GetBytes('work-status')) $Token;$peer.workStatusRequests++
        $frame=Read-IndependentFrame $peer.output $Token 2048
        if($frame -cne ('alive:'+$peer.projection)){
            if($Flow -ceq 'inspection-exit' -and $peer.workStatusRequests -eq 2 -and $peer.workStatusChecks -eq 1 -and
                $meter.workInspections -eq 1 -and $meter.nativeDispatches -eq 0){
                $peer.input.Dispose()
                $meter.workLossProof=Receive-HistoricalCoordinatorCompletion $peer 'terminate' $frame
                $meter.controllerLossObserved=$true
                throw [InvalidOperationException]::new('Retained coordinator exited after inspection; native work refused.')
            }
            throw 'Unexpected retained work-status reply; native work refused.'
        }
        $peer.workStatusChecks++
        # Runtime inspection and status transport may have waited: reserve the full 15-second native budget again.
        Assert-ImmuData ($clock.Elapsed.TotalSeconds -lt 75 -and -not $peer.holder.HasExited) 'retained-work-window-after-status'
    }
    function Invoke-RetainedPgNative([string[]]$Arguments,[byte[]]$InputBytes=$null,[switch]$AllowFailure){
        Confirm-RetainedLiveWork
        $identifier=Read-RetainedPg
        $meter.workInspections++
        Confirm-RetainedLiveWork
        Assert-RetainedObservedWorkArguments $Arguments -ExpectedIdentifier $identifier -ExpectedRole postgres
        $meter.nativeDispatches++
        return Invoke-Docker $Arguments $InputBytes 15 -AllowFailure:$AllowFailure -ObserveProcess ${function:Observe-RetainedNativeProcess}
    }
    function Start-RetainedPgBackend{
        $null=Invoke-RetainedPgNative (@('exec','-d',$identifier,'postgres','-D','/var/lib/postgresql/18/recovery',
            '-c',$listen,'-c','unix_socket_directories=/var/run/postgresql','-c','shared_buffers=32MB',
            '-c','max_connections=20','-c','password_encryption=scram-sha-256','-c','log_statement=none','-c','log_min_error_statement=panic')+$tlsArguments)
        $ready=$false
        for($n=0;$n-lt40;$n++){
            $r=Invoke-RetainedPgNative @('exec',$identifier,'pg_isready','-q','-U','postgres') -AllowFailure
            if($r.ExitCode-eq0){$ready=$true;break};Start-Sleep -Milliseconds 100
        }
        Assert-ImmuData $ready 'retained-pg-ready';$meter.bootstrapped=$true
    }
    function Pg-Sql([ValidateSet('postgres','fleetory','fleetory_signer')][string]$Database,[string]$Sql){
        $identifier=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client);$meter.sql++
        return Invoke-RetainedPgNative @('exec','-i','-e','PGCLIENTENCODING=UTF8',$identifier,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',$Database) ([Text.Encoding]::UTF8.GetBytes($Sql))
    }
    function Invoke-RetainedAuditNative([string[]]$Arguments,[byte[]]$InputBytes=$null,[switch]$AllowFailure){
        Confirm-RetainedLiveWork
        $auditId=Read-RetainedAuditNamespace $auditContext $auditStore
        $meter.workInspections++
        Confirm-RetainedLiveWork
        Assert-RetainedObservedWorkArguments $Arguments -ExpectedIdentifier $auditId -ExpectedRole audit
        $meter.nativeDispatches++
        return Invoke-Docker $Arguments $InputBytes 15 -AllowFailure:$AllowFailure -ObserveProcess ${function:Observe-RetainedNativeProcess}
    }
    function Read-RetainedInventory([ValidateSet('fleetory','fleetory_signer')][string]$database){
        $sql=Invoke-NativeBytes $Python @('-I','-S','-B',(Join-Path $pilot 'historical/retained_source_bootstrap.py'),'inventory','sql','--database',$database) -TimeoutSeconds 10
        Assert-ImmuData ($sql.ExitCode-eq0-and[string]::IsNullOrWhiteSpace($sql.Stderr)) 'retained-pg-readback-sql'
        $native=Pg-Sql $database $sql.Stdout
        $decoded=Invoke-NativeBytes $Python @('-I','-S','-B',(Join-Path $pilot 'historical/retained_source_bootstrap.py'),'inventory','readback','--database',$database) $native.StdoutBytes 10
        Assert-ImmuData ($decoded.ExitCode-eq0-and[string]::IsNullOrWhiteSpace($decoded.Stderr)) 'retained-pg-readback-parser'
        $value=$decoded.Stdout|ConvertFrom-Json -AsHashtable -Depth 20
        foreach($field in @('inventorySha256','securitySha256')){
            Assert-ImmuData ($value.inventory[$field]-ceq$Expected[$database].inventory[$field]) 'retained-pg-inventory'
        }
        Assert-ImmuData ($value.additionalSecuritySha256-ceq$Expected[$database].additionalSecuritySha256) 'retained-pg-role-state'
        return $value
    }
    function Write-RetainedConfiguredFile([ValidateSet('postgres','audit')][string]$Role,[string]$Path,[string]$Value){
        Assert-RetainedConfigurationValue $configuration ($Role+':'+$Path) $Value
        $id=if($Role -ceq 'postgres'){[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)}else{[Fleetory.Pilot.AuditContainerCustody]::Id($auditContext,$auditStore,$client)}
        $arguments=@('exec','-i',$id,'/bin/sh','-c','set -eu; umask 077; test ! -L "$1"; cat > "$1"; stat -c %a:%u:%h "$1"; sha256sum "$1"','fixture',$Path)
        $bytes=[Text.Encoding]::UTF8.GetBytes($Value)
        $reply=if($Role -ceq 'postgres'){Invoke-RetainedPgNative $arguments $bytes}else{Invoke-RetainedAuditNative $arguments $bytes}
        $lines=@($reply.Stdout.TrimEnd() -split '\r?\n');$uid=if($Role -ceq 'postgres'){'999'}else{'3322'}
        Assert-ImmuData ($lines.Count -eq 2 -and $lines[0] -ceq ('600:'+$uid+':1') -and
            $lines[1] -ceq ((Get-ImmuDataHash $bytes)+'  '+$Path)) 'retained-configuration-file-bytes'
        $meter.configurationWrites++
    }
    function Write-RetainedPgSlot([string]$Path,[string]$Value){Write-RetainedConfiguredFile 'postgres' $Path $Value}
    function Remove-RetainedAuditChild{
        if($null -eq $auditStore -or $null -eq $auditStore.Id -or [Fleetory.Pilot.AuditContainerCustody]::Closed($auditContext,$auditStore,$client)){return}
        $auditId=Read-RetainedAuditNamespace $auditContext $auditStore -CleanupOnly
        $null=Invoke-AuditDataContainerOperation $auditContext $auditStore 'Remove' @('rm','--force',$auditId)
        $null=Invoke-AuditDataContainerOperation $auditContext $auditStore 'ConfirmRemoval' @('inspect',$auditId)
        $meter.auditRemove++
    }
    function Remove-OwnedHistoricalResources{
        try{Remove-RetainedAuditChild}finally{
            if(-not [Fleetory.Pilot.AuditContainerCustody]::Closed($context,$store,$client)){
                $identifier=Read-RetainedPg -CleanupOnly
                $meter.remove++
                $null=Invoke-AuditDataContainerOperation $context $store 'Remove' @('rm','--force',$identifier)
                $null=Invoke-AuditDataContainerOperation $context $store 'ConfirmRemoval' @('inspect',$identifier)
            }
        }
        $script:cleanup=$true
    }
    if($null -ne $configuration){
        $first=@($configuration.Values.Keys)[0];$original=$configuration.Values[$first]
        try{([Collections.Generic.IDictionary[string,string]]$configuration.Values).set_Item($first,'drift')}catch{
            if($_.Exception.GetBaseException() -isnot [NotSupportedException]){throw}
            $meter.configurationReadonlyRefusals++
        }
        Assert-ImmuData ($meter.configurationReadonlyRefusals -eq 1 -and $configuration.Values[$first] -ceq $original) 'retained-configuration-readonly'
        foreach($path in @('/tmp/cli.toml','/tmp/unplanned-config')){
            try{Write-RetainedConfiguredFile 'audit' $path 'drift-value'}catch{
                if($_.Exception.GetBaseException() -isnot [InvalidOperationException]){throw}
                $meter.configurationDriftRefusals++;continue
            }
            throw 'Retained configuration drift accepted.'
        }
        Assert-ImmuData ($meter.configurationDriftRefusals -eq 2 -and $meter.nativeDispatches -eq 0) 'retained-configuration-no-native-drift'
    }
    try{
        $peer=Open-HistoricalRecoveryCoordinator $Flow
        Enter-HistoricalCoordinatorAllocation $peer
        if($null -ne $AuditStage -and $AuditStage.ContainsKey('AdmissionPeer')){Confirm-RetainedServiceUseLive $AuditStage.AdmissionPeer $peer.cancel.Token}
        $store.Id=Invoke-AuditDataContainerOperation $context $store 'Create' (Get-NativeJournalArguments $store.Session) -TimeoutSeconds 15
        $identifier=Read-RetainedPg
        if($null -ne $AuditStage){
            $auditContext=New-RetainedAuditNamespace $context $store $AuditStage.ImageContext
            $auditStore=@{Session=$auditContext.Fixture;Name=('fleetory-retained-audit-'+$auditContext.Fixture.Replace('-',''));
                Role='retained-coupled-audit';Started=[DateTimeOffset]::UtcNow;Id=$null}
            $auditContext.Stores.Add($auditStore)
            if($AuditStage.ContainsKey('AdmissionPeer')){Confirm-RetainedServiceUseLive $AuditStage.AdmissionPeer $peer.cancel.Token}
            $auditStore.Id=Invoke-AuditDataContainerOperation $auditContext $auditStore 'Create' (Get-RetainedAuditArguments $auditContext $auditStore) -TimeoutSeconds 15
            $null=Read-RetainedAuditNamespace $auditContext $auditStore
        }
        foreach($variant in @(@{context=$context.Clone();store=$store},@{context=$context;store=$store.Clone()})){
            try{$null=[Fleetory.Pilot.AuditContainerCustody]::Id($variant.context,$variant.store,$client)}
            catch [InvalidOperationException]{$meter.copiedClaimsRefused++;continue}
            throw 'Copied PostgreSQL resource claim accepted.'
        }
        $commitment=[Text.Encoding]::UTF8.GetBytes(($plan.nonce,$context.ImageId,$identifier,$capturePin,
            $Payload.packetSha256['application-postgres'],$Payload.packetSha256['signer-postgres'],
            ($Expected|ConvertTo-Json -Depth 20 -Compress),
            $(if($null -ne $AuditStage){$auditStore.Id+'|'+$auditContext.ImageId+'|'+($AuditStage.Point|ConvertTo-Json -Compress)+'|'+$AuditStage.ImageContext.ProbeHash}else{'postgres-only'}),$configurationPin -join '|'))
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
            $listen='listen_addresses=';$tlsArguments=@()
            if($serverEnabled){
                $tls=$AuditStage.Material.PostgresTls
                foreach($entry in @(@('/tmp/ca.pem',$tls.RootCertificatePem),@('/tmp/server.crt',$tls.ServerCertificatePem),@('/tmp/server.key',$tls.ServerPrivateKeyPem))){Write-RetainedPgSlot $entry[0] $entry[1]}
                Write-RetainedPgSlot '/tmp/hba.conf' (Get-RetainedPgHba)
                $listen='listen_addresses=127.0.0.1'
                $tlsArguments=@('-c','hba_file=/tmp/hba.conf','-c','ssl=on','-c','ssl_cert_file=/tmp/server.crt','-c','ssl_key_file=/tmp/server.key','-c','ssl_min_protocol_version=TLSv1.2')
            }
            Start-RetainedPgBackend
            $roles=''
            foreach($role in @('fleetory_migrator','fleetory_server','fleetory_signer_owner','fleetory_signer')){
                $login=if($role-cin@('fleetory_server','fleetory_signer')){'LOGIN'}else{'NOLOGIN'}
                $roles+='CREATE ROLE '+$role+' '+$login+' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;'
            }
            $null=Pg-Sql 'postgres' $roles
            if($serverEnabled){
                foreach($entry in @(@('fleetory_server','database'),@('fleetory_signer','signer'))){
                    $password=$AuditStage.Material.Secrets[$entry[1]]
                    Assert-ImmuData ($password -cmatch '^[a-f0-9]{64}\z') 'retained-fresh-runtime-password'
                    Assert-RetainedConfigurationValue $configuration ('credential:postgres/'+$entry[0]) $password
                    $null=Pg-Sql 'postgres' ("ALTER ROLE "+$entry[0]+" PASSWORD '"+$password+"';")
                }
                $scram=Pg-Sql 'postgres' 'SELECT count(*)=2 AND bool_and(rolpassword LIKE ''SCRAM-SHA-256$%'') FROM pg_authid WHERE rolname IN (''fleetory_server'',''fleetory_signer'');'
                Assert-ImmuData ($scram.Stdout.Trim() -ceq 't') 'retained-runtime-scram-hashes'
            }
            foreach($database in @('fleetory','fleetory_signer')){
                $owner=if($database-ceq'fleetory'){'fleetory_migrator'}else{'fleetory_signer_owner'}
                $runtime=if($database-ceq'fleetory'){'fleetory_server'}else{'fleetory_signer'}
                $kind=if($database-ceq'fleetory'){'application-postgres'}else{'signer-postgres'}
                $null=Pg-Sql 'postgres' ("CREATE DATABASE $database OWNER $owner;REVOKE ALL ON DATABASE $database FROM PUBLIC;GRANT CONNECT ON DATABASE $database TO $runtime;")
                if($Flow -ceq 'inflight-restore-exit' -and $database -ceq 'fleetory'){
                    $null=Invoke-RetainedPgNative @('exec','-i',$identifier,'pg_restore','--section=pre-data','--exit-on-error',
                        '--single-transaction','--no-password','--role=fleetory_migrator','--username=postgres','--dbname=fleetory') $copy[$kind]
                    $meter.schemaRestores++
                    Start-RetainedRestoreLock
                    Invoke-RetainedInFlightRestore $copy[$kind]
                }
                $null=Invoke-RetainedPgNative @('exec','-i',$identifier,'pg_restore','--exit-on-error','--single-transaction',
                    '--no-password',('--role='+$owner),'--username=postgres',('--dbname='+$database)) $copy[$kind]
                $meter.restores++
                $inventories[$database]=Read-RetainedInventory $database
            }
            if($null -ne $AuditStage -and $AuditStage.ContainsKey('GeneratedAdmissionFault') -and $AuditStage.GeneratedAdmissionFault){
                if($AuditStage.GeneratedAdmissionExpiry){
                    $meter.admissionExpiryMilliseconds=Wait-GeneratedRetainedServiceUseExpiry $AuditStage.AdmissionPeer
                }else{Invoke-GeneratedRetainedServicePeerExit $AuditStage.AdmissionPeer}
                $meter.admissionLossDispatches=$meter.nativeDispatches
                try{Confirm-RetainedLiveWork;throw 'Generated dead admission accepted.'}catch{
                    if($_.Exception.Message -notmatch 'service-peer-actual-owner'){throw}
                }
                $meter.admissionLossVerified=$true
                throw [InvalidOperationException]::new('retained-service-admission-lost-native-refused')
            }
            if($null -ne $AuditStage){
                $auditArgs=@{Namespace=$auditContext;AuditStore=$auditStore;Material=$AuditStage.Material;Archive=$copy['audit-immudb'];
                    Snapshot=$copy['audit-export'];Nonce=$Payload.capture.nonce;Point=$AuditStage.Point;ImageContext=$AuditStage.ImageContext;Historical=$AuditStage.Historical}
                $auditProof=Invoke-RetainedCoupledAudit @auditArgs
            }
            if($Flow -ceq 'inflight-sql-exit'){
                Invoke-RetainedInFlightSql
            }elseif($Flow -ceq 'after-work'){
                $proof=Finish-HistoricalRecoveryCoordinator $peer 'terminate'
            }elseif($Flow -ceq 'lease-after-work'){
                Assert-ImmuData ($peer.workRequests -eq 1 -and $peer.workAdmitted) 'retained-after-work-lease'
                while($peer.lease.Elapsed.TotalSeconds -lt 5){
                    $peer.cancel.Token.ThrowIfCancellationRequested()
                    Assert-ImmuData (-not $peer.holder.HasExited) 'retained-after-work-controller-live'
                    Start-Sleep -Milliseconds 50
                }
                Send-HistoricalCoordinatorFrame $peer 'status'
                Receive-HistoricalCoordinatorFrame $peer 'alive'
                Remove-OwnedHistoricalResources
                Assert-ImmuData $script:cleanup 'retained-after-work-cleanup'
                Send-HistoricalCoordinatorFrame $peer 'work';$peer.workRequests++
                Receive-HistoricalCoordinatorFrame $peer 'late-work'
                $peer.expiredLiveCleanup=$true
                $proof=Finish-HistoricalRecoveryCoordinator $peer 'refused'
            }else{
                if($serverEnabled){
                    $serverProof=Invoke-RetainedServerStage $auditContext $auditStore $AuditStage.Material $copy['audit-export'] $Payload.capture.nonce $auditProof.observationExpectation $AuditStage.Historical
                    foreach($database in @('fleetory','fleetory_signer')){$null=Read-RetainedInventory $database}
                    $serverProof.postHostInventoriesVerified=$true
                }
                $proof=Finish-HistoricalRecoveryCoordinator $peer 'completed'
            }
        }
    }catch{
        if($meter.ContainsKey('admissionLossVerified') -and $meter.admissionLossVerified){
            Assert-ImmuData ($_.Exception.Message -ceq 'retained-service-admission-lost-native-refused' -and
                $meter.restores -eq 2 -and $null -eq $auditProof -and $null -eq $serverProof -and
                $meter.nativeDispatches -eq $meter.admissionLossDispatches -and
                $AuditStage.AdmissionPeer.holder.HasExited -and $AuditStage.AdmissionPeer.holder.ExitCode -ne 0) 'retained-service-loss-no-late-work'
        }elseif($Flow -cin @('inflight-sql-exit','inflight-restore-exit')){
            if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw}
            Confirm-RetainedInterruptedNative
        }elseif($Flow -cne 'inspection-exit' -or -not $meter.controllerLossObserved -or $meter.nativeDispatches -ne 0 -or
            $meter.workInspections -ne 1 -or $_.Exception.GetBaseException() -isnot [InvalidOperationException]){throw}
        $proof=$meter.workLossProof
    }finally{
        try{Close-HistoricalRecoveryCoordinator $peer}finally{
            if($null-ne$store.Id){Remove-OwnedHistoricalResources}
            if($null -ne $meter.inflightObserver){$meter.inflightObserver.Dispose()}
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
        admissionLossAfterPgRestoreVerified=($meter.ContainsKey('admissionLossVerified') -and $meter.admissionLossVerified);
        admissionOriginalExpiryMilliseconds=$(if($meter.ContainsKey('admissionExpiryMilliseconds')){$meter.admissionExpiryMilliseconds}else{0});
        copiedClaimsRefused=$meter.copiedClaimsRefused;cleanupVerified=$true;ownRemovalCalls=$meter.remove;baseImageRemoved=$false;
        removalReplayRefusedBeforeNativeCall=$true;baseImageId=$context.ImageId;unknownCreateOutcomeRecoveryVerified=$false;
        independentCreatorDeathCleanupVerified=$false;runtimeLoginVerified=($null -ne $serverProof);nativeAuditRestored=($null -ne $auditProof);serverStarted=($null -ne $serverProof);server=$serverProof;
        audit=$auditProof;auditContainerId=$(if($null -ne $auditStore){$auditStore.Id}else{$null});ownedAuditRemovalCalls=$meter.auditRemove;
        nativeWorkDispatches=$meter.nativeDispatches;runtimeWorkInspections=$meter.workInspections;
        controllerLossAfterInspectionRefused=($Flow -ceq 'inspection-exit' -and $meter.controllerLossObserved);
        processObservationChecks=$meter.processObservationChecks;
        inFlightSql=(Get-RetainedInFlightResult 'inflight-sql-exit');inFlightRestore=(Get-RetainedInFlightResult 'inflight-restore-exit');
        nativePgPreDataSchemaRestores=$meter.schemaRestores;nativePgDataRestoreAttempts=$meter.dataRestoreAttempts;ownRestoreLockVerified=$meter.restoreLockVerified;
        configurationSha256=$configurationPin;configurationFilesVerified=$meter.configurationWrites;
        configurationDriftRefusalsBeforeNativeCall=$meter.configurationDriftRefusals;configurationReadonlyRefusals=$meter.configurationReadonlyRefusals;
        originalUseAuthenticated=$false;executionAuthorized=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
