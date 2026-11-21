#requires -Version 7.3
# Generated pre-data/COPY fault only, inside the already-owned PostgreSQL target.
function Start-RetainedRestoreLock{
    Assert-ImmuData ($Flow -ceq 'inflight-restore-exit' -and $meter.schemaRestores -eq 1 -and $meter.restores -eq 0) 'retained-restore-lock-scope'
    $meter.restoreLockApplication='fleetory-restore-lock-'+$plan.nonce
    Assert-ImmuData ($meter.restoreLockApplication -cmatch '^fleetory-restore-lock-[a-f0-9-]{36}\z') 'retained-restore-lock-marker'
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
    $sql='BEGIN; LOCK TABLE platform.audit_events IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(30); ROLLBACK;'
    $null=Invoke-RetainedPgNative @('exec','-d','-e',('PGAPPNAME='+$meter.restoreLockApplication),$id,'psql','-XqAt',
        '-v','ON_ERROR_STOP=1','-U','postgres','-d','fleetory','-c',$sql)
    $check="SELECT count(*) FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.datname='fleetory' AND a.usename='postgres' AND a.application_name='"+
        $meter.restoreLockApplication+"' AND a.state='active' AND a.wait_event_type='Timeout' AND a.wait_event='PgSleep' AND l.locktype='relation' AND l.mode='AccessExclusiveLock' AND l.granted AND l.relation='platform.audit_events'::regclass;"
    for($attempt=0;$attempt -lt 20;$attempt++){
        $result=Pg-Sql 'fleetory' $check
        if($result.Stdout.Trim() -ceq '1'){$meter.restoreLockVerified=$true;break}
        Start-Sleep -Milliseconds 100
    }
    Assert-ImmuData $meter.restoreLockVerified 'retained-restore-own-lock-granted'
}
function Get-RetainedRestoreObservation{
    Assert-ImmuData ($Flow -ceq 'inflight-restore-exit' -and $meter.restoreLockVerified) 'retained-restore-observation-purpose'
    return @{Database='fleetory';Sql=("SELECT count(*) FROM pg_stat_activity a WHERE a.datname='fleetory' AND a.usename='postgres' AND a.application_name='"+
        $meter.inflightApplication+"' AND a.state='active' AND a.wait_event_type='Lock' AND a.query LIKE 'COPY platform.audit_events %FROM stdin%' AND EXISTS (SELECT 1 FROM pg_stat_activity b JOIN pg_locks l ON l.pid=b.pid WHERE b.pid=ANY(pg_blocking_pids(a.pid)) AND b.application_name='"+
        $meter.restoreLockApplication+"' AND b.datname='fleetory' AND b.state='active' AND b.wait_event='PgSleep' AND l.locktype='relation' AND l.mode='AccessExclusiveLock' AND l.granted AND l.relation='platform.audit_events'::regclass);")}
}
function Invoke-RetainedInFlightRestore([byte[]]$Archive){
    Assert-ImmuData ($Flow -ceq 'inflight-restore-exit' -and $meter.restoreLockVerified -and $meter.schemaRestores -eq 1 -and
        $meter.dataRestoreAttempts -eq 0 -and (Get-ImmuDataHash $Archive) -ceq $Payload.packetSha256['application-postgres']) 'retained-data-restore-frozen-input'
    $meter.inflightApplication='fleetory-restore-'+$plan.nonce
    Assert-ImmuData ($meter.inflightApplication -cmatch '^fleetory-restore-[a-f0-9-]{36}\z') 'retained-data-restore-marker'
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
    $meter.dataRestoreAttempts++;$meter.inflightPending=$true;$meter.inflightWatch=[Diagnostics.Stopwatch]::StartNew()
    try{
        $null=Invoke-RetainedPgNative @('exec','-i','-e',('PGAPPNAME='+$meter.inflightApplication),$id,'pg_restore','--data-only',
            '--exit-on-error','--single-transaction','--no-password','--role=fleetory_migrator','--username=postgres','--dbname=fleetory') $Archive
        throw 'Expected actual COPY interruption did not occur.'
    }finally{$meter.inflightPending=$false}
}
function Get-RetainedInFlightResult([string]$SelectedFlow){
    $active=$Flow -ceq $SelectedFlow
    return @{nativeClientPid=$(if($active){$meter.inflightNativePid}else{0});nativeClientBirth=$(if($active){$meter.inflightBirth}else{$null});
        actualQueryActive=($active -and $meter.inflightObserved);observationCalls=$(if($active){$meter.inflightObservationCalls}else{0});
        nativeClientExitVerified=($active -and $meter.inflightClientExited);lateNativeWorkRefusals=$(if($active){$meter.lateWorkRefusals}else{0});
        coordinatorLost=($active -and $meter.controllerLossObserved);metadataGrantsAuthority=$false}
}
