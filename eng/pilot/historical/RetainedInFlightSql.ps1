#requires -Version 7.3
# Private functions run in the live retained owner's scope. No serialized process/resource claim is accepted.
function Assert-RetainedObservedWorkArguments([string[]]$Arguments){
    Assert-ImmuData ($null -ne $Arguments -and $Arguments.Count -ge 3 -and $Arguments[0] -ceq 'exec') 'observed-client-exec-only'
}
function Observe-RetainedNativeProcess([Diagnostics.Process]$Process,[Threading.CancellationToken]$Token){
    $meter.processObservationChecks++
    Confirm-RetainedLiveWork $Token
    if($meter.inflightPending){Interrupt-RetainedActiveSql $Process $Token}
}
function Interrupt-RetainedActiveSql([Diagnostics.Process]$Process,[Threading.CancellationToken]$Token){
    Assert-ImmuData ($Flow -ceq 'inflight-sql-exit' -and $meter.inflightPending -and -not $meter.inflightObserved -and
        $Token.CanBeCanceled -and -not $Process.HasExited -and $Process.ProcessName -ceq 'docker' -and $meter.inflightWatch.Elapsed.TotalSeconds -lt 8) 'retained-inflight-fault-scope'
    $Token.ThrowIfCancellationRequested()
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
    $meter.inflightObserver=[Diagnostics.Process]::GetProcessById($Process.Id)
    $null=$meter.inflightObserver.Handle
    $birth=Get-HistoricalNativeBirth $Process
    $other=Get-HistoricalNativeBirth $meter.inflightObserver
    Assert-ImmuData ($birth.kind -ceq $other.kind -and $birth.token -ceq $other.token) 'retained-inflight-client-birth'
    $meter.inflightBirth=$birth;$meter.inflightNativePid=$Process.Id
    $sql="SELECT count(*) FROM pg_stat_activity WHERE datname='postgres' AND usename='postgres' AND application_name='"+
        $meter.inflightApplication+"' AND state='active' AND wait_event_type='Timeout' AND wait_event='PgSleep' AND query='"+$meter.inflightSql+"';"
    $meter.inflightObservationCalls++
    $reply=Invoke-Docker @('exec','-i',$id,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres') ([Text.Encoding]::UTF8.GetBytes($sql)) 2
    Assert-ImmuData ($reply.ExitCode -eq 0 -and $reply.Stdout.Trim() -ceq '1' -and [string]::IsNullOrWhiteSpace($reply.Stderr) -and
        -not $Process.HasExited) 'retained-inflight-query-actually-active'
    $Token.ThrowIfCancellationRequested()
    $meter.inflightObserved=$true
    $meter.dispatchesAtInterruption=$meter.nativeDispatches
    Send-IndependentFrame $peer.input ([Text.Encoding]::ASCII.GetBytes('interrupt-inflight:'+$peer.projection)) $Token
    $frame=Read-IndependentFrame $peer.output $Token 2048
    $peer.input.Dispose()
    $meter.workLossProof=Receive-HistoricalCoordinatorCompletion $peer 'terminate' $frame -Token $Token
    $meter.controllerLossObserved=$true
    throw [OperationCanceledException]::new('Retained coordinator exited during native SQL.', $Token)
}
function Invoke-RetainedInFlightSql{
    Assert-ImmuData ($Flow -ceq 'inflight-sql-exit' -and $null -ne $auditProof -and $meter.restores -eq 2) 'retained-inflight-restored-scope'
    $meter.inflightApplication='fleetory-inflight-'+$plan.nonce
    Assert-ImmuData ($meter.inflightApplication -cmatch '^fleetory-inflight-[a-f0-9-]{36}\z') 'retained-inflight-application'
    $meter.inflightSql='SELECT pg_sleep(10) /* '+$meter.inflightApplication+' */;'
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
    $meter.inflightPending=$true;$meter.inflightWatch=[Diagnostics.Stopwatch]::StartNew()
    try{
        $null=Invoke-RetainedPgNative @('exec','-i','-e',('PGAPPNAME='+$meter.inflightApplication),$id,'psql','-XqAt',
            '-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres') ([Text.Encoding]::UTF8.GetBytes($meter.inflightSql))
        throw 'Retained in-flight fault did not interrupt the native operation.'
    }finally{$meter.inflightPending=$false}
}
function Confirm-RetainedInterruptedSql{
    Assert-ImmuData ($meter.inflightObserved -and $meter.controllerLossObserved -and $meter.inflightObservationCalls -eq 1 -and
        $null -ne $meter.inflightObserver -and $meter.inflightObserver.HasExited -and $peer.holder.HasExited -and
        $meter.workLossProof.coordinatorExitCode -ne 0 -and $meter.workLossProof.membersAbsent -and
        $meter.nativeDispatches -eq $meter.dispatchesAtInterruption) 'retained-inflight-native-client-cancelled'
    $meter.inflightClientExited=$true
    $before=$meter.nativeDispatches
    try{
        $id=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
        $null=Invoke-RetainedPgNative @('exec','-i',$id,'psql','-XqAt','-U','postgres','-d','postgres') ([Text.Encoding]::UTF8.GetBytes('SELECT 1;'))
    }catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: retained-work-window'){throw}
        $meter.lateWorkRefusals++
    }
    Assert-ImmuData ($meter.lateWorkRefusals -eq 1 -and $meter.nativeDispatches -eq $before) 'retained-inflight-no-late-work'
}
