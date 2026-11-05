#requires -Version 7.3
# Real registered BackgroundService in the caller's generated, owned Server sandbox.
function Assert-WorkerQueue([int]$Events,[int]$Queue,[int]$Attempts=0){
    Assert-True ($Events -in @(2,3,4,5,6) -and $Queue -in @(0,1) -and $Attempts -in @(0,1)) 'Unknown worker inventory state.'
    $sql='SELECT (SELECT count(*) FROM platform.audit_events)='+$Events+' AND (SELECT count(*) FROM platform.audit_export_queue)='+$Queue
    if($Queue -eq 1){$sql+=' AND (SELECT bool_and(attempt_count='+$Attempts+' AND lease_id IS NULL AND leased_until IS NULL) FROM platform.audit_export_queue)'}
    Assert-True ((Invoke-Database 'fleetory' ($sql+';')).Stdout.Trim() -ceq 't') 'Worker queue inventory drift.'
}
function Assert-WorkerAudit([string[]]$Events,[string]$Absent=''){
    $envelope='{"admin":"'+$secrets.admin+'","events":['+($Events -join ',')+']'
    if($Absent){$envelope+=',"absent":'+$Absent}
    $packet=[Text.Encoding]::UTF8.GetBytes(($envelope+'}'))
    Assert-True ($packet.Length -le 4096) 'Worker verification packet too large.'
    $null=Invoke-ServerProbe 'worker-verify' 'worker-verify' $packet
}
function Invoke-NativeOutboxWorker{
    $baselineEvent=Get-PipelineEventJson
    $null=Invoke-ServerProbe 'db-worker-write' 'db-write'
    Assert-WorkerQueue 2 1
    $workerEvent=Get-PipelineEventJson 'Fixture.Worker.Read'
    # Manufacture only the new disposable backlog's age; no clock or retry-date overrides.
    $aged=Invoke-Database 'fleetory' "WITH aged AS (UPDATE platform.audit_export_queue SET enqueued_at=clock_timestamp()-INTERVAL '6 minutes' RETURNING audit_event_id) SELECT count(*) FROM aged;"
    Assert-True ($aged.Stdout.Trim() -ceq '1') 'Generated backlog age setup failed.'
    Assert-WorkerAudit @($baselineEvent) $workerEvent
    $null=Invoke-Database 'fleetory' 'REVOKE UPDATE ON platform.audit_export_queue FROM fleetory_server;'
    try{$denied=Invoke-ServerProbe 'worker-denied' 'worker-denied'}finally{$null=Invoke-Database 'fleetory' 'GRANT UPDATE ON platform.audit_export_queue TO fleetory_server;'}
    Assert-WorkerQueue 2 1
    Assert-WorkerAudit @($baselineEvent) $workerEvent
    Write-ServerSlot 'audit-immudb-password' $secrets.wrong
    try{$retained=Invoke-ServerProbe 'worker-retain' 'worker-retain'}finally{Write-ServerSlot 'audit-immudb-password' $secrets.writer}
    Assert-WorkerQueue 2 1 1
    Assert-WorkerAudit @($baselineEvent) $workerEvent
    $drained=Invoke-ServerProbe 'worker-drain' 'worker-drain'
    Assert-WorkerQueue 3 1
    $afterStopEvent=Get-PipelineEventJson 'Fixture.Worker.AfterStop'
    Assert-WorkerAudit @($baselineEvent,$workerEvent) $afterStopEvent
    $restarted=Invoke-ServerProbe 'worker-restart' 'worker-restart'
    Assert-WorkerQueue 3 0
    Assert-WorkerAudit @($baselineEvent,$workerEvent,$afterStopEvent)
    Assert-True ((Get-PipelineEventJson) -ceq $baselineEvent -and
        (Get-PipelineEventJson 'Fixture.Worker.Read') -ceq $workerEvent -and
        (Get-PipelineEventJson 'Fixture.Worker.AfterStop') -ceq $afterStopEvent) 'Worker changed an immutable event.'
    $runs=@($denied.lifecycle,$retained.lifecycle,$drained.lifecycle,$restarted.lifecycle)
    Assert-True (@($runs.processId|Select-Object -Unique).Count -eq 4) 'Worker process restart identity drift.'
    foreach($run in $runs){Assert-True ($run.started -eq $true -and $run.executionCompleted -eq $true -and
        $run.stopElapsedMilliseconds -ge 0 -and $run.stopElapsedMilliseconds -lt 5000) 'Worker bounded stop unverified.'}
    Assert-True ($denied.lifecycle.claimFailures -eq 1 -and $drained.lifecycle.afterStopPendingVerified -eq $true) 'Worker failure/quiescence observation missing.'
    return [ordered]@{registeredWorkerStarts=4;completedWorkerStops=4;maximumStopMilliseconds=($runs.stopElapsedMilliseconds|Measure-Object -Maximum).Maximum;
        nativeClaimFailures=1;nativeSinkFailuresRetained=1;degradedBacklogBeforeRecovery=$true;healthyAfterDrain=$true;
        afterStopEnqueueStayedPending=$true;freshProcessRestartDelivered=$true;workerEvents=2;workerEventRevisions=@(1,1);
        crossStoreFieldsPerEvent=10;totalAuditKeys=4;queueRowsAfterRestart=0;immutableEventsUnchanged=$true;directPumpCallsInWorkerCases=0}
}
