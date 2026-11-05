#requires -Version 7.3
# Actual host lifecycle, within the caller's fresh loopback-only network-none sandbox.
function Invoke-NativeServerHost{
    $priorEvents=@((Get-PipelineEventJson),(Get-PipelineEventJson 'Fixture.Worker.Read'),(Get-PipelineEventJson 'Fixture.Worker.AfterStop'))
    $null=Invoke-ServerProbe 'db-host-write' 'db-write'
    Assert-WorkerQueue 4 1
    $hostEvent=Get-PipelineEventJson 'Fixture.Host.Read'
    $aged=Invoke-Database 'fleetory' "WITH aged AS (UPDATE platform.audit_export_queue SET enqueued_at=clock_timestamp()-INTERVAL '6 minutes' RETURNING audit_event_id) SELECT count(*) FROM aged;"
    Assert-True ($aged.Stdout.Trim() -ceq '1') 'Generated host backlog setup failed.'
    Assert-WorkerAudit $priorEvents $hostEvent
    $null=Invoke-Database 'fleetory' 'REVOKE UPDATE ON platform.audit_export_queue FROM fleetory_server;'
    try{$degraded=Invoke-ServerProbe 'host-degraded' 'host-degraded'}finally{$null=Invoke-Database 'fleetory' 'GRANT UPDATE ON platform.audit_export_queue TO fleetory_server;'}
    Assert-WorkerQueue 4 1
    Assert-WorkerAudit $priorEvents $hostEvent
    $healthy=Invoke-ServerProbe 'host-drain' 'host-drain'
    Assert-WorkerQueue 4 0
    Assert-WorkerAudit (@($priorEvents)+@($hostEvent))
    $actions=@('Fixture.Database.Read','Fixture.Worker.Read','Fixture.Worker.AfterStop','Fixture.Host.Read')
    $captured=@($priorEvents)+@($hostEvent)
    for($index=0;$index -lt 4;$index++){Assert-True ((Get-PipelineEventJson $actions[$index]) -ceq $captured[$index]) 'Host changed an immutable event.'}
    $runs=@($degraded.lifecycle,$healthy.lifecycle)
    Assert-True (@($runs.processId|Select-Object -Unique).Count -eq 2) 'Native host process identity drift.'
    foreach($run in $runs){
        Assert-True ($run.applicationStarted -eq $true -and $run.applicationStopped -eq $true -and $run.workerExecutionCompleted -eq $true -and
            $run.stopElapsedMilliseconds -ge 0 -and $run.stopElapsedMilliseconds -lt 5000 -and
            ($run.listeningPorts -join ',') -ceq '19580,19581,19582' -and $run.closedPortRefusals -eq 3 -and
            $run.initialClosedPortRefusals -eq 3 -and $run.livenessBody -ceq 'Healthy' -and $run.readinessStatusCode -eq 200 -and
            $run.publicPrivilegedPathRefusals -eq 2) 'Native host lifecycle proof incomplete.'
    }
    Assert-True ($degraded.lifecycle.readinessBody -ceq 'Degraded' -and $degraded.lifecycle.claimFailures -ge 1 -and
        $healthy.lifecycle.readinessBody -ceq 'Healthy' -and $healthy.lifecycle.claimFailures -eq 0) 'Native host readiness/worker mismatch.'
    $tls=$healthy.lifecycle.clientTls
    Assert-True ($null -eq $degraded.lifecycle.clientTls -and $tls.gateways -eq 2 -and $tls.trustedClientHttpResponses -eq 2 -and
        $tls.missingClientRefusals -eq 2 -and $tls.crossRootClientRefusals -eq 2 -and $tls.wrongEkuClientRefusals -eq 2 -and
        $tls.serverRootRefusals -eq 2 -and $tls.serverHostnameRefusals -eq 2 -and $tls.protocol -ceq 'TLS1.2' -and
        $tls.nativeAuthenticationRefusals -eq 10 -and $tls.arbitraryTransportFailuresAccepted -eq 0 -and
        $tls.serverCorrelatedHandshakeRefusals -eq 6 -and $tls.serverCorrelatedTrustedHandshakes -eq 2 -and
        $tls.httpRequestsInClientRefusals -eq 0 -and
        $tls.responseStatus -eq 404 -and $tls.identityAdmissionVerified -eq $false) 'Native client TLS proof incomplete.'
    return [ordered]@{applicationStarts=2;applicationStops=2;maximumStopMilliseconds=($runs.stopElapsedMilliseconds|Measure-Object -Maximum).Maximum;
        workerExecutionCompleted=$true;httpHealthBodiesVerified=4;degradedAndHealthyBothStatus200=$true;publicPrivilegedPathRefusals=4;
        listenersVerifiedPerHost=3;closedPortRefusals=6;initialClosedPortRefusals=6;nativeClaimFailureObserved=$true;
        automaticDrainVerified=$true;totalAuditKeys=5;hostEventRevision=1;crossStoreFieldsPerEvent=10;
        queueRowsAfterHostRestart=0;immutableEventsUnchanged=$true;manualWorkerStartsInHostCases=0;clientTls=$tls;issuerActivated=$false}
}
