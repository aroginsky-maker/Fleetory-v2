#requires -Version 7.3
# Extends only the caller's positively owned fresh Server stores and generated credentials.
function Get-PipelineEventJson([string]$Action='Fixture.Database.Read'){
    Assert-True ($Action -cin @('Fixture.Database.Read','Fixture.Worker.Read','Fixture.Worker.AfterStop','Fixture.Host.Read')) 'Unknown fixture inventory action.'
    $sql=@'
SELECT jsonb_build_object('eventId',replace(event_id::text,'-',''),'actorSubjectId',actor_subject_id,
 'actorKind',actor_kind,'Action',action,'targetType',target_type,'targetId',target_id,
 'correlationId',correlation_id,'occurredAt',occurred_at,'recordedAt',recorded_at,'context',context_json)::text
FROM platform.audit_events WHERE action=
'@
    $value=(Invoke-Database 'fleetory' ($sql+"'"+$Action+"';")).Stdout.Trim()
    Assert-True ($value.Length -gt 0 -and $value.Length -le 3072) 'Pipeline event inventory outside bounds.'
    $document=[Text.Json.JsonDocument]::Parse($value)
    try{
        $id=[Guid]::Empty
        Assert-True (@($document.RootElement.EnumerateObject()).Count -eq 10 -and
            [Guid]::TryParseExact($document.RootElement.GetProperty('eventId').GetString(),'N',[ref]$id) -and $id -ne [Guid]::Empty) 'Pipeline event inventory invalid.'
    }finally{$document.Dispose()}
    return $value
}
function Get-PipelineClock{
    $value=(Invoke-Database 'fleetory' 'SELECT clock_timestamp()::text;').Stdout.Trim()
    return [DateTimeOffset]::Parse($value,[Globalization.CultureInfo]::InvariantCulture).ToUniversalTime().ToString('O',[Globalization.CultureInfo]::InvariantCulture)
}
function Assert-PipelineState([int]$Queue,[int]$Attempts=0,[int]$Delay=0,[string]$Before=''){
    Assert-True ($Queue -in @(0,1) -and $Attempts -in @(0,1,2) -and $Delay -in @(0,2,4)) 'Unknown pipeline state assertion.'
    $sql='SELECT (SELECT count(*) FROM platform.audit_events)=1 AND (SELECT count(*) FROM platform.audit_export_queue)='+$Queue
    if($Queue -eq 1){
        $condition='attempt_count='+$Attempts+' AND lease_id IS NULL AND leased_until IS NULL'
        if($Delay -gt 0){
            $parsed=[DateTimeOffset]::ParseExact($Before,'O',[Globalization.CultureInfo]::InvariantCulture)
            $literal=$parsed.ToUniversalTime().ToString('O',[Globalization.CultureInfo]::InvariantCulture)
            $condition+=" AND next_attempt_at >= TIMESTAMPTZ '"+$literal+"' + INTERVAL '"+$Delay+" seconds' AND next_attempt_at <= clock_timestamp() + INTERVAL '"+$Delay+" seconds'"
        }
        $sql+=' AND (SELECT bool_and('+$condition+') FROM platform.audit_export_queue)'
    }
    Assert-True ((Invoke-Database 'fleetory' ($sql+';')).Stdout.Trim() -ceq 't') 'Pipeline retained/acknowledged queue state drift.'
}
function Wait-PipelineDue{
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    try{
        do{
            $due=Invoke-Database 'fleetory' 'SELECT count(*)=1 AND bool_and(next_attempt_at<=clock_timestamp() AND lease_id IS NULL AND leased_until IS NULL) FROM platform.audit_export_queue;'
            if($due.Stdout.Trim() -ceq 't'){return}
            Assert-True ($deadline.Elapsed.TotalSeconds -lt 20) 'Native pipeline retry did not become due.'
            Start-Sleep -Milliseconds 200
        }while($true)
    }finally{$deadline.Stop()}
}
function Invoke-NativeOutboxPipeline{
    $pipelineEvent=Get-PipelineEventJson
    $packet=[Text.Encoding]::UTF8.GetBytes(('{"admin":"'+$secrets.admin+'","expected":'+$pipelineEvent+'}'))
    Assert-True ($packet.Length -le 4096) 'Pipeline verification packet too large.'
    Assert-PipelineState 1 0
    $null=Invoke-ServerProbe 'pipeline-pending' 'pipeline-pending' $packet
    # The exact native pump must refuse its claim when queue UPDATE is absent.
    $null=Invoke-ServerProbe 'pump-update' 'pump-privilege';Assert-PipelineState 1 0
    $null=Invoke-Database 'fleetory' 'GRANT UPDATE ON platform.audit_export_queue TO fleetory_server; REVOKE DELETE ON platform.audit_export_queue FROM fleetory_server;'
    $null=Invoke-ServerProbe 'db-queue-delete' 'db-privilege'
    $rights=Invoke-Database 'fleetory' "SELECT has_table_privilege('fleetory_server','platform.audit_export_queue','UPDATE') AND NOT has_table_privilege('fleetory_server','platform.audit_export_queue','DELETE') AND NOT has_table_privilege('fleetory_server','platform.audit_events','UPDATE') AND NOT has_table_privilege('fleetory_server','platform.audit_events','DELETE');"
    Assert-True ($rights.Stdout.Trim() -ceq 't') 'Pipeline least-privilege grant drift.'
    $before=Get-PipelineClock
    Write-ServerSlot 'audit-immudb-password' $secrets.wrong
    try{$null=Invoke-ServerProbe 'pump-auth' 'pump-retained'}finally{Write-ServerSlot 'audit-immudb-password' $secrets.writer}
    Assert-PipelineState 1 1 2 $before
    $null=Invoke-ServerProbe 'pipeline-pending' 'pipeline-pending' $packet
    Wait-PipelineDue
    $before=Get-PipelineClock
    # Write succeeds in immudb; missing DELETE prevents PostgreSQL acknowledgement.
    $null=Invoke-ServerProbe 'pump-lostack' 'pump-retained'
    Assert-PipelineState 1 2 4 $before
    $null=Invoke-ServerProbe 'pipeline-verify' 'pipeline-verify' $packet
    $null=Invoke-Database 'fleetory' 'GRANT DELETE ON platform.audit_export_queue TO fleetory_server;'
    Wait-PipelineDue
    $null=Invoke-ServerProbe 'pump-deliver' 'pump-delivered';Assert-PipelineState 0
    $null=Invoke-ServerProbe 'pipeline-verify' 'pipeline-verify' $packet
    $null=Invoke-ServerProbe 'pump-empty' 'pump-empty';Assert-PipelineState 0
    $null=Invoke-ServerProbe 'pipeline-verify' 'pipeline-verify' $packet
    Assert-True ((Get-PipelineEventJson) -ceq $pipelineEvent) 'Pipeline changed the immutable PostgreSQL event.'
    return [ordered]@{nativePumpCalls=5;queueUpdateRefusals=1;queueDeleteRefusals=1;failedDeliveriesRetained=2;nativeRetryDelaysSeconds=@(2,4);
        clearedLeasesVerified=$true;durableWriteBeforeAckFailureVerified=$true;retryDelivered=1;emptyBatchDelivered=0;
        pipelineEvents=1;pipelineEventRevision=1;crossStoreFieldsVerified=10;totalAuditKeys=2;queueRowsAfterAck=0;immutableAuditEventUnchanged=$true}
}
