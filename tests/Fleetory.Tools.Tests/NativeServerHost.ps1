#requires -Version 7.3
# Actual host lifecycle, within the caller's fresh loopback-only network-none sandbox.
function Seed-NativeRegisteredIdentity{
    $agentPublic=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($agent.IdentityClientCertificatePem)
    $adminPublic=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($admin.IdentityClientCertificatePem)
    try{
        $agentHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($agentPublic.RawData))
        $adminHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($adminPublic.RawData))
        $device=$agentDevice.ToString('D');$subject='person:'+$adminPerson.ToString('N')
        $before=$agentPublic.NotBefore.ToUniversalTime().ToString('O',[Globalization.CultureInfo]::InvariantCulture)
        $after=$agentPublic.NotAfter.ToUniversalTime().ToString('O',[Globalization.CultureInfo]::InvariantCulture)
        $adminBefore=$adminPublic.NotBefore.ToUniversalTime().ToString('O',[Globalization.CultureInfo]::InvariantCulture)
        Assert-True ($agentHash -cmatch '^[0-9A-F]{64}$' -and $adminHash -cmatch '^[0-9A-F]{64}$' -and
            $agentDevice -ne [Guid]::Empty -and $adminPerson -ne [Guid]::Empty) 'Fixture identity seed invalid.'
        # Every interpolated value is a generated GUID, digest or canonical X509 UTC timestamp.
        $sql="BEGIN; SET LOCAL ROLE fleetory_owner; INSERT INTO core.devices(device_id,display_name,updated_at,revision) VALUES ('$device','Native registered fixture','$before',1);"
        $sql+="INSERT INTO core.agent_certificates(certificate_sha256,device_id,not_before,not_after,revoked_at) VALUES ('$agentHash','$device','$before','$after',NULL);"
        $sql+="INSERT INTO platform.admin_certificate_registrations(certificate_sha256,actor_subject_id,registered_at,overlap_ends_at,previous_certificate_sha256,incident_reference,operator_reference) VALUES ('$adminHash','$subject','$adminBefore',NULL,NULL,'fixture-not-approval','fixture-not-approval'); COMMIT;"
        $null=Invoke-Database 'fleetory' $sql
        return @{device=$device;subject=$subject;agentHash=$agentHash;adminHash=$adminHash}
    }finally{$agentPublic.Dispose();$adminPublic.Dispose()}
}
function Revoke-NativeFixtureIdentity([hashtable]$Seed){
    Assert-True ($Seed.agentHash -cmatch '^[0-9A-F]{64}$' -and $Seed.adminHash -cmatch '^[0-9A-F]{64}$') 'Fixture revocation identity invalid.'
    # Only fresh fixture fingerprints; one real database instant shared by both records.
    $sql="BEGIN; SET LOCAL ROLE fleetory_owner; WITH revoked AS (UPDATE core.agent_certificates SET revoked_at=clock_timestamp() WHERE certificate_sha256='"+$Seed.agentHash+"' AND revoked_at IS NULL RETURNING revoked_at), added AS (INSERT INTO platform.admin_certificate_revocations(certificate_sha256,revoked_at,incident_reference,operator_reference) SELECT '"+$Seed.adminHash+"',revoked_at,'fixture-not-approval','fixture-not-approval' FROM revoked RETURNING certificate_sha256) SELECT count(*)=1 FROM added; COMMIT;"
    Assert-True ((Invoke-Database 'fleetory' $sql).Stdout.Trim() -ceq 't') 'Fixture owner revocation did not affect exactly one pair.'
}
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
    Assert-WorkerQueue 5 0
    $denialEvent=Get-PipelineEventJson 'admin.certificate.unregistered_denied'
    $denial=$denialEvent|ConvertFrom-Json -AsHashtable
    $registry=$healthy.lifecycle.clientTls.registryBoundary
    Assert-True ($denial.Action -ceq 'admin.certificate.unregistered_denied' -and $denial.correlationId -ceq 'native-registry-admin' -and
        $denial.actorSubjectId -ceq $registry.actorSubjectId -and $denial.actorKind -eq $registry.actorKind -and
        $denial.targetType -ceq 'admin_certificate' -and $denial.targetId -ceq $registry.certificateSha256) 'Independent registry denial event mismatch.'
    Assert-WorkerAudit (@($priorEvents)+@($hostEvent,$denialEvent))
    $actions=@('Fixture.Database.Read','Fixture.Worker.Read','Fixture.Worker.AfterStop','Fixture.Host.Read','admin.certificate.unregistered_denied')
    $captured=@($priorEvents)+@($hostEvent,$denialEvent)
    for($index=0;$index -lt 5;$index++){Assert-True ((Get-PipelineEventJson $actions[$index]) -ceq $captured[$index]) 'Host changed an immutable event.'}
    $seed=Seed-NativeRegisteredIdentity
    $registered=Invoke-ServerProbe 'host-registered' 'host-registered'
    Assert-WorkerQueue 6 0
    $oidcEvent=Get-PipelineEventJson 'admin.oidc.denied';$oidc=$oidcEvent|ConvertFrom-Json -AsHashtable
    $admission=$registered.lifecycle.registeredBoundary
    Assert-True ($oidc.Action -ceq 'admin.oidc.denied' -and $oidc.actorSubjectId -ceq $seed.subject -and
        $oidc.actorSubjectId -ceq $admission.actorSubjectId -and $oidc.actorKind -eq 1 -and
        $null -eq $oidc.targetType -and $null -eq $oidc.targetId -and $oidc.correlationId -ceq 'native-registered-admin' -and
        $admission.certificateSha256 -ceq $seed.adminHash) 'Independent OIDC denial event mismatch.'
    Assert-WorkerAudit (@($captured)+@($oidcEvent))
    for($index=0;$index -lt 5;$index++){Assert-True ((Get-PipelineEventJson $actions[$index]) -ceq $captured[$index]) 'Registered host changed prior audit.'}
    Assert-True ($admission.agentStatus -ceq 'Accepted' -and $admission.adminStatus -ceq 'Accepted' -and
        $admission.agentHttpStatus -eq 204 -and $admission.adminHttpStatus -eq 401 -and $admission.runtimeIdentityInsertRefusals -eq 2 -and
        $admission.sanParsersAccepted -eq 2 -and $admission.runtimeStorePreflights -eq 2 -and $admission.registeredInventories -eq 3 -and
        $admission.newAdminDenialEvents -eq 1 -and $admission.denialAction -ceq 'admin.oidc.denied' -and
        $admission.agentBindingAdmissionVerified -eq $true -and $admission.automaticWorkerDrain -eq $true -and
        $admission.positiveIdentityAdmissionVerified -eq $false) 'Registered host admission/OIDC boundary incomplete.'
    Revoke-NativeFixtureIdentity $seed
    $revoked=Invoke-ServerProbe 'host-revoked' 'host-revoked'
    Assert-WorkerQueue 7 0
    $revocationEvent=Get-PipelineEventJson 'admin.certificate.revoked_denied';$revocation=$revocationEvent|ConvertFrom-Json -AsHashtable
    $refusal=$revoked.lifecycle.revokedBoundary
    Assert-True ($revocation.Action -ceq 'admin.certificate.revoked_denied' -and $revocation.actorSubjectId -ceq $seed.subject -and
        $revocation.actorSubjectId -ceq $refusal.actorSubjectId -and $revocation.actorKind -eq 1 -and
        $revocation.targetType -ceq 'admin_certificate' -and $revocation.targetId -ceq $seed.adminHash -and
        $revocation.correlationId -ceq 'native-revoked-admin' -and $refusal.certificateSha256 -ceq $seed.adminHash) 'Independent revocation denial event mismatch.'
    $actions+=@('admin.oidc.denied');$captured+=@($oidcEvent)
    Assert-WorkerAudit (@($captured)+@($revocationEvent))
    for($index=0;$index -lt 6;$index++){Assert-True ((Get-PipelineEventJson $actions[$index]) -ceq $captured[$index]) 'Revoked host changed prior audit or OIDC denial.'}
    Assert-True ($refusal.agentStatus -ceq 'Revoked' -and $refusal.adminStatus -ceq 'Revoked' -and
        $refusal.agentHttpStatus -eq 403 -and $refusal.adminHttpStatus -eq 403 -and $refusal.mutualTlsHttpRefusals -eq 2 -and
        $refusal.runtimeIdentityInsertRefusals -eq 2 -and $refusal.runtimeRevocationWriteRefusals -eq 2 -and
        $refusal.sanParsersAccepted -eq 2 -and $refusal.runtimeStorePreflights -eq 2 -and $refusal.revokedInventories -eq 3 -and
        $refusal.newAdminDenialEvents -eq 1 -and $refusal.denialAction -ceq 'admin.certificate.revoked_denied' -and
        $refusal.durableRevocationVerified -eq $true -and $refusal.automaticWorkerDrain -eq $true -and
        $refusal.agentBindingAdmissionVerified -eq $false -and $refusal.positiveIdentityAdmissionVerified -eq $false -and
        $refusal.emptyBodies -eq $true -and $refusal.correlatedPrivateGets -eq 2) 'Revoked host boundary incomplete.'
    $runs=@($degraded.lifecycle,$healthy.lifecycle,$registered.lifecycle,$revoked.lifecycle)
    Assert-True (@($runs.processId|Select-Object -Unique).Count -eq 4) 'Native host process identity drift.'
    foreach($run in $runs){
        Assert-True ($run.applicationStarted -eq $true -and $run.applicationStopped -eq $true -and $run.workerExecutionCompleted -eq $true -and
            $run.stopElapsedMilliseconds -ge 0 -and $run.stopElapsedMilliseconds -lt 5000 -and
            ($run.listeningPorts -join ',') -ceq '19580,19581,19582' -and $run.closedPortRefusals -eq 3 -and
            $run.initialClosedPortRefusals -eq 3 -and $run.livenessBody -ceq 'Healthy' -and $run.readinessStatusCode -eq 200 -and
            $run.publicPrivilegedPathRefusals -eq 2) 'Native host lifecycle proof incomplete.'
    }
    Assert-True ($degraded.lifecycle.readinessBody -ceq 'Degraded' -and $degraded.lifecycle.claimFailures -ge 1 -and
        $healthy.lifecycle.readinessBody -ceq 'Healthy' -and $healthy.lifecycle.claimFailures -eq 0 -and
        $registered.lifecycle.readinessBody -ceq 'Healthy' -and $registered.lifecycle.claimFailures -eq 0 -and
        $revoked.lifecycle.readinessBody -ceq 'Healthy' -and $revoked.lifecycle.claimFailures -eq 0) 'Native host readiness/worker mismatch.'
    $tls=$healthy.lifecycle.clientTls
    Assert-True ($null -eq $degraded.lifecycle.clientTls -and $tls.gateways -eq 2 -and $tls.trustedClientHttpResponses -eq 2 -and
        $tls.missingClientRefusals -eq 2 -and $tls.crossRootClientRefusals -eq 2 -and $tls.wrongEkuClientRefusals -eq 2 -and
        $tls.serverRootRefusals -eq 2 -and $tls.serverHostnameRefusals -eq 2 -and $tls.protocol -ceq 'TLS1.2' -and
        $tls.nativeAuthenticationRefusals -eq 10 -and $tls.arbitraryTransportFailuresAccepted -eq 0 -and
        $tls.serverCorrelatedHandshakeRefusals -eq 6 -and $tls.serverCorrelatedTrustedHandshakes -eq 6 -and
        $tls.httpRequestsInClientRefusals -eq 0 -and
        $tls.responseStatus -eq 404 -and $tls.identityAdmissionVerified -eq $false) 'Native client TLS proof incomplete.'
    $identity=$tls.identityBoundary
    Assert-True ($identity.mutualTlsHttpRefusals -eq 2 -and $identity.statusCode -eq 403 -and $identity.emptyBodies -eq $true -and
        $identity.clientsWithoutSan -eq 2 -and $identity.correlatedPrivateGets -eq 2 -and
        $identity.positiveIdentityAdmissionVerified -eq $false) 'Native identity boundary proof incomplete.'
    Assert-True ($registry.sanParsersAccepted -eq 2 -and $registry.runtimeStorePreflights -eq 2 -and $registry.absentRegistryInventories -eq 3 -and
        $registry.agentStatus -ceq 'UnknownCertificate' -and $registry.adminStatus -ceq 'Unregistered' -and
        $registry.mutualTlsHttpRefusals -eq 2 -and $registry.statusCode -eq 403 -and $registry.emptyBodies -eq $true -and
        $registry.correlatedPrivateGets -eq 2 -and $registry.newAdminDenialEvents -eq 1 -and $registry.automaticWorkerDrain -eq $true -and
        $registry.positiveIdentityAdmissionVerified -eq $false) 'Native registry boundary proof incomplete.'
    return [ordered]@{applicationStarts=4;applicationStops=4;maximumStopMilliseconds=($runs.stopElapsedMilliseconds|Measure-Object -Maximum).Maximum;
        workerExecutionCompleted=$true;httpHealthBodiesVerified=8;degradedAndHealthyBothStatus200=$true;publicPrivilegedPathRefusals=8;
        listenersVerifiedPerHost=3;closedPortRefusals=12;initialClosedPortRefusals=12;nativeClaimFailureObserved=$true;
        automaticDrainVerified=$true;totalAuditKeys=8;hostEventRevision=1;registryDenialRevision=1;oidcDenialRevision=1;revocationDenialRevision=1;crossStoreFieldsPerEvent=10;
        queueRowsAfterHostRestart=0;immutableEventsUnchanged=$true;manualWorkerStartsInHostCases=0;clientTls=$tls;registeredBoundary=$admission;revokedBoundary=$refusal;issuerActivated=$false}
}
