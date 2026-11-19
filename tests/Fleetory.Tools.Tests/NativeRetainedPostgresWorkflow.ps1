#requires -Version 7.3
# The four file readers and real PostgreSQL owner use generated native source data only.
function Invoke-NativeRetainedPostgresWorkflow($Artifacts,$Expected,$AuditPoint=$null){
    . (Join-Path $repo 'eng/pilot/historical/RetainedPostgresTarget.ps1')
    . (Join-Path $repo 'eng/pilot/ImmuDataRoundtripPolicy.ps1')
    . (Join-Path $repo 'eng/pilot/AuditDataResourceOwnership.ps1')
    . (Join-Path $PSScriptRoot 'NativeAuditDataFixture.ps1')
    . (Join-Path $PSScriptRoot 'NativeRetainedMaterial.ps1')
    . (Join-Path $PSScriptRoot 'NativeRetainedServiceUseWorkflow.ps1')
    $script:stage='retained-pg-source-snapshot'
    $writer=Join-Path $PSScriptRoot 'native_retained_pg_inputs.py'
    $sql=Invoke-NativeBytes $Python @('-B',$writer,'sql') -TimeoutSeconds 10
    Assert-Pair ($sql.ExitCode-eq0-and[string]::IsNullOrWhiteSpace($sql.Stderr)) 'retained-pg-source-sql'
    $snapshot=(V2-Sql $source 'fleetory' $sql.Stdout).StdoutBytes
    $inputRoot=Join-Path $root 'retained-inputs';[Fleetory.Pilot.ExclusiveAuditDirectory]::Create($inputRoot)
    $sourceFrame=@{fixture=$fixture;snapshot=[Convert]::ToBase64String($snapshot)}
    foreach($kind in @('application','signer','audit')){$sourceFrame[$kind]=[Convert]::ToBase64String($Artifacts[$kind])}
    $sourceBytes=[Text.Encoding]::UTF8.GetBytes(($sourceFrame|ConvertTo-Json -Compress));$oldDirectory=[Environment]::CurrentDirectory
    try{
        [Environment]::CurrentDirectory=$inputRoot
        $prepared=Invoke-NativeBytes $Python @('-B',$writer,'prepare') $sourceBytes 15
        Assert-Pair ($prepared.ExitCode-eq0-and[string]::IsNullOrWhiteSpace($prepared.Stderr)) 'retained-pg-source-files'
        $metadata=$prepared.Stdout|ConvertFrom-Json -AsHashtable
        Assert-Pair ($metadata.generatedFixtureOnly-eq$true-and$metadata.nonce-ceq$fixture) 'retained-pg-source-scope'
        if($Profile -cin @('v2-retained-service-use','v2-retained-service-use-loss','v2-retained-service-use-expiry')){
            return Invoke-NativeRetainedServiceUseWorkflow $inputRoot $metadata $Expected $AuditPoint
        }
        $body=[Text.Encoding]::UTF8.GetBytes(($metadata.body|ConvertTo-Json -Compress))
        $captured=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/historical/retained_service_payload.py'),
            '--selection-sha256',$metadata.pins.selection,'--manifest-sha256',$metadata.pins.manifest,
            '--checkpoint-sha256',$metadata.pins.checkpoint,'--nonce',$fixture) $body 20
        Assert-Pair ($captured.ExitCode-eq0-and[string]::IsNullOrWhiteSpace($captured.Stderr)) 'retained-pg-four-input-capture'
        $payload=$captured.Stdout|ConvertFrom-Json -AsHashtable -Depth 20
    }finally{[Environment]::CurrentDirectory=$oldDirectory;[Array]::Clear($sourceBytes)}
    $prefix=[IO.Path]::GetFullPath($inputRoot)+[IO.Path]::DirectorySeparatorChar
    $comparison=if($IsWindows){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    foreach($kind in @('application-postgres','signer-postgres','audit-immudb','audit-export')){
        $path=[IO.Path]::GetFullPath((Join-Path $inputRoot $metadata.generatedPaths[$kind]))
        Assert-Pair ($path.StartsWith($prefix,$comparison)) 'retained-pg-generated-path'
        $null=Get-ProviderOrdinaryItem $path
        [IO.File]::WriteAllBytes($path,[Text.Encoding]::UTF8.GetBytes('generated source path replaced after frozen capture'))
    }
    foreach($blob in $Artifacts.Values){[Array]::Clear($blob)};$sourceFrame=$prepared=$captured=$body=$null
    $script:stage='retained-pg-owned-target';$results=[Collections.Generic.List[object]]::new()
    $imageContext=$null
    if($Profile -cin @('v2-retained-coupled','v2-retained-server','v2-retained-historical-server','v2-retained-inflight','v2-retained-restore-inflight')){
        $imageRoot=Join-Path $root 'retained-owned-public-build';$null=New-Item -ItemType Directory -Path $imageRoot
        Copy-Item -LiteralPath (Join-Path $root 'publish') -Destination (Join-Path $imageRoot 'publish') -Recurse
        $imageContext=@{Fixture=[Guid]::NewGuid().ToString('D');Root=$imageRoot;ImageName=('retained-coupled-'+[Guid]::NewGuid().ToString('N'));
            ProbeHash=$state.ProbeHash;ImageId=$null;ImageClaimed=$false}
        Build-AuditDataImage $imageContext 'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'
    }
    $flows=@('complete','after-acquire','lease-expired')
    if($null -ne $imageContext){$flows+=@('after-work','lease-after-work','inspection-exit')}
    if($Profile -ceq 'v2-retained-inflight'){$flows=@('inflight-sql-exit')}
    if($Profile -ceq 'v2-retained-restore-inflight'){$flows=@('inflight-restore-exit')}
    try{foreach($flow in $flows){
        $script:stage='retained-pg-'+$flow
        $auditStage=$null
        if($null -ne $imageContext){
            $material=New-NativeRetainedMaterial $flow ($Profile -cin @('v2-retained-server','v2-retained-historical-server'))
            $auditStage=@{ImageContext=$imageContext;Material=$material;Point=$AuditPoint;ServerEnabled=($Profile -cin @('v2-retained-server','v2-retained-historical-server'));Historical=($Profile -ceq 'v2-retained-historical-server')}
        }
        $result=Invoke-RetainedPostgresTarget $repo $Python $payload $Expected $flow $auditStage
        Assert-Pair ($result.verified-eq$true-and$result.cleanupVerified-eq$true-and$result.ownRemovalCalls-eq1-and$result.copiedClaimsRefused-eq2-and
            $result.removalReplayRefusedBeforeNativeCall-eq$true) 'retained-pg-owned-result'
        $restored=$flow -cin @('complete','after-work','lease-after-work','inflight-sql-exit')
        Assert-Pair ($result.nativePgRestores-eq$(if($restored){2}else{0})) 'retained-pg-restore-dispatch'
        if($flow -ceq 'inflight-restore-exit'){
            Assert-Pair ($result.inFlightRestore.actualQueryActive -and $result.inFlightRestore.nativeClientExitVerified -and
                $result.inFlightRestore.coordinatorLost -and $result.inFlightRestore.observationCalls -eq 1 -and
                $result.inFlightRestore.lateNativeWorkRefusals -eq 1 -and $result.nativePgPreDataSchemaRestores -eq 1 -and
                $result.nativePgDataRestoreAttempts -eq 1 -and $result.ownRestoreLockVerified -and
                -not $result.nativeAuditRestored -and -not $result.inFlightSql.actualQueryActive -and -not $result.serverStarted) 'retained-actual-copy-cancellation'
        }
        if($flow -ceq 'inflight-sql-exit'){
            Assert-Pair ($result.inFlightSql.actualQueryActive -and $result.inFlightSql.nativeClientExitVerified -and
                $result.inFlightSql.coordinatorLost -and $result.inFlightSql.observationCalls -eq 1 -and
                $result.inFlightSql.lateNativeWorkRefusals -eq 1 -and $result.coordinator.coordinatorExitCode -ne 0 -and
                $result.coordinator.membersAbsent -and -not $result.serverStarted) 'retained-inflight-active-sql-cancel-cleanup'
        }
        if($flow -ceq 'inspection-exit'){
            Assert-Pair ($result.controllerLossAfterInspectionRefused -and $result.nativeWorkDispatches -eq 0 -and
                $result.runtimeWorkInspections -eq 1 -and $result.coordinator.workStatusRequests -eq 2 -and
                $result.coordinator.workStatusChecks -eq 1 -and $result.coordinator.coordinatorExitCode -ne 0 -and
                $result.coordinator.membersAbsent) 'retained-inspection-exit-no-late-work'
        }
        if($null -ne $imageContext){
            $expectedFiles=if($restored){8}else{0}
            if($Profile -cin @('v2-retained-server','v2-retained-historical-server')){
                $expectedFiles=if($flow -ceq 'complete'){22}elseif($restored){12}else{0}
            }
            Assert-Pair ($result.configurationSha256 -cmatch '^[a-f0-9]{64}\z' -and
                $result.configurationFilesVerified -eq $expectedFiles -and
                $result.configurationDriftRefusalsBeforeNativeCall -eq 2 -and
                $result.configurationReadonlyRefusals -eq 1) 'retained-configuration-proof'
            Assert-Pair ($result.ownedAuditRemovalCalls -eq 1 -and $result.nativeAuditRestored -eq $restored) 'retained-coupled-restore-cleanup'
            if($restored){Assert-Pair ($result.audit.nativeAuditRestores -eq 1 -and $result.audit.targetSignaturesVerified -and
                $result.audit.pgExportExpectationsUsed -and $result.audit.observation.knownEvents -eq 4 -and $result.audit.observation.nativeTransactions -eq 5) 'retained-coupled-audit-proof'}
        }
        if($Profile -cin @('v2-retained-server','v2-retained-historical-server')){
            Assert-Pair ($result.serverStarted -eq ($flow -ceq 'complete') -and $result.runtimeLoginVerified -eq ($flow -ceq 'complete')) 'retained-server-dispatch'
        }
        $results.Add($result)
    }}finally{if($null -ne $imageContext){Remove-AuditDataImage $imageContext}}
    return @{schema=$(if($Profile -ceq 'v2-retained-restore-inflight'){'fleetory.native-retained-inflight-restore-stage.v1'}elseif($Profile -ceq 'v2-retained-inflight'){'fleetory.native-retained-inflight-sql-stage.v1'}elseif($Profile -ceq 'v2-retained-historical-server'){'fleetory.native-retained-historical-server-stage.v1'}elseif($Profile -ceq 'v2-retained-server'){'fleetory.native-retained-server-stage.v1'}elseif($null -ne $imageContext){'fleetory.native-retained-coupled-data-stage.v1'}else{'fleetory.native-retained-postgres-data-stage.v1'});
        verified=$true;scope='Generated four-input capture and owned data-stage lifecycle';probeSha256=$state.ProbeHash;
        fourInputReaderUsed=$true;nativePgRestores=[int](($results|Measure-Object -Property nativePgRestores -Sum).Sum);cases=$results;actualOwnedPostgresTargets=$flows.Count;copiedClaimsRefused=($flows.Count*2);
        nativeAuditRestores=@($results|Where-Object nativeAuditRestored).Count;
        ownAuditImageId=$(if($null -ne $imageContext){$imageContext.ImageId}else{$null});
        ownAuditImageRemovalVerified=$(if($null -ne $imageContext){Test-AuditDataImageClosed $imageContext}else{$false});
        postRestoreCoordinatorExitVerified=($flows -ccontains 'after-work');postRestoreLiveLeaseExpiryVerified=($flows -ccontains 'lease-after-work');
        coordinatorLossAfterInspectionVerified=($flows -ccontains 'inspection-exit');inFlightSqlCancellationVerified=($flows -ccontains 'inflight-sql-exit');inFlightRestoreCancellationVerified=($flows -ccontains 'inflight-restore-exit');
        controllerExitCleanupVerified=($flows -ccontains 'after-acquire' -or $flows -ccontains 'inflight-sql-exit' -or $flows -ccontains 'inflight-restore-exit');liveLeaseExpiryCleanupVerified=($flows -ccontains 'lease-expired');completeNativeReplyCustodyUsed=$true;
        allFourGeneratedPathsReplacedAfterCapture=$true;nativeRestoreFromFrozenBytesVerified=$true;removalReplayRefusals=$flows.Count;
        sourceOriginalFilesRead=$false;nativeAuditRestored=(@($results|Where-Object nativeAuditRestored).Count -gt 0);serverStarted=($Profile -cin @('v2-retained-server','v2-retained-historical-server'));runtimeLoginVerified=($Profile -cin @('v2-retained-server','v2-retained-historical-server'));
        untrustedArchiveSandboxVerified=$false;originalUseAuthenticated=$false;sourceVpsAccessed=$false;
        originalPkiOrProviderUsed=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
