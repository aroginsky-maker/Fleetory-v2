#requires -Version 7.3
# The four file readers and real PostgreSQL owner use generated native source data only.
function Invoke-NativeRetainedPostgresWorkflow($Artifacts,$Expected){
    . (Join-Path $repo 'eng/pilot/historical/RetainedPostgresTarget.ps1')
    . (Join-Path $repo 'eng/pilot/ImmuDataRoundtripPolicy.ps1')
    . (Join-Path $repo 'eng/pilot/AuditDataResourceOwnership.ps1')
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
    foreach($flow in @('complete','after-acquire','lease-expired')){
        $script:stage='retained-pg-'+$flow
        $result=Invoke-RetainedPostgresTarget $repo $Python $payload $Expected $flow
        Assert-Pair ($result.verified-eq$true-and$result.cleanupVerified-eq$true-and$result.ownRemovalCalls-eq1-and$result.copiedClaimsRefused-eq2-and
            $result.removalReplayRefusedBeforeNativeCall-eq$true) 'retained-pg-owned-result'
        Assert-Pair ($result.nativePgRestores-eq$(if($flow-ceq'complete'){2}else{0})) 'retained-pg-restore-dispatch'
        $results.Add($result)
    }
    return @{schema='fleetory.native-retained-postgres-data-stage.v1';verified=$true;scope='Generated four-input capture and owned PostgreSQL substage only';
        fourInputReaderUsed=$true;nativePgRestores=2;cases=$results;actualOwnedPostgresTargets=3;copiedClaimsRefused=6;
        controllerExitCleanupVerified=$true;liveLeaseExpiryCleanupVerified=$true;completeNativeReplyCustodyUsed=$true;
        allFourGeneratedPathsReplacedAfterCapture=$true;nativeRestoreFromFrozenBytesVerified=$true;removalReplayRefusals=3;
        sourceOriginalFilesRead=$false;nativeAuditRestored=$false;serverStarted=$false;runtimeLoginVerified=$false;
        untrustedArchiveSandboxVerified=$false;originalUseAuthenticated=$false;sourceVpsAccessed=$false;
        originalPkiOrProviderUsed=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
