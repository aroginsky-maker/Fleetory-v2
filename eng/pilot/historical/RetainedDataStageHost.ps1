#requires -Version 7.3
# Library called by trusted owner code. Metadata cannot select commands, callbacks or permission.
function Invoke-RetainedDataStageHost([string]$Repository,[string]$Python,[string]$InputRoot,
    [hashtable]$RawMetadata,[hashtable]$Commitments,[hashtable]$Expected,$AuditPoint,$ImageContext,$Material,
    [ValidateSet('normal','exit-on-request','expire-after-restore')][string]$Mode='normal',
    [scriptblock]$GeneratedAfterCapture=$null,[hashtable]$OriginalExpected=$null,$ControllerPipe=$null){
    if($null -ne $GeneratedAfterCapture){
        $namespace=Split-Path ([IO.Path]::GetFullPath($InputRoot)) -Parent
        $parent=[IO.Path]::GetFullPath((Split-Path $namespace -Parent))
        $expectedParent=[IO.Path]::GetFullPath((Join-Path $Repository 'artifacts'))
        $comparison=if($IsWindows){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
        Assert-ImmuData ($parent.Equals($expectedParent,$comparison) -and
            (Split-Path $namespace -Leaf) -cmatch '^native-pair-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z' -and
            (Split-Path $InputRoot -Leaf) -ceq 'retained-inputs') 'retained-host-generated-callback-root'
    }
    $externalLoss=$null -ne $ControllerPipe
    if($externalLoss){
        Assert-ImmuData ($Mode -ceq 'normal' -and $null -ne $GeneratedAfterCapture -and $null -ne $OriginalExpected) 'controller-host-generated-only'
        Assert-RetainedControllerPipe $ControllerPipe
    }
    $loss=$Mode -cne 'normal' -or $externalLoss;$expiry=$Mode -ceq 'expire-after-restore'
    $admission=$null
    try{
        if($null -ne $OriginalExpected){
            Assert-ImmuData ($OriginalExpected.ContainsKey('root') -and $OriginalExpected.ContainsKey('revision') -and
                $OriginalExpected.ContainsKey('imageId') -and $OriginalExpected.ContainsKey('probeSha256') -and
                $OriginalExpected.ContainsKey('configurationSha256')) 'original-host-binding-fields'
            Assert-ImmuData ($OriginalExpected.root -ceq $InputRoot -and $OriginalExpected.revision -ceq $Commitments.revision -and
                $OriginalExpected.imageId -ceq $Commitments.imageId -and $OriginalExpected.imageId -ceq $ImageContext.ImageId -and
                $OriginalExpected.probeSha256 -ceq $Commitments.probeSha256 -and $OriginalExpected.probeSha256 -ceq $ImageContext.ProbeHash -and
                $OriginalExpected.configurationSha256 -ceq $Commitments.configurationSha256) 'original-host-binding-drift'
            $admission=Open-OriginalFourServiceUsePeer $Repository $Python $InputRoot $RawMetadata $Commitments -ExpectedBinding $OriginalExpected -Mode $Mode
        }else{
            $admission=Open-RetainedServiceUsePeer $Repository $Python $InputRoot $RawMetadata $Commitments -Mode $Mode
        }
        $payload=Receive-RetainedServicePayload $admission
        Confirm-RetainedServiceUseLive $admission $admission.cancel.Token
        if($null -ne $GeneratedAfterCapture){$null=& $GeneratedAfterCapture}
        Confirm-RetainedServiceUseLive $admission $admission.cancel.Token
        $auditStage=@{ImageContext=$ImageContext;Material=$Material;Point=$AuditPoint;ServerEnabled=$true;Historical=$true;
            AdmissionPeer=$admission;ExpectedConfigurationSha256=$Commitments.configurationSha256;
            GeneratedAdmissionFault=($loss -and -not $externalLoss);GeneratedAdmissionExpiry=$expiry}
        if($externalLoss){$auditStage.ControllerPipe=$ControllerPipe}
        $result=Invoke-RetainedPostgresTarget $Repository $Python $payload $Expected 'complete' $auditStage
        Assert-ImmuData ($result.verified -and $result.cleanupVerified -and $result.nativePgRestores -eq $(if($externalLoss){0}else{2}) -and
            $result.nativeAuditRestored -eq (-not $loss) -and $result.serverStarted -eq (-not $loss) -and
            $result.runtimeLoginVerified -eq (-not $loss) -and $result.admissionLossAfterPgRestoreVerified -eq ($loss -and -not $externalLoss) -and
            $result.ownRemovalCalls -eq 1 -and $result.ownedAuditRemovalCalls -eq 1 -and
            $result.configurationSha256 -ceq $Commitments.configurationSha256) 'retained-host-native-result'
        if($externalLoss){
            Assert-ImmuData ($result.externalControllerLossVerified -and $result.nativeWorkDispatches -eq 0 -and
                $result.externalControllerLateWorkRefusals -eq 1) 'controller-host-no-native-work'
        }
        if(-not $loss){
            Assert-ImmuData ($result.server.boundedRestartVerified -and $result.server.sameTargetBackendRestartVerified -and
                $result.server.postgresOutageRefusedBeforeHost -and $result.server.auditOutageRefusedBeforeHost -and
                $result.server.nativeApplicationStarts -eq 2 -and $result.server.nativeApplicationStops -eq 2) 'retained-host-backend-retry-restart'
            Confirm-RetainedServiceUseLive $admission $admission.cancel.Token
        }
        Remove-AuditDataImage $ImageContext
        Assert-ImmuData (Test-AuditDataImageClosed $ImageContext) 'retained-host-own-image-removed'
        if(-not $loss){$null=Complete-RetainedServiceUse $admission ([Text.Encoding]::UTF8.GetBytes(($result|ConvertTo-Json -Compress -Depth 24)))}
        return @{schema='fleetory.retained-native-data-host.v1';verified=$true;case=$result;
            measuredImageId=$Commitments.imageId;probeSha256=$Commitments.probeSha256;configurationSha256=$Commitments.configurationSha256;
            privateFourPacketTransferVerified=$true;statusChecks=$admission.statusChecks;
            heldCodeFiles=$admission.codeFiles;heldCodePlanSha256=$admission.codePlanSha256;
            codeLeaseHandoffBound=$true;fullTransitiveExecutionVerified=$false;
            actualChildExitVerified=($admission.closed -or ($loss -and $admission.holder.HasExited -and $admission.holder.ExitCode -ne 0));
            admissionLossAfterPgRestoreVerified=($loss -and -not $externalLoss);
            externalControllerLossVerified=$externalLoss;
            admissionOriginalExpiryVerified=($expiry -and $result.admissionOriginalExpiryMilliseconds -ge 108000);
            ownAuditImageRemovalVerified=$true;gateOriginAuthenticated=$false;nativeResultAuthenticated=$false;
            originalExecutorReady=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
    }finally{
        try{if($ImageContext.ImageClaimed -and -not (Test-AuditDataImageClosed $ImageContext)){Remove-AuditDataImage $ImageContext}}
        finally{Close-RetainedServiceUsePeer $admission}
    }
}
