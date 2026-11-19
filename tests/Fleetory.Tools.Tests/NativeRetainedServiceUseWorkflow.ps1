#requires -Version 7.3
# Generated data through the same native target; no original gate/consent authority is inferred.
function Invoke-NativeRetainedServiceUseWorkflow([string]$InputRoot,[hashtable]$Metadata,[hashtable]$Expected,$AuditPoint){
    foreach($helper in @('HistoricalRecoveryInFlight.ps1','HistoricalRecoveryCoordinator.ps1','historical/RetainedConfiguration.ps1',
        'historical/RetainedServiceUseTransport.ps1')){. (Join-Path $repo ('eng/pilot/'+$helper))}
    $imageRoot=Join-Path $root 'retained-owned-public-build';$null=New-Item -ItemType Directory -Path $imageRoot
    Copy-Item -LiteralPath (Join-Path $root 'publish') -Destination (Join-Path $imageRoot 'publish') -Recurse
    $imageContext=@{Fixture=[Guid]::NewGuid().ToString('D');Root=$imageRoot;ImageName=('retained-service-'+[Guid]::NewGuid().ToString('N'));
        ProbeHash=$state.ProbeHash;ImageId=$null;ImageClaimed=$false}
    $admission=$null;$result=$null;$receipt=$null
    $expiry=$Profile -ceq 'v2-retained-service-use-expiry'
    $loss=$Profile -cin @('v2-retained-service-use-loss','v2-retained-service-use-expiry')
    try{
        Build-AuditDataImage $imageContext 'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'
        $material=New-NativeRetainedMaterial 'service-use' $true
        $configuration=New-RetainedConfiguration $material $true $true
        $generated=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'native_retained_pg_inputs.py'),'generated-gates') -TimeoutSeconds 10
        Assert-Pair ($generated.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($generated.Stderr)) 'service-use-generated-gates'
        $gates=$generated.Stdout|ConvertFrom-Json -AsHashtable
        Assert-Pair ($gates.generatedFixtureOnly -and -not $gates.gateOriginAuthenticated) 'service-use-no-origin-authority'
        $raw=@{}
        foreach($name in @('selection','manifest','checkpoint')){$raw[$name]=[Convert]::FromBase64String($Metadata.body[$name])}
        foreach($name in @('ci','local')){$raw[$name]=[Convert]::FromBase64String($gates.body[$name])}
        $commitments=@{nonce=$fixture;revision=$gates.revision;imageId=$imageContext.ImageId;
            probeSha256=$imageContext.ProbeHash;configurationSha256=$configuration.Sha256}
        $script:stage='retained-service-open'
        $mode=if($expiry){'expire-after-restore'}elseif($loss){'exit-on-request'}else{'normal'}
        $admission=Open-RetainedServiceUsePeer $repo $Python $InputRoot $raw $commitments -Mode $mode
        $payload=Receive-RetainedServicePayload $admission
        Confirm-RetainedServiceUseLive $admission $admission.cancel.Token
        # Replace all four generated paths: only the already captured bytes may reach the target.
        foreach($relative in $Metadata.generatedPaths.Values){
            $path=Join-Path $InputRoot $relative
            $null=Get-ProviderOrdinaryItem $path
            [IO.File]::WriteAllText($path,'generated path replaced after private transfer')
        }
        $auditStage=@{ImageContext=$imageContext;Material=$material;Point=$AuditPoint;ServerEnabled=$true;Historical=$true;
            AdmissionPeer=$admission;ExpectedConfigurationSha256=$configuration.Sha256;GeneratedAdmissionFault=$loss;GeneratedAdmissionExpiry=$expiry}
        $script:stage='retained-service-native-target'
        $result=Invoke-RetainedPostgresTarget $repo $Python $payload $Expected 'complete' $auditStage
        Assert-Pair ($result.verified -and $result.cleanupVerified -and $result.nativePgRestores -eq 2 -and
            $result.nativeAuditRestored -eq (-not $loss) -and $result.serverStarted -eq (-not $loss) -and
            $result.runtimeLoginVerified -eq (-not $loss) -and $result.admissionLossAfterPgRestoreVerified -eq $loss -and
            $result.ownRemovalCalls -eq 1 -and $result.ownedAuditRemovalCalls -eq 1 -and
            $result.configurationSha256 -ceq $configuration.Sha256) 'service-use-native-result'
        if(-not $loss){
            Assert-Pair ($result.server.boundedRestartVerified -and $result.server.sameTargetBackendRestartVerified -and
                $result.server.postgresOutageRefusedBeforeHost -and $result.server.auditOutageRefusedBeforeHost -and
                $result.server.nativeApplicationStarts -eq 2 -and $result.server.nativeApplicationStops -eq 2) 'service-use-backend-retry-restart'
        }
        if(-not $loss){Confirm-RetainedServiceUseLive $admission $admission.cancel.Token}
        Remove-AuditDataImage $imageContext
        Assert-Pair (Test-AuditDataImageClosed $imageContext) 'service-use-own-image-removed'
        if(-not $loss){$receipt=Complete-RetainedServiceUse $admission ([Text.Encoding]::UTF8.GetBytes(($result|ConvertTo-Json -Compress -Depth 24)))}
        return @{schema='fleetory.native-retained-service-use-stage.v1';verified=$true;case=$result;
            measuredImageId=$commitments.imageId;probeSha256=$commitments.probeSha256;configurationSha256=$configuration.Sha256;
            privateFourPacketTransferVerified=$true;statusChecks=$admission.statusChecks;
            actualChildExitVerified=($admission.closed -or ($loss -and $admission.holder.HasExited -and $admission.holder.ExitCode -ne 0));
            admissionLossAfterPgRestoreVerified=$loss;
            admissionOriginalExpiryVerified=($expiry -and $result.admissionOriginalExpiryMilliseconds -ge 108000);
            ownAuditImageRemovalVerified=$true;allFourGeneratedPathsReplacedAfterCapture=$true;
            sourceOriginalFilesRead=$false;gateOriginAuthenticated=$false;nativeResultAuthenticated=$false;
            originalExecutorReady=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
    }finally{
        try{if($imageContext.ImageClaimed -and -not (Test-AuditDataImageClosed $imageContext)){Remove-AuditDataImage $imageContext}}
        finally{Close-RetainedServiceUsePeer $admission}
    }
}
