#requires -Version 7.3
# Generated source only; the actual owner receives frozen input through a private pipe.
. (Join-Path $repo 'eng/pilot/HistoricalAuditControllerPolicy.ps1')
function New-NativeAuditCodeContext{
    $nonce=[Guid]::NewGuid().ToString('D')
    $imageContext=$context.Clone()
    $imageContext.Fixture=$nonce;$imageContext.Root=Join-Path $repo ('artifacts/native-audit-controller-'+$nonce)
    $imageContext.ImageName=Get-ImmuDataImageName $nonce;$imageContext.ImageId=$null;$imageContext.ImageClaimed=$false
    $imageContext.PayloadClaimed=$false;$imageContext.PayloadRemoved=$false;$imageContext.Stores=[Collections.Generic.List[object]]::new()
    New-AuditDataPublicPayload $repo $imageContext
    $sourceBundle=Get-HistoricalProbeBundle $published
    Copy-Item -LiteralPath $published -Destination (Join-Path $imageContext.Root 'publish') -Recurse
    Assert-ImmuData ((Get-HistoricalProbeBundle (Join-Path $imageContext.Root 'publish')).sha256 -ceq $sourceBundle.sha256 -and
        (Get-HistoricalProbeBundle $published).sha256 -ceq $sourceBundle.sha256) 'image-fault-public-copy-pin'
    return $imageContext
}
function Invoke-NativeImageReplyFault{
    $liveClient=${function:Invoke-Docker}
    $imageContext=New-NativeAuditCodeContext
    $fault=@{Injected=$false;Calls=[Collections.Generic.List[string]]::new();Witness=$null;Closed=$false;ForeignReadback=$false;Client=$null}
    function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
        $fault.Calls.Add(($Arguments -join '|'))
        if($Arguments[0] -ceq 'build' -and -not $fault.Injected){
            $fault.Injected=$true;$fault.Witness=$imageContext.Clone();$fault.Witness.ImageId=$null;$fault.Witness.ImageClaimed=$false
            $heldClient=$liveClient;$native=@{Reply=$null}
            $operation=[Func[Tuple[int,byte[],byte[]]]]{
                $native.Reply=& $heldClient $Arguments $InputBytes $TimeoutSeconds -AllowFailure
                return [Tuple[int,byte[],byte[]]]::new($native.Reply.ExitCode,$native.Reply.StdoutBytes,$native.Reply.StderrBytes)
            }.GetNewClosure()
            $null=[Fleetory.Pilot.AuditImageCustody]::Build($fault.Witness,$fault.Client,$InputBytes,$operation)
            Assert-ImmuData ($native.Reply.ExitCode -eq 0 -and $native.Reply.StdoutBytes.Length -ge 72) 'image-witness-complete-build-reply'
            return @{ExitCode=0;Stdout=$native.Reply.Stdout.Substring(0,19);Stderr='';
                StdoutBytes=[byte[]]$native.Reply.StdoutBytes[0..18];StderrBytes=[byte[]]@()}
        }
        $r=& $liveClient $Arguments $InputBytes $TimeoutSeconds -AllowFailure:$AllowFailure
        if($fault.ForeignReadback -and $Arguments[0] -ceq 'image' -and $Arguments[1] -ceq 'inspect' -and $Arguments[2] -ceq $fault.Witness.ImageId){
            # A fault in the actual native readback, not an actual foreign tag claim.
            $items=@($r.Stdout|ConvertFrom-Json -AsHashtable -Depth 32);$items[0].RepoTags=@('foreign-image-reference:fixture')
            $out=ConvertTo-Json -InputObject $items -Depth 32 -Compress
            return @{ExitCode=$r.ExitCode;Stdout=$out;Stderr=$r.Stderr;StdoutBytes=[Text.Encoding]::UTF8.GetBytes($out);StderrBytes=$r.StderrBytes}
        }
        return $r
    }
    $fault.Client=${function:Invoke-Docker}
    try{
        $refused=$false;try{Build-AuditDataImage $imageContext 'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Injected -and $null -ne $fault.Witness -and $null -eq $imageContext.ImageId) 'native-partial-image-build-refused'
        $calls=$fault.Calls.Count;$refused=$false
        try{Remove-AuditDataImage $imageContext}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Calls.Count -eq $calls) 'native-unknown-image-no-alias-lookup'
        $imageContext.ImageId=$fault.Witness.ImageId;$refused=$false
        try{Remove-AuditDataImage $imageContext}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Calls.Count -eq $calls) 'native-saved-image-id-no-authority'
        $imageContext.ImageId=$null
        Read-AuditDataImage $fault.Witness
        $fault.ForeignReadback=$true;$refused=$false
        try{Remove-AuditDataImage $fault.Witness}catch{$refused=$true}
        Assert-ImmuData ($refused -and @($fault.Calls|Where-Object {$_ -like 'image|rm|*'}).Count -eq 0) 'native-foreign-image-readback-no-removal'
        $fault.ForeignReadback=$false
        Remove-AuditDataImage $fault.Witness
        Assert-ImmuData ((Test-AuditDataImageClosed $fault.Witness) -and
            @($fault.Calls|Where-Object {$_ -ceq ('image|rm|--no-prune|'+$fault.Witness.ImageId)}).Count -eq 1) 'native-image-witness-full-removal'
        $fault.Closed=$true;$calls=$fault.Calls.Count;$refused=$false
        try{Remove-AuditDataImage $fault.Witness}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Calls.Count -eq $calls) 'native-image-removal-replay-refused'
        foreach($base in @($script:nativeAuditSourceImage,$script:nativeSignerImage,'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd')){
            $r=Invoke-Docker @('image','inspect','--format','{{json .Id}}',$base)
            Assert-ImmuData ($r.ExitCode -eq 0 -and ($r.Stdout|ConvertFrom-Json) -cmatch '^sha256:[a-f0-9]{64}\z') 'native-image-base-preserved'
        }
    }finally{
        if($null -ne $fault.Witness -and -not $fault.Closed){Remove-AuditDataImage $fault.Witness;$fault.Closed=$true}
        if($fault.Closed){Remove-AuditDataPublicPayload $repo $imageContext}
    }
    Assert-ImmuData ($fault.Closed -and $imageContext.PayloadRemoved -and -not (Test-Path -LiteralPath $imageContext.Root)) 'native-image-fault-all-owned-disposed'
}

function Invoke-NativeContainerReplyFault{
    # A separate live fixture witness retains the real complete native reply;
    # the tested owner sees only a prefix and may not recover ownership by name.
    $liveClient=${function:Invoke-Docker}
    $containerContext=New-NativeAuditCodeContext
    $fault=@{Injected=$false;Calls=0;WitnessContext=$null;WitnessStore=$null;Closed=$false;StopAttempted=$false;StopComplete=$false}
    function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
        $fault.Calls++
        if($Arguments[0] -ceq 'run' -and -not $fault.Injected){
            $fault.Injected=$true
            $fault.WitnessStore=$containerContext.Stores[-1].Clone()
            $fault.WitnessContext=$containerContext.Clone()
            $fault.WitnessContext.Stores=[Collections.Generic.List[object]]::new()
            $fault.WitnessContext.Stores.Add($fault.WitnessStore)
            $native=@{Reply=$null}
            $heldClient=$liveClient # GetNewClosure captures locals, not the enclosing function variables.
            $operation=[Func[Tuple[int,byte[],byte[]]]]{
                $native.Reply=& $heldClient $Arguments $InputBytes $TimeoutSeconds -AllowFailure
                return [Tuple[int,byte[],byte[]]]::new($native.Reply.ExitCode,$native.Reply.StdoutBytes,$native.Reply.StderrBytes)
            }.GetNewClosure()
            $null=[Fleetory.Pilot.AuditContainerCustody]::Create($fault.WitnessContext,$fault.WitnessStore,$fault.Client,$operation)
            Assert-ImmuData ($native.Reply.ExitCode -eq 0 -and $native.Reply.StdoutBytes.Length -ge 65) 'fault-witness-complete-native-reply'
            return @{ExitCode=0;Stdout=$native.Reply.Stdout.Substring(0,12);Stderr='';
                StdoutBytes=[byte[]]$native.Reply.StdoutBytes[0..11];StderrBytes=[byte[]]@()}
        }
        return & $liveClient $Arguments $InputBytes $TimeoutSeconds -AllowFailure:$AllowFailure
    }
    $fault.Client=${function:Invoke-Docker}
    $outer=$null
    try{
        Build-AuditDataImage $containerContext 'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'
        $refused=$false;try{$null=New-AuditDataStore $containerContext 'corrupt'}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Injected -and $null -ne $fault.WitnessStore) 'partial-native-create-refused'
        $outer=$containerContext.Stores[-1]
        Assert-ImmuData (-not [object]::ReferenceEquals($outer,$fault.WitnessStore)) 'fault-witness-distinct-store'
        Assert-ImmuData ($null -eq $outer.Id) 'partial-create-id-not-adopted'
        $calls=$fault.Calls;$refused=$false
        try{Remove-AuditDataStore $containerContext $outer}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Calls -eq $calls) 'partial-create-no-name-lookup'
        $outer.Id=$fault.WitnessStore.Id;$refused=$false
        try{Remove-AuditDataStore $containerContext $outer}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Calls -eq $calls) 'metadata-cannot-repair-unknown-create'
        $outer.Id=$null
        # The tested claim stays unknown. Only the witness's own complete reply
        # and fresh generated profile authorize fixture disposal.
        Read-AuditDataStore $fault.WitnessContext $fault.WitnessStore
        $fault.StopAttempted=$true
        $stopped=Invoke-Docker @('stop','--timeout','1',$fault.WitnessStore.Id)
        Assert-ImmuData ($stopped.ExitCode -eq 0 -and $stopped.Stdout -cin @(($fault.WitnessStore.Id+"`n"),($fault.WitnessStore.Id+"`r`n"))) 'fault-owned-stop-complete-reply'
        $fault.StopComplete=$true;$calls=$fault.Calls
        Remove-AuditDataStore $fault.WitnessContext $fault.WitnessStore
        Assert-ImmuData ($fault.Calls -eq ($calls+1) -and (Test-AuditDataStoreClosed $fault.WitnessContext $fault.WitnessStore)) 'fault-native-empty-array-absence-no-rm'
        $fault.Closed=$true;$calls=$fault.Calls;$refused=$false
        try{Remove-AuditDataStore $fault.WitnessContext $fault.WitnessStore}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Calls -eq $calls) 'native-witness-removal-no-replay'
    }catch{
        $failure=$_.Exception
        while($null -ne $failure){
            if($failure.Message -cmatch '^(Audit container live custody refused: [a-z-]+\.|Audit data fixture refused: [a-z0-9-]{1,64})$'){
                [Console]::Error.WriteLine('Generated custody fault: '+$failure.Message)
            }
            $failure=$failure.InnerException
        }
        [Console]::Error.WriteLine('Generated custody fault line='+$_.InvocationInfo.ScriptLineNumber)
        throw
    }finally{
        Assert-ImmuData (-not $fault.StopAttempted -or $fault.StopComplete) 'fault-unknown-stop-no-retry'
        if($null -ne $fault.WitnessStore -and -not $fault.Closed){Remove-AuditDataStore $fault.WitnessContext $fault.WitnessStore;$fault.Closed=$true}
        if($null -ne $outer -and $fault.Closed){$null=$containerContext.Stores.Remove($outer)}
        if($fault.Closed){
            Remove-AuditDataImage $containerContext
            Assert-ImmuData (Test-AuditDataImageClosed $containerContext) 'container-fault-own-image-closed'
            Remove-AuditDataPublicPayload $repo $containerContext
        }
    }
    Assert-ImmuData $fault.Closed 'native-partial-reply-fixture-disposed'
}

function Assert-ControllerResourcesAbsent($Resources,[int]$Count){
    Assert-ImmuData (@($Resources.ids).Count -eq $Count -and $Resources.payloadAbsent -eq $true -and
        $Resources.payloadClaimed -is [bool] -and $Resources.payloadRemoved -eq $Resources.payloadClaimed) 'controller-resource-count'
    foreach($id in @($Resources.ids)){
        Assert-ImmuData ($id -cmatch '^[a-f0-9]{64}\z' -and $id -cne $script:controllerSourceId -and $id -cne $script:controllerForeignId) 'controller-resource-ownership'
        $r=Invoke-Docker @('inspect',$id) -AllowFailure
        Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stdout+$r.Stderr) -match '(?i)no such (object|container)') 'controller-resource-absent'
    }
    Assert-ImmuData ($Resources.image -ceq (Get-ImmuDataImageName $Resources.fixture)) 'controller-image-name'
    $r=Invoke-Docker @('image','inspect',$Resources.image) -AllowFailure
    Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stdout+$r.Stderr) -match '(?i)no such (object|image)') 'controller-image-absent'
    if($null -ne $Resources.imageId){
        Assert-ImmuData ($Resources.imageId -cmatch '^sha256:[a-f0-9]{64}\z' -and $Resources.imageId -cne $context.ImageId) 'controller-owned-image-id'
        $r=Invoke-Docker @('image','inspect',$Resources.imageId) -AllowFailure
        Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stdout+$r.Stderr) -match '(?i)no such (object|image)') 'controller-owned-image-absent'
    }
    Assert-ImmuData (-not (Test-Path -LiteralPath (Join-Path $repo ('artifacts/native-audit-controller-'+$Resources.fixture)))) 'controller-payload-absent'
}
function Invoke-GeneratedController($Plan,$Packet,[string]$ExpectedRefusal='',[int]$Resources=0,[string]$Failure='none'){
    $case=New-HistoricalControllerCase $Plan $Packet ([Guid]::NewGuid().ToString('D')) $script:controllerCaseNonces
    $r=Invoke-NativeBytes ([Environment]::ProcessPath) @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $repo 'eng/pilot/Invoke-HistoricalAuditObservation.ps1'),
        '-ExpectedPlanSha256',$case.planSha256,'-Python',$Python,'-FailurePoint',$Failure) $case.bytes 120
    $value=$r.Stdout|ConvertFrom-Json -AsHashtable -Depth 20
    if($ExpectedRefusal){
        if($r.ExitCode -ne 1 -or $value.refusal -cne $ExpectedRefusal){
            foreach($name in @('stage','refusal')){if($value.ContainsKey($name) -and $value[$name] -cmatch '^[a-z0-9-]{1,64}\z'){[Console]::Error.WriteLine('Controller negative '+$name+'='+$value[$name])}}
        }
        Assert-ImmuData ($r.ExitCode -eq 1 -and $r.Stderr.Trim() -ceq 'Historical native controller refused; no input contents or credentials logged.' -and
            $value.schema -ceq 'fleetory.historical-audit-controller-cleanup.v1' -and $value.refusal -ceq $ExpectedRefusal -and $value.cleanupVerified -eq $true) 'controller-typed-refusal'
    }else{
        if($r.ExitCode -ne 0){
            foreach($name in @('stage','refusal')){
                if($value.ContainsKey($name) -and $value[$name] -cmatch '^[a-z0-9-]{1,64}\z'){
                    [Console]::Error.WriteLine('Controller positive '+$name+'='+$value[$name])
                }
            }
            if($value.dotnetApplicationRefusal -is [System.Collections.IDictionary]){
                foreach($field in @('errorType','causeType','location')){
                    if($value.dotnetApplicationRefusal[$field] -cmatch '^[A-Za-z0-9_]{1,80}\z'){
                        [Console]::Error.WriteLine('Controller probe '+$field+'='+$value.dotnetApplicationRefusal[$field])
                    }
                }
            }
        }
        Assert-ImmuData ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr) -and $value.schema -ceq 'fleetory.historical-audit-owned-observation.v1' -and $value.verified -eq $true -and $value.cleanupVerified -eq $true) 'controller-positive'
    }
    Assert-ControllerResourcesAbsent $value.resources $Resources
    Assert-ImmuData ($value.resources.payloadClaimed -eq ($ExpectedRefusal -cnotin @('controller-code-pin','controller-code-revision','controller-coordinator-before-acquire'))) 'controller-payload-claim-evidence'
    return $value
}
function Assert-HistoricalCoordinator($Result,[string]$Flow,[bool]$Acquired,[bool]$Expired,[bool]$WorkAdmitted){
    $proof=$Result.recoveryCoordinator
    $expectedStop=$Flow -cin @('before-acquire','after-acquire')
    Assert-ImmuData ($proof.flow -ceq $Flow -and $proof.ownerPid -ne $proof.coordinatorPid -and
        $proof.ownerAliveDuringCleanup -eq $true -and $proof.identityVerified -eq $true -and
        $proof.exitObservedHeld -eq $true -and $proof.membersAbsent -eq $true -and
        ($proof.coordinatorExitCode -ne 0) -eq $expectedStop -and $proof.allocationRequests -eq [int]$Acquired -and
        $proof.workRequests -eq [int]($Expired -or $WorkAdmitted) -and $proof.workAdmitted -eq $WorkAdmitted -and
        $proof.expiredLiveCleanup -eq $Expired -and $proof.lateRequestRefused -eq $Expired) ('coordinator-evidence-'+$Flow)
    if($Acquired){
        Assert-ImmuData ($proof.projection -cmatch '^[a-f0-9]{64}\z' -and
            $Result.resources.imageId -cmatch '^sha256:[a-f0-9]{64}\z') ('coordinator-acquired-'+$Flow)
        $ids=@($Result.resources.ids)
        $bytes=[Text.Encoding]::ASCII.GetBytes(($proof.nonce,$Result.resources.fixture,$Result.resources.imageId,$ids[0] -join '|'))
        Assert-ImmuData ($proof.projection -ceq (Get-ImmuDataHash $bytes) -and
            $proof.projection -cne $ids[0]) ('coordinator-projection-'+$Flow)
    }else{
        Assert-ImmuData ($null -eq $proof.projection -and $null -eq $Result.resources.imageId -and
            -not $Result.resources.payloadClaimed) 'coordinator-never-allocated'
    }
    if(-not $WorkAdmitted){
        Assert-ImmuData ($null -eq $Result.independentController -and $null -eq $Result.independentNativeOutcomeUnconfirmed) ('coordinator-no-historical-work-'+$Flow)
    }
}
function Assert-HistoricalRoutedCreateFault($Result,[string]$Fault){
    $proof=$Result.routedCreateFault
    $peer=$Result.recoveryCoordinator
    Assert-ImmuData ($peer.flow -ceq 'create-refused' -and $peer.ownerAliveDuringCleanup -eq $true -and
        $peer.identityVerified -eq $true -and $peer.exitObservedHeld -eq $true -and $peer.membersAbsent -eq $true -and
        $peer.allocationRequests -eq 1 -and $peer.allocationReplayRefused -eq $true -and
        $null -eq $peer.projection -and $peer.workRequests -eq 0 -and -not $peer.workAdmitted -and
        $null -eq $Result.independentController -and $null -eq $Result.independentNativeOutcomeUnconfirmed) ('create-routed-admission-'+$Fault)
    Assert-ImmuData ($proof.fault -ceq $Fault -and $proof.createDispatches -eq 1 -and
        $proof.witnessPid -gt 0 -and $proof.witnessPid -notin @($peer.ownerPid,$peer.coordinatorPid,$peer.supervisorPid) -and
        $proof.replySeenOnlyAfterCleanup -eq $true -and $proof.unknownCleanupRefused -eq $true -and
        $proof.lateReplyRefused -eq $true -and $proof.idAdoptionRefused -eq $true -and $proof.witnessOwnedAbsenceVerified -eq $true -and
        $proof.containerId -cmatch '^[a-f0-9]{64}\z' -and
        $proof.containerId -cnotin @($script:controllerSourceId,$script:controllerForeignId)) ('create-routed-ownership-'+$Fault)
    $r=Invoke-Docker @('inspect',$proof.containerId) -AllowFailure
    Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stdout+$r.Stderr) -match '(?i)no such (object|container)') ('create-routed-exact-absence-'+$Fault)
}

function Invoke-NativeHistoricalControllerWorkflow($Source,$Foreign){
    $script:controllerCaseNonces=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $script:controllerSourceId=$Source.Id;$script:controllerForeignId=$Foreign.Id
    $script:stage='controller-native-image-reply-fault';Invoke-NativeImageReplyFault
    $script:stage='controller-native-reply-fault';Invoke-NativeContainerReplyFault
    $script:stage='controller-source';$setup=Probe $Source 'observation-history-seed'
    $expected=New-HistoricalObservationExpectation $Source $setup
    $before=Read-HistoricalObservation $Source $expected
    Read-AuditDataStore $context $Source
    $backup=(Invoke-Docker (Get-ImmuDataCliArguments $Source.Id 'backup')).StdoutBytes
    $parts=@{archive=$backup;values=[Text.Encoding]::UTF8.GetBytes(($setup.comparisonExpectations|ConvertTo-Json -Depth 8 -Compress));
        state=[Text.Encoding]::UTF8.GetBytes(($setup.state|ConvertTo-Json -Depth 8 -Compress));publicKey=[IO.File]::ReadAllBytes((Public-KeyPath 'source'))}
    $inputs=@{archiveBytes=$backup.Length};foreach($name in $parts.Keys){$inputs[$name+'Sha256']=Get-ImmuDataHash $parts[$name]}
    $scope=@{historicalComparisonOnly=$true};foreach($name in @('writerAdmissionVerified','stateMutationAuthorized','sourceOriginAuthenticated','sourceIndependenceAuthenticated','productionTokensIssued','originalPrivatePkiUsed','providerAdminSession','executionAuthorized','fullSystemRecoveryVerified','phase7Complete')){$scope[$name]=$false}
    $probeBundle=Get-HistoricalProbeBundle $published
    $plan=@{schema='fleetory.historical-audit-restore-plan.v2';purpose='historical-known-events-sandbox-observation.v1';nonce=$fixture;revision=((& git -C $repo rev-parse HEAD).Trim());
        codeSha256=(Get-HistoricalAuditCodeHash);probeSha256=$context.ProbeHash;probeBundleSha256=$probeBundle.sha256;ciEvidenceSha256=('a'*64);localEvidenceSha256=('b'*64);
        inputs=$inputs;scope=$scope;limits=@{nativeSeconds=600;containerSeconds=660;maximumArchiveBytes=65536;maximumPacketBytes=131072}}
    $packet=@{schema='fleetory.historical-audit-restore-packet.v1';planBase64=''};foreach($name in $parts.Keys){$packet[$name+'Base64']=[Convert]::ToBase64String($parts[$name])}
    $parents=@($script:nativeAuditSourceImage,$script:nativeSignerImage,
        'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd')
    $baseIds=@($parents|ForEach-Object {(Invoke-Docker @('image','inspect','--format','{{.Id}}',$_)).Stdout.Trim()})
    Assert-ImmuData ($baseIds.Count -eq 3 -and @($baseIds|Where-Object {$_ -cmatch '^sha256:[a-f0-9]{64}\z'}).Count -eq 3) 'coordinator-base-images'
    $parentPlan=ConvertTo-Json $plan -Depth 8 -Compress;$parentPacket=ConvertTo-Json $packet -Depth 8 -Compress
    $script:stage='controller-positive';$positive=Invoke-GeneratedController $plan $packet -Resources 1
    Assert-ImmuData ($positive.historicalWorkerCommandsPinned -eq $true -and $positive.historicalWorkerRawRepliesRetained -eq $true -and
        $positive.historicalWorkerOsFenceVerified -eq $false -and $positive.historicalWorkerCalls -ge 7 -and $positive.historicalWorkerCalls -le 64) 'controller-closed-worker-profile'
    Assert-ImmuData ($positive.historicalComparisonWorkerFenceVerified -eq $true -and $positive.historicalComparisonWorkerCalls -eq 3) 'controller-actual-comparison-worker'
    Assert-ImmuData ($positive.dotnetObservationLeafExitVerified -eq $true -and $positive.dotnetObservationLeafCalls -eq 3) 'controller-actual-dotnet-observation'
    $exits=$positive.dotnetModeExitCounts
    Assert-ImmuData ($exits.Count -eq 4 -and $exits['audit-health'] -ge 2 -and $exits['history-users'] -eq 1 -and
        $exits['observation-history-read'] -eq 3 -and $exits['observation-reader-denial'] -eq 1) 'controller-dotnet-all-mode-exits'
    foreach($name in @('sourceStateSignatureVerified','targetStateSignaturesVerified','codeAndProbePinsMatched','inputDigestsMatched','wrongPasswordRefused','readerWriteRefused','restartPreservedObservation','freshTargetCredentialsAndKeys','codeInventoryV2Matched','publishedProbeBundleMatched','containerProbeBundleMatched')){Assert-ImmuData ($positive[$name] -eq $true) 'controller-positive-evidence'}
    foreach($name in @('dataOriginAuthenticated','externalGatesAuthenticated','exclusiveUseLedgerVerified','originalPrivatePkiUsed','executionAuthorized','writerAdmissionVerified','fullSystemRecoveryVerified','phase7Complete')){Assert-ImmuData ($positive[$name] -eq $false) 'controller-no-authority-promotion'}
    Assert-ImmuData ($positive.targetLifetimeSeconds -eq 660 -and $positive.nativeDeadlineSeconds -eq 600 -and $positive.nativeRestores -eq 1 -and
        $positive.observation.knownEvents -eq 4 -and $positive.observation.currentKvKeys -eq 4 -and $positive.observation.nativeTransactions -eq 5 -and
        $positive.observation.comparison.nullContextMembersPreserved -eq 1 -and $positive.observation.additionalStateReviewed -eq $false -and
        $positive.observation.comparison.sourceNonce -ceq $fixture -and
        $positive.observation.comparison.knownValuesCommitment -ceq $expected.comparison.knownValuesCommitment -and
        $positive.observation.wholeKeyspaceVerified -eq $false -and $positive.observation.observationSha256 -ceq $before.Parsed.observationSha256) 'controller-observed-copy'
    $script:stage='controller-fault-cleanup'
    foreach($failure in @('after-container','after-restore')){$null=Invoke-GeneratedController $plan $packet 'controller-injected-failure' 1 $failure}
    $script:stage='controller-comparison-worker-faults'
    foreach($fault in @('early-eof','abrupt-exit')){
        $proof=Invoke-GeneratedController $plan $packet ('controller-worker-'+$fault) 1 ('worker-'+$fault)
        $observed=$proof.comparisonFault
        $bytes=if($fault -ceq 'early-eof'){4}else{0}
        Assert-ImmuData ($observed.fault -ceq $fault -and $observed.childImageAndBirthVerified -eq $true -and
            $observed.childMembersAbsent -eq $true -and $observed.requestBytes -eq $bytes -and
            $observed.childExitCode -ne 0 -and $null -eq $observed.result) 'controller-native-comparison-fault'
    }
    $script:stage='controller-dotnet-leaf-faults'
    $faultModes=[ordered]@{'dotnet-'='observation-history-read';'dotnet-health-'='audit-health';
        'dotnet-users-'='history-users';'dotnet-denial-'='observation-reader-denial'}
    foreach($prefix in $faultModes.Keys){
        foreach($suffix in @('early-eof','abrupt-exit')){
            $point=$prefix+$suffix
            $proof=Invoke-GeneratedController $plan $packet ('controller-'+$point) 1 $point
            $leaf=$proof.dotnetFault
            $expectedExit=if($suffix -ceq 'early-eof'){65}else{137}
            Assert-ImmuData ($leaf.mode -ceq $faultModes[$prefix] -and $leaf.heldBirthVerified -eq $true -and
                $leaf.heldExitVerified -eq $true -and $leaf.childExitCode -eq $expectedExit -and
                $leaf.payloadBytesReleased -eq 0 -and $leaf.stdout -ceq '') 'controller-native-dotnet-leaf-fault'
        }
    }
    $script:stage='controller-dotnet-transport-loss'
    $lost=Invoke-GeneratedController $plan $packet 'controller-dotnet-transport-loss' 1 'dotnet-transport-loss'
    $transport=$lost.dotnetTransportFault
    foreach($name in @('hostDockerClientIdentityVerified','originalHostClientTerminated','observerBoundBeforeLoss','heldDaemonChildExitVerified',
        'wrongBirthRefused','copiedClaimRefused','interruptedObserverNoTerminalReceipt')){
        Assert-ImmuData ($transport[$name] -eq $true) 'controller-native-dotnet-transport-proof'
    }
    Assert-ImmuData ($transport.daemonChildAfterLoss -cin @('same-live','held-exit') -and
        $transport.releasedApplicationBytes -eq 0 -and $transport.applicationReplyAccepted -eq $false) 'controller-native-dotnet-transport-result'
    $script:stage='controller-independent-creator'
    $independent=Invoke-GeneratedController $plan $packet -Resources 1 -Failure 'independent-complete'
    $app=$independent.independentController
    Assert-ImmuData ($app.flow -ceq 'complete' -and $app.creatorAliveDuringCleanup -eq $true -and $app.controllerMembersAbsent -eq $true -and
        $app.childIdentityVerified -eq $true -and $app.controllerExitObservedHeld -eq $true -and $app.controllerExitCode -eq 0 -and $app.nativeObservationCalls -eq 3 -and
        ($app.nativeStages -join '|') -ceq 'observe|authenticate|check-reader|restart|observe-after-restart' -and
        $app.applicationResult.before.observationSha256 -ceq $before.Parsed.observationSha256 -and
        $app.applicationResult.after.observationSha256 -ceq $before.Parsed.observationSha256 -and
        $app.applicationResult.authenticationRefused -eq $true -and $app.applicationResult.readerWriteRefused -eq $true -and
        $app.applicationResult.restartPreservedObservation -eq $true -and
        $app.creatorPid -ne $app.controllerPid -and $independent.restartPreservedObservation -eq $true) 'controller-independent-positive'
    Assert-HistoricalCoordinator $independent 'complete' $true $false $true
    $died=(Invoke-GeneratedController $plan $packet 'controller-independent-controller-exit' 1 'independent-controller-exit').independentController
    Assert-ImmuData ($died.flow -ceq 'controller-exit' -and $died.creatorAliveDuringCleanup -eq $true -and
        $died.childIdentityVerified -eq $true -and $died.controllerExitObservedHeld -eq $true -and $died.controllerMembersAbsent -eq $true -and $died.controllerExitCode -ne 0 -and
        $null -eq $died.applicationResult -and $died.nativeObservationCalls -eq 0 -and $died.creatorPid -ne $died.controllerPid) 'controller-independent-death'
    $expired=(Invoke-GeneratedController $plan $packet 'controller-independent-lease-expired' 1 'independent-lease-expired').independentController
    Assert-ImmuData ($expired.flow -ceq 'lease-expired' -and $expired.creatorAliveDuringCleanup -eq $true -and
        $expired.childIdentityVerified -eq $true -and $expired.controllerExitObservedHeld -eq $true -and $expired.controllerMembersAbsent -eq $true -and $expired.controllerExitCode -eq 0 -and
        $expired.lateApplicationRequestRefused -eq $true -and $expired.controllerAliveAfterCleanup -eq $true -and
        $null -eq $expired.applicationResult -and $expired.nativeObservationCalls -eq 0 -and $expired.creatorPid -ne $expired.controllerPid) 'controller-independent-expiry'
    $script:stage='controller-independent-handoff-exit'
    $cut=Invoke-GeneratedController $plan $packet 'controller-independent-between-operations-exit' 1 'independent-between-operations-exit'
    $handoff=$cut.independentController
    Assert-ImmuData ($handoff.flow -ceq 'between-operations-exit' -and $handoff.creatorAliveDuringCleanup -eq $true -and
        $handoff.childIdentityVerified -eq $true -and $handoff.controllerExitObservedHeld -eq $true -and
        $handoff.controllerMembersAbsent -eq $true -and $handoff.controllerExitCode -ne 0 -and
        $handoff.interruptedNativeOperation -ceq 'authenticate' -and $cut.independentNativeOutcomeUnconfirmed -ceq 'authenticate' -and
        ($handoff.nativeStages -join '|') -ceq 'observe|authenticate' -and $handoff.nativeObservationCalls -eq 2 -and
        $null -eq $handoff.applicationResult -and $handoff.creatorPid -ne $handoff.controllerPid) 'controller-independent-handoff-exit'
    foreach($fault in @('lost','malformed')){
        $script:stage='controller-independent-restart-reply-'+$fault
        $unknown=Invoke-GeneratedController $plan $packet $script:stage 1 ('independent-restart-reply-'+$fault)
        $controller=$unknown.independentController
        $reply=$unknown.nativeRestartReplyFault
        Assert-ImmuData ($reply.fault -ceq $fault -and $reply.nativeDispatches -eq 1 -and
            $reply.completeReplyWitnessHeld -eq $true -and $reply.heldDaemonExitObserved -eq $true -and
            $reply.replyAdmitted -eq $false -and $reply.lateReplayRefused -eq $true -and $reply.lateReplyDeliveryCalls -eq 0) $script:stage
        Assert-ImmuData ($controller.flow -ceq 'restart-unconfirmed' -and $controller.creatorAliveDuringCleanup -eq $true -and
            $controller.childIdentityVerified -eq $true -and $controller.controllerExitObservedHeld -eq $true -and
            $controller.controllerMembersAbsent -eq $true -and $controller.controllerExitCode -ne 0 -and
            $controller.interruptedNativeOperation -ceq 'restart' -and $unknown.independentNativeOutcomeUnconfirmed -ceq 'restart' -and
            ($controller.nativeStages -join '|') -ceq 'observe|authenticate|check-reader|restart' -and $controller.nativeObservationCalls -eq 2 -and
            $null -eq $controller.applicationResult -and $controller.creatorPid -ne $controller.controllerPid) $script:stage
    }
    foreach($flow in @('before-acquire','after-acquire','lease-expired')){
        $script:stage='controller-coordinator-'+$flow
        $count=if($flow -ceq 'before-acquire'){0}else{1}
        $lost=Invoke-GeneratedController $plan $packet $script:stage $count ('coordinator-'+$flow)
        Assert-HistoricalCoordinator $lost $flow ($count -eq 1) ($flow -ceq 'lease-expired') $false
    }
    foreach($fault in @('lost','truncated')){
        $script:stage='controller-coordinator-create-'+$fault
        $unknown=Invoke-GeneratedController $plan $packet $script:stage 0 ('coordinator-create-'+$fault)
        Assert-HistoricalRoutedCreateFault $unknown $fault
    }
    $script:stage='controller-code-probe-refusals'
    foreach($name in @('codeSha256','probeSha256')){
        $bad=($plan|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable;$bad[$name]='0'*64
        $category=if($name -ceq 'codeSha256'){'controller-code-pin'}else{'controller-probe-pin'}
        $null=Invoke-GeneratedController $bad $packet $category
    }
    foreach($name in @('revision','probeBundleSha256')){
        $bad=($plan|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable
        $bad[$name]=if($name -ceq 'revision'){'0'*40}else{'0'*64}
        $category=if($name -ceq 'revision'){'controller-code-revision'}else{'controller-probe-bundle-pin'}
        $null=Invoke-GeneratedController $bad $packet $category
    }
    $script:stage='controller-crypto-refusals'
    $bad=($plan|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable;$changed=$packet.Clone()
    $bytes=[IO.File]::ReadAllBytes((Public-KeyPath 'corrupt'));$changed.publicKeyBase64=[Convert]::ToBase64String($bytes);$bad.inputs.publicKeySha256=Get-ImmuDataHash $bytes
    $null=Invoke-GeneratedController $bad $changed 'controller-source-public-pin'
    $bad=($plan|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable;$changed=$packet.Clone()
    $state=($setup.state|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable
    $sig=[Convert]::FromBase64String($state.signature.signature);$sig[-1]=$sig[-1] -bxor 1;$state.signature.signature=[Convert]::ToBase64String($sig)
    $bytes=[Text.Encoding]::UTF8.GetBytes(($state|ConvertTo-Json -Depth 8 -Compress));$changed.stateBase64=[Convert]::ToBase64String($bytes);$bad.inputs.stateSha256=Get-ImmuDataHash $bytes
    $null=Invoke-GeneratedController $bad $changed 'controller-source-signature'
    $script:stage='controller-native-corruption'
    $bad=($plan|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable;$changed=$packet.Clone()
    $bytes=$backup.Clone();$bytes[30]=$bytes[30] -bxor 1;$changed.archiveBase64=[Convert]::ToBase64String($bytes);$bad.inputs.archiveSha256=Get-ImmuDataHash $bytes
    $null=Invoke-GeneratedController $bad $changed 'controller-native-archive-refusal' 1
    $script:stage='controller-foreign-lifetime'
    $wrongContext=$context.Clone();$wrongContext.LifetimeSeconds=660;$denied=$false
    try{Read-AuditDataStore $wrongContext $Foreign}catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit container live custody refused: object-identity.'){throw}
        $denied=$true
    }
    Assert-ImmuData $denied 'controller-copied-context-refused'
    # Preserve the independent runtime lifetime check after the earlier object-boundary refusal.
    $actual=@((Invoke-Docker @('inspect',$Foreign.Id)).Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-ImmuData ($actual.Count -eq 1) 'controller-foreign-runtime-inspect'
    $denied=$false
    try{Assert-NativeStoreRuntime $actual[0] '3322:3322' 'audit' 660}catch{
        if($_.Exception.Message -cne 'Native signer fixture refused: audit-runtime'){throw}
        $denied=$true
    }
    Assert-ImmuData $denied 'controller-foreign-lifetime-refused';Read-AuditDataStore $context $Foreign
    $after=Read-HistoricalObservation $Source $expected
    Assert-ImmuData ($after.Parsed.observationSha256 -ceq $before.Parsed.observationSha256) 'controller-source-unchanged'
    $remainingBases=@($parents|ForEach-Object {(Invoke-Docker @('image','inspect','--format','{{.Id}}',$_)).Stdout.Trim()})
    Assert-ImmuData (($remainingBases -join '|') -ceq ($baseIds -join '|')) 'coordinator-base-images-preserved'
    Assert-ImmuData ($script:controllerCaseNonces.Count -eq 32 -and -not $script:controllerCaseNonces.Contains($fixture) -and
        (ConvertTo-Json $plan -Depth 8 -Compress) -ceq $parentPlan -and
        (ConvertTo-Json $packet -Depth 8 -Compress) -ceq $parentPacket) 'controller-distinct-cases'
    return @{schema='fleetory.generated-historical-audit-controller.v1';verified=$true;scope='generated-only';privateOwnerPipeVerified=$true;
        knownEvents=4;nullMembersPreserved=1;nativeTransactions=5;controllerCases=32;faultCleanupCases=23;comparisonWorkerFaultCases=2;dotnetObservationLeafFaultCases=2;dotnetOtherModeFaultCases=6;typedRefusals=7;nativeArchiveCorruptionRefused=$true;
        distinctOperationNonces=32;operationNoncesDifferFromSource=$true;sourceIdentityPreserved=$true;parentInputsUnchanged=$true;
        historicalWorkerCommandsPinned=$true;historicalWorkerRawRepliesRetained=$true;historicalWorkerOsFenceVerified=$false;historicalComparisonWorkerFenceVerified=$true;comparisonWorkerAbruptExitVerified=$true;comparisonWorkerPrematureEofVerified=$true;dotnetObservationLeafExitVerified=$true;dotnetObservationLeafEarlyEofVerified=$true;dotnetObservationLeafAbruptExitVerified=$true;dotnetAllModeExitsVerified=$true;dotnetAllModeEarlyEofAndAbruptExitVerified=$true;dotnetTransportLoss=$transport;independentCreatorCases=6;
        nativeRestartReplyFaultCases=2;nativeRestartReplyLossRefused=$true;nativeRestartMalformedReplyRefused=$true;nativeRestartLateReplyReplayRefused=$true;
        recoveryCoordinatorCases=6;
        routedCreateFaultCases=2;routedCreateMissingReplyRefused=$true;routedCreateTruncatedReplyRefused=$true;
        routedCreateNativeReplayRefused=$true;routedCreateCoordinatorReplayRefused=$true;routedCreateSeparateWitnessCleanupVerified=$true;recoveryCoordinatorBeforeAcquireExitVerified=$true;recoveryCoordinatorAfterAcquireExitCleanupVerified=$true;recoveryCoordinatorLiveExpiryCleanupVerified=$true;recoveryCoordinatorFullSequenceVerified=$true;
        independentControllerObservationVerified=$true;independentCreatorControllerDeathCleanupVerified=$true;
        independentControllerFullSequenceVerified=$true;independentControllerHandoffExitCleanupVerified=$true;unconfirmedNativeOutcomeNotReplayed=$true;
        independentCreatorLiveLeaseExpiryCleanupVerified=$true;lateIndependentControllerReplayRefused=$true;codeInventoryV2Matched=$true;publishedProbeBundleMatched=$true;containerProbeBundleMatched=$true;revisionMismatchRefused=$true;probeBundleMismatchRefused=$true;
        foreignLifetimeRefused=$true;copiedContextRefusedBeforeLookup=$true;sourceUnchanged=$true;nativeOwnerCleanupVerified=$true;nativePartialBuildReplyRefused=$true;nativeImageIdAdoptionRefused=$true;nativeForeignImageReadbackRefused=$true;nativeUntaggedImageWitnessDisposed=$true;nativeImageNoPruneVerified=$true;nativeImageRemovalReplayRefused=$true;partialNativeCreateReplyRefused=$true;unknownCreateNameAdoptionRefused=$true;liveCompleteReplyWitnessDisposed=$true;containerRemovalReplayRefused=$true;nativeAutoRemovedAbsenceVerified=$true;alreadyAbsentCleanupPerformedNoRm=$true;targetLifetimeSeconds=660;nativeDeadlineSeconds=600;
        originalInputsRead=$false;originalPrivatePkiUsed=$false;sourceVpsAccessed=$false;externalGatesAuthenticated=$false;exclusiveUseLedgerVerified=$false;
        historicalComparisonOnly=$true;writerAdmissionVerified=$false;executionAuthorized=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
