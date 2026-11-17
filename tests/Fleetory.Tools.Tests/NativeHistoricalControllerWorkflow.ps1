#requires -Version 7.3
# Generated source only; the actual owner receives frozen input through a private pipe.
. (Join-Path $repo 'eng/pilot/HistoricalAuditControllerPolicy.ps1')
function Invoke-NativeContainerReplyFault{
    # A separate live fixture witness retains the real complete native reply;
    # the tested owner sees only a prefix and may not recover ownership by name.
    $liveClient=${function:Invoke-Docker}
    $fault=@{Injected=$false;Calls=0;WitnessContext=$null;WitnessStore=$null;Closed=$false;StopAttempted=$false;StopComplete=$false}
    function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
        $fault.Calls++
        if($Arguments[0] -ceq 'run' -and -not $fault.Injected){
            $fault.Injected=$true
            $fault.WitnessStore=$context.Stores[-1].Clone()
            $fault.WitnessContext=$context.Clone()
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
        $refused=$false;try{$null=New-AuditDataStore $context 'corrupt'}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Injected -and $null -ne $fault.WitnessStore) 'partial-native-create-refused'
        $outer=$context.Stores[-1]
        Assert-ImmuData (-not [object]::ReferenceEquals($outer,$fault.WitnessStore)) 'fault-witness-distinct-store'
        Assert-ImmuData ($null -eq $outer.Id) 'partial-create-id-not-adopted'
        $calls=$fault.Calls;$refused=$false
        try{Remove-AuditDataStore $context $outer}catch{$refused=$true}
        Assert-ImmuData ($refused -and $fault.Calls -eq $calls) 'partial-create-no-name-lookup'
        $outer.Id=$fault.WitnessStore.Id;$refused=$false
        try{Remove-AuditDataStore $context $outer}catch{$refused=$true}
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
        if($null -ne $outer -and $fault.Closed){$null=$context.Stores.Remove($outer)}
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
        Assert-ImmuData ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr) -and $value.schema -ceq 'fleetory.historical-audit-owned-observation.v1' -and $value.verified -eq $true -and $value.cleanupVerified -eq $true) 'controller-positive'
    }
    Assert-ControllerResourcesAbsent $value.resources $Resources
    Assert-ImmuData ($value.resources.payloadClaimed -eq ($ExpectedRefusal -cnotin @('controller-code-pin','controller-code-revision'))) 'controller-payload-claim-evidence'
    return $value
}
function Invoke-NativeHistoricalControllerWorkflow($Source,$Foreign){
    $script:controllerCaseNonces=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $script:controllerSourceId=$Source.Id;$script:controllerForeignId=$Foreign.Id
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
    $parentPlan=ConvertTo-Json $plan -Depth 8 -Compress;$parentPacket=ConvertTo-Json $packet -Depth 8 -Compress
    $script:stage='controller-positive';$positive=Invoke-GeneratedController $plan $packet -Resources 1
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
    Assert-ImmuData ($script:controllerCaseNonces.Count -eq 10 -and -not $script:controllerCaseNonces.Contains($fixture) -and
        (ConvertTo-Json $plan -Depth 8 -Compress) -ceq $parentPlan -and
        (ConvertTo-Json $packet -Depth 8 -Compress) -ceq $parentPacket) 'controller-distinct-cases'
    return @{schema='fleetory.generated-historical-audit-controller.v1';verified=$true;scope='generated-only';privateOwnerPipeVerified=$true;
        knownEvents=4;nullMembersPreserved=1;nativeTransactions=5;controllerCases=10;faultCleanupCases=2;typedRefusals=7;nativeArchiveCorruptionRefused=$true;
        distinctOperationNonces=10;operationNoncesDifferFromSource=$true;sourceIdentityPreserved=$true;parentInputsUnchanged=$true;
        codeInventoryV2Matched=$true;publishedProbeBundleMatched=$true;containerProbeBundleMatched=$true;revisionMismatchRefused=$true;probeBundleMismatchRefused=$true;
        foreignLifetimeRefused=$true;copiedContextRefusedBeforeLookup=$true;sourceUnchanged=$true;nativeOwnerCleanupVerified=$true;partialNativeCreateReplyRefused=$true;unknownCreateNameAdoptionRefused=$true;liveCompleteReplyWitnessDisposed=$true;containerRemovalReplayRefused=$true;nativeAutoRemovedAbsenceVerified=$true;alreadyAbsentCleanupPerformedNoRm=$true;targetLifetimeSeconds=660;nativeDeadlineSeconds=600;
        originalInputsRead=$false;originalPrivatePkiUsed=$false;sourceVpsAccessed=$false;externalGatesAuthenticated=$false;exclusiveUseLedgerVerified=$false;
        historicalComparisonOnly=$true;writerAdmissionVerified=$false;executionAuthorized=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
