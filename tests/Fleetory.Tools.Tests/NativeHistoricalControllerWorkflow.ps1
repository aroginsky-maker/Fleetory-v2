#requires -Version 7.3
# Generated source only; the actual owner receives frozen input through a private pipe.
. (Join-Path $repo 'eng/pilot/HistoricalAuditControllerPolicy.ps1')
function Assert-ControllerResourcesAbsent($Resources,[int]$Count){
    Assert-ImmuData (@($Resources.ids).Count -eq $Count -and $Resources.payloadRemoved -eq $true) 'controller-resource-count'
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
    $planBytes=[Text.Encoding]::UTF8.GetBytes(($Plan|ConvertTo-Json -Depth 8 -Compress))
    $Packet.planBase64=[Convert]::ToBase64String($planBytes)
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Packet|ConvertTo-Json -Depth 8 -Compress))
    $r=Invoke-NativeBytes ([Environment]::ProcessPath) @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $repo 'eng/pilot/Invoke-HistoricalAuditObservation.ps1'),
        '-ExpectedPlanSha256',(Get-ImmuDataHash $planBytes),'-Python',$Python,'-FailurePoint',$Failure) $bytes 120
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
    return $value
}
function Invoke-NativeHistoricalControllerWorkflow($Source,$Foreign){
    $script:controllerSourceId=$Source.Id;$script:controllerForeignId=$Foreign.Id
    $script:stage='controller-source';$setup=Probe $Source 'observation-history-seed'
    $expected=New-HistoricalObservationExpectation $Source $setup
    $before=Read-HistoricalObservation $Source $expected
    Read-AuditDataStore $context $Source
    $backup=(Invoke-Docker (Get-ImmuDataCliArguments $Source.Id 'backup')).StdoutBytes
    $parts=@{archive=$backup;values=[Text.Encoding]::UTF8.GetBytes(($setup.comparisonExpectations|ConvertTo-Json -Depth 8 -Compress));
        state=[Text.Encoding]::UTF8.GetBytes(($setup.state|ConvertTo-Json -Depth 8 -Compress));publicKey=[IO.File]::ReadAllBytes((Public-KeyPath 'source'))}
    $inputs=@{archiveBytes=$backup.Length};foreach($name in $parts.Keys){$inputs[$name+'Sha256']=Get-ImmuDataHash $parts[$name]}
    $scope=@{historicalComparisonOnly=$true};foreach($name in @('writerAdmissionVerified','stateMutationAuthorized','sourceOriginAuthenticated','sourceIndependenceAuthenticated','productionTokensIssued','originalPrivatePkiUsed','providerAdminSession','executionAuthorized','fullSystemRecoveryVerified','phase7Complete')){$scope[$name]=$false}
    $plan=@{schema='fleetory.historical-audit-restore-plan.v1';purpose='historical-known-events-sandbox-observation.v1';nonce=$fixture;revision=((& git -C $repo rev-parse HEAD).Trim());
        codeSha256=(Get-HistoricalAuditCodeHash);probeSha256=$context.ProbeHash;ciEvidenceSha256=('a'*64);localEvidenceSha256=('b'*64);
        inputs=$inputs;scope=$scope;limits=@{nativeSeconds=600;containerSeconds=660;maximumArchiveBytes=65536;maximumPacketBytes=131072}}
    $packet=@{schema='fleetory.historical-audit-restore-packet.v1';planBase64=''};foreach($name in $parts.Keys){$packet[$name+'Base64']=[Convert]::ToBase64String($parts[$name])}
    $script:stage='controller-positive';$positive=Invoke-GeneratedController $plan $packet -Resources 1
    foreach($name in @('sourceStateSignatureVerified','targetStateSignaturesVerified','codeAndProbePinsMatched','inputDigestsMatched','wrongPasswordRefused','readerWriteRefused','restartPreservedObservation','freshTargetCredentialsAndKeys')){Assert-ImmuData ($positive[$name] -eq $true) 'controller-positive-evidence'}
    foreach($name in @('dataOriginAuthenticated','externalGatesAuthenticated','exclusiveUseLedgerVerified','originalPrivatePkiUsed','executionAuthorized','writerAdmissionVerified','fullSystemRecoveryVerified','phase7Complete')){Assert-ImmuData ($positive[$name] -eq $false) 'controller-no-authority-promotion'}
    Assert-ImmuData ($positive.targetLifetimeSeconds -eq 660 -and $positive.nativeDeadlineSeconds -eq 600 -and $positive.nativeRestores -eq 1 -and
        $positive.observation.knownEvents -eq 4 -and $positive.observation.currentKvKeys -eq 4 -and $positive.observation.nativeTransactions -eq 5 -and
        $positive.observation.comparison.nullContextMembersPreserved -eq 1 -and $positive.observation.additionalStateReviewed -eq $false -and
        $positive.observation.wholeKeyspaceVerified -eq $false -and $positive.observation.observationSha256 -ceq $before.Parsed.observationSha256) 'controller-observed-copy'
    $script:stage='controller-fault-cleanup'
    foreach($failure in @('after-container','after-restore')){$null=Invoke-GeneratedController $plan $packet 'controller-injected-failure' 1 $failure}
    $script:stage='controller-code-probe-refusals'
    foreach($name in @('codeSha256','probeSha256')){
        $bad=($plan|ConvertTo-Json -Depth 8)|ConvertFrom-Json -AsHashtable;$bad[$name]='0'*64
        $category=if($name -ceq 'codeSha256'){'controller-code-pin'}else{'controller-probe-pin'}
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
        if($_.Exception.Message -cne 'Native signer fixture refused: audit-runtime'){throw}
        $denied=$true
    }
    Assert-ImmuData $denied 'controller-foreign-lifetime-refused';Read-AuditDataStore $context $Foreign
    $after=Read-HistoricalObservation $Source $expected
    Assert-ImmuData ($after.Parsed.observationSha256 -ceq $before.Parsed.observationSha256) 'controller-source-unchanged'
    return @{schema='fleetory.generated-historical-audit-controller.v1';verified=$true;scope='generated-only';privateOwnerPipeVerified=$true;
        knownEvents=4;nullMembersPreserved=1;nativeTransactions=5;controllerCases=8;faultCleanupCases=2;typedRefusals=5;nativeArchiveCorruptionRefused=$true;
        foreignLifetimeRefused=$true;sourceUnchanged=$true;nativeOwnerCleanupVerified=$true;targetLifetimeSeconds=660;nativeDeadlineSeconds=600;
        originalInputsRead=$false;originalPrivatePkiUsed=$false;sourceVpsAccessed=$false;externalGatesAuthenticated=$false;exclusiveUseLedgerVerified=$false;
        historicalComparisonOnly=$true;writerAdmissionVerified=$false;executionAuthorized=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
