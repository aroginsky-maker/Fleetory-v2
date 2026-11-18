#requires -Version 7.3
# Private stdin/stdout pipe. Receives frozen bytes, never an operator file path or address.
param([Parameter(Mandatory)][string]$ExpectedPlanSha256,[string]$Python='',
    [ValidateSet('none','after-container','after-restore','worker-early-eof','worker-abrupt-exit','dotnet-early-eof','dotnet-abrupt-exit',
        'dotnet-health-early-eof','dotnet-health-abrupt-exit','dotnet-users-early-eof','dotnet-users-abrupt-exit',
        'dotnet-denial-early-eof','dotnet-denial-abrupt-exit','dotnet-transport-loss')][string]$FailurePoint='none',[switch]$PreparationOnly,[string]$PreparationGitPath='',
    [switch]$PayloadReservationOnly,[switch]$ResourceAcknowledgementOnly,[switch]$ProbeRuntimeAcknowledgementOnly,[switch]$ProbeRuntimeCreationOnly,[switch]$PublicProbePublicationOnly,[string]$PublicationDotnetPath='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$testRoot=Join-Path $repo 'tests/Fleetory.Tools.Tests'
if($PreparationOnly -or $PayloadReservationOnly -or $ResourceAcknowledgementOnly -or $ProbeRuntimeAcknowledgementOnly -or $ProbeRuntimeCreationOnly -or $PublicProbePublicationOnly){
    if(@(@($PreparationOnly,$PayloadReservationOnly,$ResourceAcknowledgementOnly,$ProbeRuntimeAcknowledgementOnly,$ProbeRuntimeCreationOnly,$PublicProbePublicationOnly)|Where-Object {$_}).Count -ne 1){throw 'Exactly one preparation mode is required.'}
    foreach($helper in @('PilotNativeProcess.ps1','ProviderRecoveryPolicy.ps1','ImmuDataRoundtripPolicy.ps1','HistoricalAuditControllerPolicy.ps1','HistoricalPreparation.ps1')){. (Join-Path $PSScriptRoot $helper)}
    if($PublicProbePublicationOnly){
        . (Join-Path $PSScriptRoot 'HistoricalPublicPublication.ps1')
        exit (Invoke-HistoricalPublicPublication $ExpectedPlanSha256 $Python $repo $PreparationGitPath $PublicationDotnetPath)
    }
    if($ResourceAcknowledgementOnly -or $ProbeRuntimeAcknowledgementOnly -or $ProbeRuntimeCreationOnly){
        . (Join-Path $PSScriptRoot 'HistoricalPayloadReservation.ps1')
        . (Join-Path $PSScriptRoot 'HistoricalResourceAcknowledgement.ps1')
        exit (Invoke-HistoricalResourceAcknowledgement $ExpectedPlanSha256 $Python $repo $PreparationGitPath -ProbeRuntime:($ProbeRuntimeAcknowledgementOnly -or $ProbeRuntimeCreationOnly) -CreateProbe:$ProbeRuntimeCreationOnly)
    }
    if($PayloadReservationOnly){
        . (Join-Path $PSScriptRoot 'HistoricalPayloadReservation.ps1')
        exit (Invoke-HistoricalPayloadReservation $ExpectedPlanSha256 $Python $repo $PreparationGitPath)
    }
    exit (Invoke-HistoricalPreparation $ExpectedPlanSha256 $Python $repo $PreparationGitPath)
}
foreach($helper in @('PilotNativeProcess.ps1','ProviderRecoveryTransport.ps1','ProviderRecoveryPolicy.ps1','ImmuDataRoundtripPolicy.ps1','AuditObservationPolicy.ps1','HistoricalAuditControllerPolicy.ps1')){. (Join-Path $PSScriptRoot $helper)}
foreach($helper in @('PilotDisposableTls.ps1','NativeSignerFixture.ps1','NativeAuditFixture.ps1','NativeWorkerRuntime.ps1','NativeAuditDataFixture.ps1')){. (Join-Path $testRoot $helper)}
if(-not $Python){$Python=(Get-Command $(if($IsLinux){'python3'}else{'python'})).Source}
$fixture=[Guid]::NewGuid().ToString('D');$root=Join-Path $repo ('artifacts/native-audit-controller-'+$fixture)
$context=@{Fixture=$fixture;Root=$root;ImageName=(Get-ImmuDataImageName $fixture);ImageId=$null;ImageClaimed=$false;ProbeHash=$null;
    PayloadClaimed=$false;PayloadRemoved=$false;LifetimeSeconds=660;Stores=[Collections.Generic.List[object]]::new();Tls=$null;SigningPems=@{};Secrets=@{}}
$canaries=[Collections.Generic.List[string]]::new();$watch=[Diagnostics.Stopwatch]::StartNew();$cleaning=$false
$stage='input';$refusal='operational';$failure=$false;$cleanup=$false;$proof=$null;$store=$null;$body=$null;$archive=$null;$raw=$null
$comparisonCalls=0;$comparisonFault=$null;$managedCalls=[hashtable]::new([StringComparer]::Ordinal);$managedFault=$null;$transportFault=$null;$managedApplicationRefusal=@{}
$oldBuildKit=$env:DOCKER_BUILDKIT;$env:DOCKER_BUILDKIT='0'
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
    Assert-ImmuData ($cleaning -or $watch.Elapsed.TotalSeconds -lt 600) 'controller-deadline'
    $result=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments -ClassicBuilder:($Arguments[0] -ceq 'build'))) $InputBytes $TimeoutSeconds}else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    foreach($value in $canaries){Assert-ImmuData (-not ($result.Stdout+$result.Stderr).Contains($value,[StringComparison]::Ordinal)) 'controller-canary'}
    if(-not $AllowFailure){Assert-ImmuData ($result.ExitCode -eq 0) 'controller-docker'}
    return $result
}
function Invoke-ControllerProbe($Store,[string]$Mode,[string]$ExpectedType='',[switch]$WrongPassword,[ValidateRange(0,2)][byte]$ManagedFault=0){
    Read-AuditDataStore $context $Store
    $packet=@{fixture=$plan.nonce;admin=$context.Secrets['target-admin'];reader=$context.Secrets['target-reader'];writer=$context.Secrets['target-writer']}
    if($Mode -ceq 'observation-history-read'){$packet=@{fixture=$plan.nonce;reader=$(if($WrongPassword){$context.Secrets.wrong}else{$context.Secrets['target-reader']});observation=$script:expected}}
    $packetBytes=[Text.Encoding]::UTF8.GetBytes(($packet|ConvertTo-Json -Compress -Depth 8))
    $applicationInputLength=$packetBytes.Length
    $bytes=[byte[]]::new($applicationInputLength+1)
    $bytes[0]=$ManagedFault
    [Array]::Copy($packetBytes,0,$bytes,1,$applicationInputLength)
    [Array]::Clear($packetBytes,0,$applicationInputLength)
    $client=${function:Invoke-Docker}
    $native=[Func[string[],byte[],Tuple[int,byte[],byte[]]]]{param([string[]]$Arguments,[byte[]]$InputBytes)
        $reply=& $client $Arguments $InputBytes 60 -AllowFailure
        return [Tuple[int,byte[],byte[]]]::new($reply.ExitCode,$reply.StdoutBytes,$reply.StderrBytes)
    }.GetNewClosure()
    try{$rawReply=[Fleetory.Pilot.AuditHistoricalProbeProfile]::Invoke($context,$Store,$client,$Mode,$bytes,$native)}
    finally{[Array]::Clear($bytes,0,$bytes.Length)}
    $result=@{ExitCode=$rawReply.Item1;Stdout=[Text.Encoding]::UTF8.GetString($rawReply.Item2);Stderr=[Text.Encoding]::UTF8.GetString($rawReply.Item3)}
    Assert-ImmuData ($result.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($result.Stderr)) 'controller-dotnet-supervisor'
    $supervised=$result.Stdout|ConvertFrom-Json -AsHashtable -Depth 5
    Assert-ImmuData ($supervised.Count -eq 8 -and $supervised.schema -ceq 'fleetory.historical-dotnet-probe.v1' -and
        $supervised.mode -ceq $Mode -and $supervised.fault -eq $ManagedFault -and
        $supervised.heldBirthVerified -eq $true -and $supervised.heldExitVerified -eq $true -and
        $supervised.stdout -is [string]) 'controller-dotnet-exit-evidence'
    if($ManagedFault -ne 0){
        $expectedExit=if($ManagedFault -eq 1){65}else{137}
        Assert-ImmuData ($supervised.childExitCode -eq $expectedExit -and $supervised.payloadBytesReleased -eq 0 -and
            $supervised.stdout -ceq '') 'controller-dotnet-fault-evidence'
        return $supervised
    }
    Assert-ImmuData ($supervised.childExitCode -cin @(0,1) -and $supervised.payloadBytesReleased -eq $applicationInputLength) 'controller-dotnet-complete-evidence'
    $result=@{ExitCode=$supervised.childExitCode;Stdout=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($supervised.stdout));Stderr=''}
    foreach($value in $canaries){Assert-ImmuData (-not $result.Stdout.Contains($value,[StringComparison]::Ordinal)) 'controller-canary'}
    $value=$result.Stdout|ConvertFrom-Json -AsHashtable -Depth 16
    if($result.ExitCode -ne 0 -and -not $ExpectedType){
        foreach($name in @('errorType','causeType','location')){
            if($value[$name] -is [string] -and $value[$name] -cmatch '^[A-Za-z0-9_]{1,80}\z'){
                $managedApplicationRefusal[$name]=$value[$name]
            }
        }
    }
    if($Mode.StartsWith('observation-',[StringComparison]::Ordinal)){Assert-AuditObservationProbe $result $value $Mode $ExpectedType}
    else{Assert-ImmuData ($result.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($result.Stderr) -and $value.category -ceq $Mode) 'controller-probe'}
    if($Mode -ceq 'history-users'){
        Assert-ImmuData ($value.targetOnlyUsersCreated -eq $true) 'controller-dotnet-users-result'
    }
    if($Mode -ceq 'observation-reader-denial'){
        Assert-ImmuData ($value.readerWriteRefused -eq $true) 'controller-dotnet-reader-result'
    }
    $managedCalls[$Mode]=[int]$managedCalls[$Mode]+1
    return $value
}
function Invoke-AuditDataHealth($Store){$null=Invoke-ControllerProbe $Store 'audit-health'}
function Invoke-SelectedDotnetFault($Store,[string]$Mode,[string]$Prefix){
    $fault=switch -CaseSensitive ($FailurePoint){
        ($Prefix+'early-eof'){1;break}
        ($Prefix+'abrupt-exit'){2;break}
        default{0}
    }
    if($fault -eq 0){return}
    $script:managedFault=Invoke-ControllerProbe $Store $Mode -ManagedFault $fault
    Assert-ImmuData $false ('controller-'+$FailurePoint)
}
function Invoke-ControllerArchiveAction([string]$Mode){
    Assert-ImmuData ($Mode -cin @('verify','restore')) 'controller-archive-mode'
    Read-AuditDataStore $context $store
    $result=Invoke-Docker (Get-ImmuDataCliArguments $store.Id $Mode) $archive -AllowFailure
    if($result.ExitCode -ne 0){
        if(Test-HistoricalArchiveChecksumRefusal $result){Assert-ImmuData $false 'controller-native-archive-refusal'}
        throw 'Native archive operation failed.'
    }
}
function Invoke-HistoricalComparison([ValidateSet('build','observe')][string]$Operation,$Request,[string]$Fault='none'){
    Assert-ImmuData ($watch.Elapsed.TotalSeconds -lt 590) 'controller-deadline'
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Request|ConvertTo-Json -Compress -Depth 8 -WarningAction Stop))
    try{
        $reply=Invoke-NativeBytes $comparisonPython @('-I','-S','-B',(Join-Path $PSScriptRoot 'historical_audit_observation.py'),'--fenced',
            $Operation,$Fault,$comparisonPythonHash,$codeSnapshot.comparisonSourcePins) $bytes 10
    }finally{[Array]::Clear($bytes,0,$bytes.Length)}
    Assert-ImmuData ($reply.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($reply.Stderr)) 'controller-comparison-worker'
    $value=$reply.Stdout|ConvertFrom-Json -AsHashtable -Depth 18
    $platformFence=if($IsLinux){'linux-process-group'}else{'windows-job-object'}
    Assert-ImmuData ($value.schema -ceq 'fleetory.historical-comparison-worker.v1' -and $value.operation -ceq $Operation -and
        $value.fault -ceq $Fault -and $value.childImageAndBirthVerified -eq $true -and $value.childMembersAbsent -eq $true -and
        $value.fence -ceq $platformFence) 'controller-comparison-evidence'
    if($Fault -ceq 'none'){
        Assert-ImmuData ($value.childExitCode -eq 0 -and $value.requestBytes -eq ($bytes.Length+4) -and
            $value.result -is [System.Collections.IDictionary]) 'controller-comparison-result'
        return $value.result
    }
    $expectedBytes=if($Fault -ceq 'early-eof'){4}else{0}
    Assert-ImmuData ($null -eq $value.result -and $value.childExitCode -ne 0 -and $value.requestBytes -eq $expectedBytes) 'controller-comparison-fault'
    return $value
}
function Read-ControllerObservation {
    $native=Invoke-ControllerProbe $store 'observation-history-read'
    foreach($side in @('stateBefore','stateAfter')){
        $signed=New-ImmudbStateReceipt $native[$side] 'fleetoryaudit' (Join-Path $root 'target-public.pem')
        Assert-ImmuData ([int]$signed.txId -eq 5 -and $signed.txHash -ceq $source.txHash) 'controller-target-signed-point'
    }
    Read-AuditDataStore $context $store
    $native.producer=@{containerId=$store.Id;imageId=$context.ImageId;probeSha256=$context.ProbeHash}
    $expectedBytes=[Text.Encoding]::UTF8.GetBytes(($script:expected|ConvertTo-Json -Depth 8 -Compress))
    $request=@{expectedBase64=[Convert]::ToBase64String($expectedBytes);expectedSha256=(Get-ImmuDataHash $expectedBytes);
        observedBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($native|ConvertTo-Json -Depth 16 -Compress)))}
    return Invoke-HistoricalComparison 'observe' $request
}
[Fleetory.Pilot.AuditHistoricalProbeProfile]::Begin($context,${function:Invoke-Docker})
try{
    [byte[]]$raw=Read-HistoricalControllerPacket
    $admitted=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'historical_audit_restore.py'),$ExpectedPlanSha256) $raw 10
    Assert-ImmuData ($admitted.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($admitted.Stderr)) 'controller-input-admission'
    $admission=$admitted.Stdout|ConvertFrom-Json -AsHashtable -Depth 8
    $body=([Text.UTF8Encoding]::new($false,$true).GetString($raw))|ConvertFrom-Json -AsHashtable -Depth 16
    $plan=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($body.planBase64)))|ConvertFrom-Json -AsHashtable -Depth 8
    $stage='code';$codeSnapshot=Get-HistoricalAuditCodeSnapshot $repo -IncludeComparisonWorkerPins
    Assert-ImmuData ($codeSnapshot.revision -ceq $plan.revision) 'controller-code-revision'
    Assert-ImmuData ($codeSnapshot.sha256 -ceq $plan.codeSha256) 'controller-code-pin'
    $comparisonPython=(Get-Command $Python -CommandType Application).Source
    $interpreter=[IO.FileInfo]::new($comparisonPython)
    $resolved=$interpreter.ResolveLinkTarget($true)
    if($null -ne $resolved){$comparisonPython=$resolved.FullName}
    $comparisonPythonHash=(Get-HistoricalInputFileHash $comparisonPython 67108864).sha256
    New-AuditDataPublicPayload $repo $context
    $published=Publish-NativeProbe $repo 'ServerBackendProbe' $root
    $context.ProbeHash=(Get-FileHash -LiteralPath (Join-Path $published 'ServerBackendProbe.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-ImmuData ($context.ProbeHash -ceq $plan.probeSha256) 'controller-probe-pin'
    $context.ProbeBundle=Get-HistoricalProbeBundle $published
    Assert-ImmuData ($context.ProbeBundle.sha256 -ceq $plan.probeBundleSha256) 'controller-probe-bundle-pin'
    [IO.File]::WriteAllBytes((Join-Path $root 'source-public.pem'),[Convert]::FromBase64String($body.publicKeyBase64))
    . (Join-Path $repo 'eng/verify-immudb-state.ps1') -Address 'https://127.0.0.1:8090' -PublicKeyPath (Join-Path $root 'source-public.pem') -AnchorPath (Join-Path $root 'unused-anchor') -BearerToken ''
    $stage='source-signature'
    $sourceState=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($body.stateBase64)))|ConvertFrom-Json -AsHashtable -Depth 8
    $source=New-ImmudbStateReceipt $sourceState 'fleetoryaudit' (Join-Path $root 'source-public.pem')
    Assert-ImmuData ([int]$source.txId -eq 5 -and $source.txHash -ceq $admission.point.txHash) 'controller-source-signed-point'
    $stage='image';Build-AuditDataImage $context 'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'
    $context.Tls=New-PilotDisposableTlsMaterial -IncludeClient
    foreach($kind in @('admin','reader','writer')){$value=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();$context.Secrets['target-'+$kind]=$value;$canaries.Add($value)}
    $context.Secrets.wrong=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();$canaries.Add($context.Secrets.wrong)
    $key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    try{$context.SigningPems.target=$key.ExportECPrivateKeyPem();[IO.File]::WriteAllText((Join-Path $root 'target-public.pem'),$key.ExportSubjectPublicKeyInfoPem(),[Text.UTF8Encoding]::new($false))}finally{$key.Dispose()}
    foreach($pem in @($context.Tls.ServerPrivateKeyPem,$context.Tls.ClientPrivateKeyPem,$context.SigningPems.target)){foreach($line in ($pem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$canaries.Add($line.Substring(0,40))}}}
    $stage='container';$store=New-AuditDataStore $context 'target'
    if($FailurePoint -ceq 'after-container'){throw 'Injected controller refusal.'}
    $stage='restore';$archive=[Convert]::FromBase64String($body.archiveBase64)
    Invoke-ControllerArchiveAction 'verify'
    Invoke-ControllerArchiveAction 'restore'
    if($FailurePoint -ceq 'after-restore'){throw 'Injected controller refusal.'}
    Invoke-SelectedDotnetFault $store 'audit-health' 'dotnet-health-'
    Invoke-SelectedDotnetFault $store 'history-users' 'dotnet-users-'
    $null=Invoke-ControllerProbe $store 'history-users'
    $stage='expectation';$request=@{sourceBase64=$body.valuesBase64;sourceSha256=$plan.inputs.valuesSha256;nonce=$plan.nonce;point=$admission.point;
        producer=@{containerId=$store.Id;imageId=$context.ImageId;probeSha256=$context.ProbeHash}}
    Read-AuditDataStore $context $store
    if($FailurePoint -cin @('worker-early-eof','worker-abrupt-exit')){
        $comparisonFault=Invoke-HistoricalComparison 'build' $request $FailurePoint.Substring(7)
        Assert-ImmuData $false ('controller-'+$FailurePoint)
    }
    $script:expected=Invoke-HistoricalComparison 'build' $request
    $comparisonCalls++
    $stage='observe'
    if($FailurePoint -ceq 'dotnet-transport-loss'){
        Read-AuditDataStore $context $store
        $docker=(Get-Command $(if($IsWindows){'docker.exe'}else{'/usr/bin/docker'}) -CommandType Application).Source
        $transportFault=[Fleetory.Pilot.AuditHistoricalProbeProfile]::VerifyTransportLoss($context,$store,${function:Invoke-Docker},$plan.nonce,$docker)
        Assert-ImmuData $false 'controller-dotnet-transport-loss'
    }
    Invoke-SelectedDotnetFault $store 'observation-history-read' 'dotnet-'
    Invoke-SelectedDotnetFault $store 'observation-reader-denial' 'dotnet-denial-'
    $first=Read-ControllerObservation
    $comparisonCalls++
    $null=Invoke-ControllerProbe $store 'observation-history-read' 'authentication' -WrongPassword
    $null=Invoke-ControllerProbe $store 'observation-reader-denial'
    $stage='restart';Read-AuditDataStore $context $store
    $pidText=(Invoke-Docker @('exec',$store.Id,'/bin/cat','/tmp/immudb.pid')).Stdout.Trim()
    Assert-ImmuData ($pidText -cmatch '^[1-9][0-9]{0,7}\z') 'controller-pid'
    $null=Invoke-Docker @('exec',$store.Id,'/bin/kill','-TERM',$pidText);$stopped=$false
    for($n=0;$n -lt 40;$n++){$r=Invoke-Docker @('exec',$store.Id,'/bin/kill','-0',$pidText) -AllowFailure;if($r.ExitCode -ne 0){$stopped=$true;break};Start-Sleep -Milliseconds 200}
    Assert-ImmuData $stopped 'controller-server-stopped';Start-AuditDataServer $context $store
    $again=Read-ControllerObservation
    $comparisonCalls++
    Assert-ImmuData ($first.observationSha256 -ceq $again.observationSha256) 'controller-stable-restart'
    $proof=@{schema='fleetory.historical-audit-owned-observation.v1';verified=$true;historicalComparisonOnly=$true;observation=$again;
        nativeRestores=1;targetLifetimeSeconds=660;nativeDeadlineSeconds=600;historicalWorkerCommandsPinned=$true;historicalWorkerRawRepliesRetained=$true;historicalWorkerOsFenceVerified=$false;
        historicalComparisonWorkerFenceVerified=$true;historicalComparisonWorkerCalls=$comparisonCalls;
        dotnetObservationLeafExitVerified=($managedCalls['observation-history-read'] -eq 3);
        dotnetObservationLeafCalls=$managedCalls['observation-history-read'];dotnetModeExitCounts=$managedCalls;
        historicalWorkerCalls=[Fleetory.Pilot.AuditHistoricalProbeProfile]::Calls($context,${function:Invoke-Docker});sourceStateSignatureVerified=$true;targetStateSignaturesVerified=$true;
        codeAndProbePinsMatched=$true;inputDigestsMatched=$true;wrongPasswordRefused=$true;readerWriteRefused=$true;restartPreservedObservation=$true;
        freshTargetCredentialsAndKeys=$true;codeInventoryV2Matched=$true;publishedProbeBundleMatched=$true;containerProbeBundleMatched=$true;
        dataOriginAuthenticated=$false;externalGatesAuthenticated=$false;exclusiveUseLedgerVerified=$false;
        sourceFileOpened=$false;sourceVpsAccessed=$false;originalPrivatePkiUsed=$false;originalKeyContinuityVerified=$false;
        writerAdmissionVerified=$false;productionTokensIssued=$false;executionAuthorized=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}catch{
    $failure=$true
    $message=$_.Exception.GetBaseException().Message
    if($message -cmatch '^Audit data fixture refused: ([a-z0-9-]{1,64})\z'){$refusal=$Matches[1]}
    elseif($_.Exception.Message -ceq 'immudb state public key does not match the pinned key.'){$refusal='controller-source-public-pin'}
    elseif($_.Exception.Message -ceq 'The immudb state signature is invalid.'){$refusal='controller-source-signature'}
    elseif($_.Exception.Message -ceq 'Injected controller refusal.'){$refusal='controller-injected-failure'}
}finally{
    $cleaning=$true;$failures=@()
    foreach($item in $context.Stores){try{Remove-AuditDataStore $context $item}catch{$failures+='store'}}
    if(-not $failures.Count){try{Remove-AuditDataImage $context}catch{$failures+='image'}}
    if(-not $failures.Count){try{Remove-AuditDataPublicPayload $repo $context}catch{$failures+='payload'}}
    $cleanup=$failures.Count -eq 0
    $resources=@{fixture=$fixture;ids=@($context.Stores|ForEach-Object {$_.Id});image=$context.ImageName;payloadClaimed=($context.PayloadClaimed -or $context.PayloadRemoved);payloadRemoved=$context.PayloadRemoved;
        payloadAbsent=(-not (Test-Path -LiteralPath $root))}
    $context.Secrets.Clear();$context.SigningPems.Clear();$context.Tls=$null;$canaries.Clear();$archive=$body=$raw=$sourceState=$null
    $watch.Stop();$env:DOCKER_BUILDKIT=$oldBuildKit
}
if($failure -or -not $cleanup){
    @{schema='fleetory.historical-audit-controller-cleanup.v1';stage=$stage;refusal=$refusal;cleanupVerified=$cleanup;resources=$resources;comparisonFault=$comparisonFault;dotnetFault=$managedFault;dotnetTransportFault=$transportFault;dotnetApplicationRefusal=$managedApplicationRefusal}|ConvertTo-Json -Compress -Depth 5
    [Console]::Error.WriteLine('Historical native controller refused; no input contents or credentials logged.')
    exit 1
}
$proof.cleanupVerified=$true;$proof.resources=$resources
$proof|ConvertTo-Json -Compress -Depth 16
