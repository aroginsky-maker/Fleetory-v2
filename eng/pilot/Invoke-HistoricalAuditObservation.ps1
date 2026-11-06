#requires -Version 7.3
# Private stdin/stdout pipe. Receives frozen bytes, never an operator file path or address.
param([Parameter(Mandatory)][string]$ExpectedPlanSha256,[string]$Python='',
    [ValidateSet('none','after-container','after-restore')][string]$FailurePoint='none')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$testRoot=Join-Path $repo 'tests/Fleetory.Tools.Tests'
foreach($helper in @('PilotNativeProcess.ps1','ProviderRecoveryTransport.ps1','ProviderRecoveryPolicy.ps1','ImmuDataRoundtripPolicy.ps1','AuditObservationPolicy.ps1','HistoricalAuditControllerPolicy.ps1')){. (Join-Path $PSScriptRoot $helper)}
foreach($helper in @('PilotDisposableTls.ps1','NativeSignerFixture.ps1','NativeAuditFixture.ps1','NativeWorkerRuntime.ps1','NativeAuditDataFixture.ps1')){. (Join-Path $testRoot $helper)}
if(-not $Python){$Python=(Get-Command $(if($IsLinux){'python3'}else{'python'})).Source}
$fixture=[Guid]::NewGuid().ToString('D');$root=Join-Path $repo ('artifacts/native-audit-controller-'+$fixture)
$context=@{Fixture=$fixture;Root=$root;ImageName=(Get-ImmuDataImageName $fixture);ImageId=$null;ImageClaimed=$false;ProbeHash=$null;
    LifetimeSeconds=660;Stores=[Collections.Generic.List[object]]::new();Tls=$null;SigningPems=@{};Secrets=@{}}
$canaries=[Collections.Generic.List[string]]::new();$watch=[Diagnostics.Stopwatch]::StartNew();$cleaning=$false
$stage='input';$refusal='operational';$failure=$false;$cleanup=$false;$proof=$null;$store=$null;$body=$null;$archive=$null;$raw=$null
$oldBuildKit=$env:DOCKER_BUILDKIT;$env:DOCKER_BUILDKIT='0'
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
    Assert-ImmuData ($cleaning -or $watch.Elapsed.TotalSeconds -lt 600) 'controller-deadline'
    $result=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments -ClassicBuilder:($Arguments[0] -ceq 'build'))) $InputBytes $TimeoutSeconds}else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    foreach($value in $canaries){Assert-ImmuData (-not ($result.Stdout+$result.Stderr).Contains($value,[StringComparison]::Ordinal)) 'controller-canary'}
    if(-not $AllowFailure){Assert-ImmuData ($result.ExitCode -eq 0) 'controller-docker'}
    return $result
}
function Invoke-ControllerProbe($Store,[string]$Mode,[string]$ExpectedType='',[switch]$WrongPassword){
    Read-AuditDataStore $context $Store
    $packet=@{fixture=$plan.nonce;admin=$context.Secrets['target-admin'];reader=$context.Secrets['target-reader'];writer=$context.Secrets['target-writer']}
    if($Mode -ceq 'observation-history-read'){$packet=@{fixture=$plan.nonce;reader=$(if($WrongPassword){$context.Secrets.wrong}else{$context.Secrets['target-reader']});observation=$script:expected}}
    $result=Invoke-Docker @('exec','-i','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',$Store.Id,'dotnet','/tool/ServerBackendProbe.dll',$Mode) ([Text.Encoding]::UTF8.GetBytes(($packet|ConvertTo-Json -Compress -Depth 8))) -AllowFailure
    $value=$result.Stdout|ConvertFrom-Json -AsHashtable -Depth 16
    if($Mode.StartsWith('observation-',[StringComparison]::Ordinal)){Assert-AuditObservationProbe $result $value $Mode $ExpectedType}
    else{Assert-ImmuData ($result.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($result.Stderr) -and $value.category -ceq $Mode) 'controller-probe'}
    return $value
}
function Invoke-AuditDataHealth($Store){$null=Invoke-ControllerProbe $Store 'audit-health'}
function Invoke-ControllerArchiveAction([string]$Mode){
    Assert-ImmuData ($Mode -cin @('verify','restore')) 'controller-archive-mode'
    Read-AuditDataStore $context $store
    $result=Invoke-Docker (Get-ImmuDataCliArguments $store.Id $Mode) $archive -AllowFailure
    if($result.ExitCode -ne 0){
        if(Test-HistoricalArchiveChecksumRefusal $result){Assert-ImmuData $false 'controller-native-archive-refusal'}
        throw 'Native archive operation failed.'
    }
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
    $checked=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'historical_audit_observation.py'),'observe') ([Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Compress))) 10
    Assert-ImmuData ($checked.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($checked.Stderr)) 'controller-observation-policy'
    return $checked.Stdout|ConvertFrom-Json -AsHashtable -Depth 12
}
try{
    [byte[]]$raw=Read-HistoricalControllerPacket
    $admitted=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'historical_audit_restore.py'),$ExpectedPlanSha256) $raw 10
    Assert-ImmuData ($admitted.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($admitted.Stderr)) 'controller-input-admission'
    $admission=$admitted.Stdout|ConvertFrom-Json -AsHashtable -Depth 8
    $body=([Text.UTF8Encoding]::new($false,$true).GetString($raw))|ConvertFrom-Json -AsHashtable -Depth 16
    $plan=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($body.planBase64)))|ConvertFrom-Json -AsHashtable -Depth 8
    $stage='code';Assert-ImmuData ((Get-HistoricalAuditCodeHash) -ceq $plan.codeSha256) 'controller-code-pin'
    $null=New-Item -ItemType Directory -Path $root
    $published=Publish-NativeProbe $repo 'ServerBackendProbe' $root
    $context.ProbeHash=(Get-FileHash -LiteralPath (Join-Path $published 'ServerBackendProbe.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-ImmuData ($context.ProbeHash -ceq $plan.probeSha256) 'controller-probe-pin'
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
    $null=Invoke-ControllerProbe $store 'history-users'
    $stage='expectation';$request=@{sourceBase64=$body.valuesBase64;sourceSha256=$plan.inputs.valuesSha256;nonce=$plan.nonce;point=$admission.point;
        producer=@{containerId=$store.Id;imageId=$context.ImageId;probeSha256=$context.ProbeHash}}
    $built=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'historical_audit_observation.py'),'build') ([Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Compress -Depth 8))) 10
    Assert-ImmuData ($built.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($built.Stderr)) 'controller-expectation'
    $script:expected=$built.Stdout|ConvertFrom-Json -AsHashtable -Depth 12
    $stage='observe';$first=Read-ControllerObservation
    $null=Invoke-ControllerProbe $store 'observation-history-read' 'authentication' -WrongPassword
    $null=Invoke-ControllerProbe $store 'observation-reader-denial'
    $stage='restart';Read-AuditDataStore $context $store
    $pidText=(Invoke-Docker @('exec',$store.Id,'/bin/cat','/tmp/immudb.pid')).Stdout.Trim()
    Assert-ImmuData ($pidText -cmatch '^[1-9][0-9]{0,7}\z') 'controller-pid'
    $null=Invoke-Docker @('exec',$store.Id,'/bin/kill','-TERM',$pidText);$stopped=$false
    for($n=0;$n -lt 40;$n++){$r=Invoke-Docker @('exec',$store.Id,'/bin/kill','-0',$pidText) -AllowFailure;if($r.ExitCode -ne 0){$stopped=$true;break};Start-Sleep -Milliseconds 200}
    Assert-ImmuData $stopped 'controller-server-stopped';Start-AuditDataServer $context $store
    $again=Read-ControllerObservation
    Assert-ImmuData ($first.observationSha256 -ceq $again.observationSha256) 'controller-stable-restart'
    $proof=@{schema='fleetory.historical-audit-owned-observation.v1';verified=$true;historicalComparisonOnly=$true;observation=$again;
        nativeRestores=1;targetLifetimeSeconds=660;nativeDeadlineSeconds=600;sourceStateSignatureVerified=$true;targetStateSignaturesVerified=$true;
        codeAndProbePinsMatched=$true;inputDigestsMatched=$true;wrongPasswordRefused=$true;readerWriteRefused=$true;restartPreservedObservation=$true;
        freshTargetCredentialsAndKeys=$true;dataOriginAuthenticated=$false;externalGatesAuthenticated=$false;exclusiveUseLedgerVerified=$false;
        sourceFileOpened=$false;sourceVpsAccessed=$false;originalPrivatePkiUsed=$false;originalKeyContinuityVerified=$false;
        writerAdmissionVerified=$false;productionTokensIssued=$false;executionAuthorized=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}catch{
    $failure=$true
    if($_.Exception.Message -cmatch '^Audit data fixture refused: ([a-z0-9-]{1,64})\z'){$refusal=$Matches[1]}
    elseif($_.Exception.Message -ceq 'immudb state public key does not match the pinned key.'){$refusal='controller-source-public-pin'}
    elseif($_.Exception.Message -ceq 'The immudb state signature is invalid.'){$refusal='controller-source-signature'}
    elseif($_.Exception.Message -ceq 'Injected controller refusal.'){$refusal='controller-injected-failure'}
}finally{
    $cleaning=$true;$failures=@()
    foreach($item in $context.Stores){try{Remove-AuditDataStore $context $item}catch{$failures+='store'}}
    if(-not $failures.Count){try{Remove-AuditDataImage $context}catch{$failures+='image'}}
    if(-not $failures.Count){try{Remove-NativePublicPayload $repo $root}catch{$failures+='payload'}}
    $cleanup=$failures.Count -eq 0
    $resources=@{fixture=$fixture;ids=@($context.Stores|ForEach-Object {$_.Id});image=$context.ImageName;payloadRemoved=$cleanup}
    $context.Secrets.Clear();$context.SigningPems.Clear();$context.Tls=$null;$canaries.Clear();$archive=$body=$raw=$sourceState=$null
    $watch.Stop();$env:DOCKER_BUILDKIT=$oldBuildKit
}
if($failure -or -not $cleanup){
    @{schema='fleetory.historical-audit-controller-cleanup.v1';stage=$stage;refusal=$refusal;cleanupVerified=$cleanup;resources=$resources}|ConvertTo-Json -Compress -Depth 5
    [Console]::Error.WriteLine('Historical native controller refused; no input contents or credentials logged.')
    exit 1
}
$proof.cleanupVerified=$true;$proof.resources=$resources
$proof|ConvertTo-Json -Compress -Depth 16
