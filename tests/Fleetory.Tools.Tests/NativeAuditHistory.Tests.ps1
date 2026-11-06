#requires -Version 7.3
param([string]$Python='',[ValidateSet('none','after-stores')][string]$FailurePoint='none',[ValidateSet('history','observation','historical-observation')][string]$Profile='history')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($helper in @('PilotNativeProcess.ps1','../../eng/pilot/ProviderRecoveryTransport.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1','../../eng/pilot/ImmuDataRoundtripPolicy.ps1','../../eng/pilot/AuditHistoryPolicy.ps1','../../eng/pilot/AuditObservationPolicy.ps1','PilotDisposableTls.ps1','NativeSignerFixture.ps1','NativeAuditFixture.ps1','NativeWorkerRuntime.ps1','NativeAuditDataFixture.ps1')){. (Join-Path $PSScriptRoot $helper)}
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if(-not $Python){$Python=(Get-Command $(if($IsLinux){'python3'}else{'python'})).Source}
$fixture=[Guid]::NewGuid().ToString('D');$root=Join-Path $repo ('artifacts/native-audit-history-'+$fixture)
$context=@{Fixture=$fixture;Root=$root;ImageName=(Get-ImmuDataImageName $fixture);ImageId=$null;ImageClaimed=$false;ProbeHash=$null;Stores=[Collections.Generic.List[object]]::new();Tls=$null;SigningPems=@{};Secrets=@{}}
$canaries=[Collections.Generic.List[string]]::new();$stage='publish';$watch=[Diagnostics.Stopwatch]::StartNew();$cleaning=$false;$proof=$null
$oldBuildKit=$env:DOCKER_BUILDKIT;$env:DOCKER_BUILDKIT='0'
foreach($role in @('source','target','corrupt')){foreach($kind in @('admin','reader','writer')){$value=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();$context.Secrets[$role+'-'+$kind]=$value;$canaries.Add($value)}}
$context.Secrets.wrong=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();$canaries.Add($context.Secrets.wrong)
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
    Assert-ImmuData ($cleaning -or $watch.Elapsed.TotalSeconds -lt 600) 'history-deadline'
    $r=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments -ClassicBuilder:($Arguments[0] -ceq 'build'))) $InputBytes $TimeoutSeconds}else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    foreach($v in $canaries){Assert-ImmuData (-not ($r.Stdout+$r.Stderr).Contains($v,[StringComparison]::Ordinal)) 'history-canary'}
    if(-not $AllowFailure){Assert-ImmuData ($r.ExitCode -eq 0) 'history-docker'}
    return $r
}
function Probe($Store,[string]$Mode,[string]$ExpectedType='',[switch]$WrongPassword){
    Read-AuditDataStore $context $Store
    $body=@{fixture=$fixture;admin=$(if($WrongPassword){$context.Secrets.wrong}else{$context.Secrets[$Store.Role+'-admin']});reader=$context.Secrets[$Store.Role+'-reader'];writer=$context.Secrets[$Store.Role+'-writer']}
    if($Mode -cin @('observation-read','observation-history-read')){$body=@{fixture=$fixture;reader=$(if($WrongPassword){$context.Secrets.wrong}else{$context.Secrets[$Store.Role+'-reader']});observation=$script:observationExpectation}}
    $r=Invoke-Docker @('exec','-i','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',$Store.Id,'dotnet','/tool/ServerBackendProbe.dll',$Mode) ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Depth 6 -Compress))) -AllowFailure
    $v=$r.Stdout|ConvertFrom-Json -AsHashtable -Depth 16
    if($r.ExitCode -ne 0 -and -not $ExpectedType -and $Mode -cne 'audit-health'){
        foreach($name in @('errorType','causeType','location')){if($v.ContainsKey($name) -and $v[$name] -cmatch '^[A-Za-z0-9_]{1,80}\z'){[Console]::Error.WriteLine('History probe '+$Mode+': '+$name+'='+$v[$name])}}
    }
    if($Mode.StartsWith('observation-',[StringComparison]::Ordinal)){Assert-AuditObservationProbe $r $v $Mode $ExpectedType}else{Assert-AuditHistoryProbe $r $v $Mode $ExpectedType}
    return $v
}
function Invoke-AuditDataHealth($Store){$null=Probe $Store 'audit-health'}
function Public-KeyPath([string]$Role){Assert-ImmuData ($Role -cin @('source','target','corrupt')) 'public-role';return Join-Path $root ($Role+'-public.pem')}
function Point($Store,[string]$Mode='history-read'){
    $v=Probe $Store $Mode
    Assert-ImmuData ($v.fixture -ceq $fixture -and $v.events -eq 4 -and $v.keys -eq 5 -and $v.transactions -eq 5 -and $v.completeKeysetVerified -eq $true -and $v.allFiveNativeTransactionsVerified -eq $true -and $v.singleRevisionPerKeyVerified -eq $true -and $v.nativeSinkEventFieldsVerified -eq $true -and $v.stableReadWindow -eq $true) 'history-readback'
    if($Mode -ceq 'history-reader'){Assert-ImmuData ($v.readerWriteRefused -eq $true) 'history-reader-denial'}
    $receipt=New-ImmudbStateReceipt $v.state 'fleetoryaudit' (Public-KeyPath $Store.Role)
    return [ordered]@{database=$receipt.database;tx=[int]$receipt.txId;txHash=[Convert]::ToHexString([Convert]::FromBase64String($receipt.txHash));keyFingerprint=$receipt.publicKeySha256;historySha256=$v.historySha256;events=4;keys=5;transactions=5}
}
function Same-SourcePoint($Value,$Expected){Assert-ImmuData (($Value|ConvertTo-Json -Compress) -ceq ($Expected|ConvertTo-Json -Compress)) 'source-point'}
function Compare-Restore($Value){
    $body=[Text.Encoding]::UTF8.GetBytes((@{source=$script:expected;target=$Value}|ConvertTo-Json -Depth 5 -Compress))
    $r=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/audit_history_inputs.py'),'compare') $body 10
    Assert-ImmuData ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'distinct-key-restored-point'
    $v=$r.Stdout|ConvertFrom-Json -AsHashtable
    Assert-ImmuData ($v.sameDataDistinctSigners -eq $true -and $v.signaturesVerified -eq $false -and $v.originalKeyContinuityVerified -eq $false -and $v.executionAuthorized -eq $false) 'point-comparison-scope'
}
function Restored-Target{
    $s=New-AuditDataStore $context 'target'
    $null=Invoke-Docker (Get-ImmuDataCliArguments $s.Id 'verify') $script:captured
    $null=Invoke-Docker (Get-ImmuDataCliArguments $s.Id 'restore') $script:captured
    $null=Probe $s 'history-users'
    Compare-Restore (Point $s)
    $script:restores++
    return $s
}
function Crypto-Refused($State,[string]$Path,[string]$ExpectedReason='The immudb state signature is invalid.'){
    $seen=$false;try{$null=New-ImmudbStateReceipt $State 'fleetoryaudit' $Path}catch{Assert-AuditHistoryCryptoReason $_.Exception.Message $ExpectedReason;$seen=$true}
    Assert-ImmuData $seen 'history-crypto-refusal'
}
try{
    $null=New-Item -ItemType Directory -Path $root
    $published=Publish-NativeProbe $repo 'ServerBackendProbe' $root
    $context.ProbeHash=(Get-FileHash -LiteralPath (Join-Path $published 'ServerBackendProbe.dll')).Hash.ToLowerInvariant()
    . (Join-Path $repo 'eng/verify-immudb-state.ps1') -Address 'https://127.0.0.1:8090' -PublicKeyPath (Public-KeyPath 'source') -AnchorPath (Join-Path $root 'unused-anchor') -BearerToken ''
    Build-AuditDataImage $context 'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'
    $context.Tls=New-PilotDisposableTlsMaterial -IncludeClient
    foreach($role in @('source','target','corrupt')){
        $key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
        try{$context.SigningPems[$role]=$key.ExportECPrivateKeyPem();[IO.File]::WriteAllText((Public-KeyPath $role),$key.ExportSubjectPublicKeyInfoPem(),[Text.UTF8Encoding]::new($false))}finally{$key.Dispose()}
    }
    foreach($pem in @($context.Tls.ServerPrivateKeyPem,$context.Tls.ClientPrivateKeyPem)+@($context.SigningPems.Values)){foreach($line in ($pem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$canaries.Add($line.Substring(0,40))}}}
    $stage='stores';$source=New-AuditDataStore $context 'source';$target=New-AuditDataStore $context 'target'
    if($FailurePoint -ceq 'after-stores'){Write-Output 'AUDIT HISTORY INJECTED FAILURE AFTER STORES';throw 'Intentional history fixture failure.'}
    if($Profile -ceq 'historical-observation'){
        . (Join-Path $PSScriptRoot 'NativeAuditObservationWorkflow.ps1')
        . (Join-Path $PSScriptRoot 'NativeHistoricalObservationWorkflow.ps1')
        $proof=Invoke-NativeHistoricalObservationWorkflow $source $target
    }elseif($Profile -ceq 'observation'){
        . (Join-Path $PSScriptRoot 'NativeAuditObservationWorkflow.ps1')
        $proof=Invoke-NativeAuditObservationWorkflow $source $target
    }else{
    $stage='seed';$null=Probe $source 'history-seed';$script:expected=Point $source
    $stage='capture';Read-AuditDataStore $context $source
    $dump=(Invoke-Docker (Get-ImmuDataCliArguments $source.Id 'backup')).StdoutBytes;$pin=Get-ImmuDataHash $dump;Assert-ImmuDataPacket $dump $pin
    $after=Point $source;Same-SourcePoint $after $expected
    $manifest=@{schema='fleetory.generated-audit-history-capture.v1';scope='generated-only-no-original-approval';fixture=$fixture;probeSha256=$context.ProbeHash;imageId=$context.ImageId;sourceContainer=$source.Id;point=$expected;capture=@{before=$expected;after=$after};artifact=@{bytes=$dump.Length;sha256=$pin}}
    $manifestBytes=[Text.Encoding]::UTF8.GetBytes(($manifest|ConvertTo-Json -Depth 7 -Compress));$manifestPin=Get-ImmuDataHash $manifestBytes
    $body=[Text.Encoding]::UTF8.GetBytes((@{manifestBase64=[Convert]::ToBase64String($manifestBytes);backupBase64=[Convert]::ToBase64String($dump)}|ConvertTo-Json -Compress))
    $r=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/audit_history_inputs.py'),'--pin',$manifestPin,'--fixture',$fixture) $body 30
    Assert-ImmuData ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'history-admission'
    $c=$r.Stdout|ConvertFrom-Json -AsHashtable
    Assert-ImmuData ($c.generatedOnly -eq $true -and $c.executionAuthorized -eq $false -and $c.signaturesVerified -eq $false -and $c.nativeChecksumVerified -eq $false -and $c.originalKeyContinuityVerified -eq $false) 'history-capture-scope'
    $script:captured=[Convert]::FromBase64String($c.backupBase64);Assert-ImmuDataPacket $captured $pin;[Array]::Clear($dump);$body=$c=$r=$null
    $stage='format';$null=Invoke-Docker (Get-ImmuDataCliArguments $target.Id 'verify') $captured
    $short=[byte[]]::new(64);[Array]::Copy($captured,$short,64)
    $bad=Invoke-Docker (Get-ImmuDataCliArguments $target.Id 'verify') $short -AllowFailure
    Assert-ImmuData ($bad.ExitCode -ne 0 -and ($bad.Stderr+$bad.Stdout) -match '(?i)malformed|unexpected|EOF|corrupt') 'history-native-truncation'
    $stage='corruption';$corrupt=New-AuditDataStore $context 'corrupt';$badBytes=$captured.Clone();$badBytes[30]=$badBytes[30] -bxor 1
    $bad=Invoke-Docker (Get-ImmuDataCliArguments $corrupt.Id 'restore') $badBytes -AllowFailure
    Assert-ImmuData ($bad.ExitCode -ne 0 -and ($bad.Stderr+$bad.Stdout) -match '(?i)transaction checksums don.t match|malformed|unexpected|EOF|corrupt') 'history-native-corruption'
    Remove-AuditDataStore $context $corrupt
    $stage='restore';$null=Invoke-Docker (Get-ImmuDataCliArguments $target.Id 'restore') $captured;$null=Probe $target 'history-users';$script:restores=1
    Compare-Restore (Point $target 'history-reader')
    $duplicate=Invoke-Docker (Get-ImmuDataCliArguments $target.Id 'restore') $captured -AllowFailure
    Assert-ImmuData ($duplicate.ExitCode -ne 0 -and ($duplicate.Stdout+$duplicate.Stderr).Contains('cannot restore to non-empty database without --append flag',[StringComparison]::Ordinal)) 'history-nonempty-refusal'
    Compare-Restore (Point $target)
    $stage='keyset-refusal';$null=Probe $target 'history-extra';$null=Probe $target 'history-read' 'AuditHistoryKeySetException';Remove-AuditDataStore $context $target
    $stage='revision-refusal';$target=Restored-Target;$null=Probe $target 'history-rewrite';$null=Probe $target 'history-read' 'AuditHistoryRevisionException';Remove-AuditDataStore $context $target
    $stage='transaction-refusal';$target=New-AuditDataStore $context 'target';$null=Probe $target 'history-seed-reversed';$null=Probe $target 'history-read' 'AuditHistoryTransactionException';Remove-AuditDataStore $context $target
    $stage='positive-target';$target=Restored-Target;Compare-Restore (Point $target 'history-reader')
    $badLogin=Probe $target 'history-wrong-password' -WrongPassword;Assert-ImmuData ($badLogin.refused -eq $true) 'history-wrong-password'
    $stage='crypto';$sourceState=(Probe $source 'history-read').state;$targetState=(Probe $target 'history-read').state
    Crypto-Refused $sourceState (Public-KeyPath 'target') 'immudb state public key does not match the pinned key.';Crypto-Refused $targetState (Public-KeyPath 'source') 'immudb state public key does not match the pinned key.'
    foreach($kind in @('signature','hash','tx','database')){
        $changed=($targetState|ConvertTo-Json -Depth 6)|ConvertFrom-Json -AsHashtable
        if($kind -ceq 'signature'){$bytes=[Convert]::FromBase64String($changed.signature.signature);$bytes[-1]=$bytes[-1] -bxor 1;$changed.signature.signature=[Convert]::ToBase64String($bytes)}
        elseif($kind -ceq 'hash'){$bytes=[Convert]::FromBase64String($changed.txHash);$bytes[0]=$bytes[0] -bxor 1;$changed.txHash=[Convert]::ToBase64String($bytes)}
        elseif($kind -ceq 'tx'){$changed.txId='4'}else{$changed.db='defaultdb'}
        $reason=if($kind -ceq 'database'){"Unexpected immudb database 'defaultdb'."}else{'The immudb state signature is invalid.'}
        Crypto-Refused $changed (Public-KeyPath 'target') $reason
    }
    $stage='restart';Read-AuditDataStore $context $target
    $pidText=(Invoke-Docker @('exec',$target.Id,'/bin/cat','/tmp/immudb.pid')).Stdout.Trim();Assert-ImmuData ($pidText -cmatch '^[1-9][0-9]{0,7}\z') 'history-server-pid'
    $null=Invoke-Docker @('exec',$target.Id,'/bin/kill','-TERM',$pidText);$stopped=$false
    for($n=0;$n -lt 40;$n++){$r=Invoke-Docker @('exec',$target.Id,'/bin/kill','-0',$pidText) -AllowFailure;if($r.ExitCode -ne 0){$stopped=$true;break};Start-Sleep -Milliseconds 200}
    Assert-ImmuData $stopped 'history-stop';Start-AuditDataServer $context $target
    Compare-Restore (Point $target 'history-reader');Same-SourcePoint (Point $source) $expected
    $proof=@{schema='fleetory.native-audit-history.v1';verified=$true;scope='generated five-transaction audit history only';events=4;keys=5;nativeTransactions=5;revisionsPerKey=1;nativeTransactionHeadersVerified=5;independentMerkleInclusionProofsVerified=$false;productionSinkEventFieldsVerified=$true;sourceTargetKeysDistinct=$true;sourceKeyContinuityClaimed=$false;signaturesAndOwnPinsVerified=$true;cryptoRefusals=6;nativeDataRefusals=3;readerWriteRefusals=3;targetWrongPasswordRefused=$true;nativeCorruptionRefused=$true;nativeTruncationRefused=$true;nonemptyRestoreRefused=$true;nativeRestores=$restores;backupBytes=$captured.Length;backupSha256=$pin;manifestSha256=$manifestPin;probeSha256=$context.ProbeHash;historySha256=$expected.historySha256;txHash=$expected.txHash;sourceKeyFingerprint=$expected.keyFingerprint;targetKeyFingerprint=(Point $target).keyFingerprint;capturedBytesFrozen=$true;sourceObservedStableAndUnchanged=$true;restartPreservedHistoryAndReader=$true;originalInputsRead=$false;sourceVpsAccessed=$false;originalPkiOrProviderUsed=$false;originalKeyRecovered=$false;serverApplicationStarted=$false;issuerActivated=$false;globalAtomicSnapshotClaimed=$false;untrustedArchiveSandboxVerified=$false;sessionTokenRevocationVerified=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
    }
}catch{
    if($_.Exception.Message -cmatch '^Audit data fixture refused: ([a-z0-9-]{1,64})\z'){[Console]::Error.WriteLine('Audit history refusal category='+$Matches[1])}
    [Console]::Error.WriteLine('Native audit history failed at '+$stage+'; type='+$_.Exception.GetType().Name+'; line='+$_.InvocationInfo.ScriptLineNumber+'. No packet, value or credential logged.')
    throw 'Native audit history fixture failed.'
}finally{
    $cleaning=$true;$failures=@()
    foreach($s in $context.Stores){try{Remove-AuditDataStore $context $s}catch{$failures+='store'}}
    if(-not $failures.Count){try{Remove-AuditDataImage $context}catch{$failures+='image'}}
    if(-not $failures.Count){try{Remove-NativePublicPayload $repo $root}catch{$failures+='payload'}}
    $env:DOCKER_BUILDKIT=$oldBuildKit;$context.Secrets.Clear();$context.SigningPems.Clear();$context.Tls=$null;$canaries.Clear();$captured=$dump=$body=$c=$null;$watch.Stop()
    if($failures.Count){throw 'Native audit history owned cleanup unverified; ledger retained.'}
    @{schema='fleetory.native-audit-history-cleanup.v1';fixture=$fixture;ids=@($context.Stores|ForEach-Object {$_.Id});image=$context.ImageName;cleanupVerified=$true;originalInputsRead=$false}|ConvertTo-Json -Compress
}
if($FailurePoint -ceq 'none'){
    $fault=Invoke-NativeBytes ([Environment]::ProcessPath) @('-NoLogo','-NoProfile','-NonInteractive','-File',$PSCommandPath,'-Python',$Python,'-FailurePoint','after-stores','-Profile',$Profile) -TimeoutSeconds 120
    Assert-ImmuData ($fault.ExitCode -ne 0 -and $fault.Stdout.Contains('AUDIT HISTORY INJECTED FAILURE AFTER STORES') -and $fault.Stderr.Contains('Native audit history fixture failed.')) 'history-fault-exit'
    $records=@($fault.Stdout -split '\r?\n'|Where-Object {$_.StartsWith('{')}|ForEach-Object {$_|ConvertFrom-Json -AsHashtable}|Where-Object {$_.schema -ceq 'fleetory.native-audit-history-cleanup.v1'})
    Assert-ImmuData ($records.Count -eq 1 -and $records[0].cleanupVerified -eq $true -and $records[0].originalInputsRead -eq $false -and @($records[0].ids).Count -eq 2 -and $records[0].image -ceq (Get-ImmuDataImageName $records[0].fixture)) 'history-fault-record'
    foreach($id in $records[0].ids){Assert-ImmuData ($id -cmatch '^[a-f0-9]{64}\z') 'history-fault-id';$r=Invoke-Docker @('inspect',$id) -AllowFailure;Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'history-fault-store-absence'}
    $r=Invoke-Docker @('image','inspect',$records[0].image) -AllowFailure;Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'history-fault-image-absence'
    Assert-ImmuData (-not (Test-Path -LiteralPath (Join-Path $repo ('artifacts/native-audit-history-'+$records[0].fixture)))) 'history-fault-payload-absence'
    $proof.faultCleanupVerified=$true;$proof.faultCleanupContainers=2
}
$proof.cleanupVerified=$true;$proof|ConvertTo-Json -Compress -Depth 8
$global:LASTEXITCODE=0
