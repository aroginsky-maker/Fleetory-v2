#requires -Version 7.3
param([string]$Python='',[ValidateSet('none','after-stores')][string]$FailurePoint='none')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'ImmuDataRoundtripPolicy.Tests.ps1')
foreach($helper in @('PilotNativeProcess.ps1','../../eng/pilot/ProviderRecoveryTransport.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1','PilotDisposableTls.ps1','NativeSignerFixture.ps1','NativeAuditFixture.ps1','NativeWorkerRuntime.ps1','NativeAuditDataFixture.ps1')){. (Join-Path $PSScriptRoot $helper)}
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$fixture=[Guid]::NewGuid().ToString('D');$root=Join-Path $repo ('artifacts/native-immu-data-'+$fixture)
$cliImage='codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'
$imageName=Get-ImmuDataImageName $fixture;$stores=@();$stage='publish';$proof=$null;$cleaning=$false
$previousBuildKit=$env:DOCKER_BUILDKIT;$env:DOCKER_BUILDKIT='0'
$watch=[Diagnostics.Stopwatch]::StartNew();$canaries=[Collections.Generic.List[string]]::new();$lastExit=0;$lastOperation='none';$lastClass='none'
$secrets=@{}
foreach($name in @('source-admin','target-admin','source-reader','target-reader','corrupt-admin','corrupt-reader','wrong')){$secrets[$name]=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();$canaries.Add($secrets[$name])}
if(-not $Python){$Python=(Get-Command $(if($IsLinux){'python3'}else{'python'})).Source}
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60,[switch]$AllowFailure){
    Assert-ImmuData ($cleaning -or $watch.Elapsed.TotalSeconds -lt 600) 'fixture-deadline'
    $r=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments -ClassicBuilder:($Arguments[0] -ceq 'build'))) $InputBytes $TimeoutSeconds}
        else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    $script:lastExit=$r.ExitCode;$script:lastOperation=$Arguments[0]
    $script:lastClass='unclassified'
    foreach($kind in @('invalid password','invalid argument','not a terminal','inappropriate ioctl','no such file','permission denied','x509','certificate','unauthenticated','not logged','EOF','password')){if(($r.Stdout+$r.Stderr).Contains($kind,[StringComparison]::OrdinalIgnoreCase)){$script:lastClass=$kind.Replace(' ','-');break}}
    foreach($v in $canaries){Assert-ImmuData (-not ($r.Stdout+$r.Stderr).Contains($v,[StringComparison]::Ordinal)) 'credential-canary'}
    if(-not $AllowFailure){Assert-ImmuData ($r.ExitCode -eq 0) 'docker-operation'}
    return $r
}
$auditContext=@{Fixture=$fixture;Root=$root;ImageName=$imageName;ImageId=$null;ImageClaimed=$false;ProbeHash=$null;Stores=[Collections.Generic.List[object]]::new();Tls=$null;SigningPems=@{};Secrets=$secrets}
function Owned($s,[switch]$Cleanup){Read-AuditDataStore $auditContext $s -Cleanup:$Cleanup}
function Invoke-AuditDataHealth($s){$null=Probe $s 'audit-health'}
function Probe($s,[string]$Mode,[switch]$WrongPassword){
    Owned $s
    if($Mode -cne 'audit-health'){$script:stage=$s.Role+'-'+$Mode}
    $admin=if($WrongPassword){$secrets.wrong}else{$secrets[$s.Role+'-admin']}
    $packet=[Text.Encoding]::UTF8.GetBytes((@{admin=$admin;reader=$secrets[$s.Role+'-reader']}|ConvertTo-Json -Compress))
    $r=Invoke-Docker @('exec','-i','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',$s.Id,'dotnet','/tool/ServerBackendProbe.dll',$Mode) $packet -AllowFailure
    $v=$r.Stdout|ConvertFrom-Json -AsHashtable -Depth 16
    if($r.ExitCode -ne 0 -and $Mode -cne 'audit-health'){[Console]::Error.WriteLine('Audit probe category='+[string]$v.category+'; type='+[string]$v.errorType+'; cause='+[string]$v.causeType+'; status='+[string]$v.controlStatus)}
    Assert-ImmuData ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr)) 'probe-process'
    Assert-ImmuData ($v.category -ceq $Mode) 'probe-category'
    return $v
}
function Start-Server($s){Start-AuditDataServer $auditContext $s}
function New-Store([string]$Role){
    $auditContext.Tls=$tls;$auditContext.SigningPems[$Role]=$script:signingPem
    $s=New-AuditDataStore $auditContext $Role;$script:stores=@($auditContext.Stores.ToArray());return $s
}
function Point($s,[string]$Mode='immu-inspect'){
    $snapshot=Probe $s $Mode
    Assert-ImmuData ($snapshot.keyCount -eq 4 -and $snapshot.stableReadWindow -eq $true -and $snapshot.originalMaterialUsed -eq $false) 'snapshot'
    if($Mode -ceq 'immu-reader'){Assert-ImmuData ($snapshot.readerWriteRefused -eq $true) 'reader-write-refusal'}
    $receipt=New-ImmudbStateReceipt $snapshot.state 'fleetoryaudit' (Join-Path $root 'state-public.pem')
    $entries=[Text.Encoding]::UTF8.GetBytes(($snapshot.entries|ConvertTo-Json -Depth 5 -Compress))
    return @{database=$receipt.database;tx=[long]$receipt.txId;txHash=[Convert]::ToHexString([Convert]::FromBase64String($receipt.txHash));
        keyFingerprint=$receipt.publicKeySha256;keyCount=4;entriesSha256=Get-ImmuDataHash $entries}
}
try{
    $null=New-Item -ItemType Directory -Path $root
    $script:published=Publish-NativeProbe $repo 'ServerBackendProbe' $root
    . (Join-Path $repo 'eng/verify-immudb-state.ps1') -Address 'https://127.0.0.1:8090' -PublicKeyPath (Join-Path $root 'state-public.pem') -AnchorPath (Join-Path $root 'unused-anchor')
    $stage='build'
    $auditContext.ProbeHash=(Get-FileHash -LiteralPath (Join-Path $published 'ServerBackendProbe.dll')).Hash.ToLowerInvariant()
    Build-AuditDataImage $auditContext $cliImage
    $tls=New-PilotDisposableTlsMaterial -IncludeClient
    $key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    try{$script:signingPem=$key.ExportECPrivateKeyPem();[IO.File]::WriteAllText((Join-Path $root 'state-public.pem'),$key.ExportSubjectPublicKeyInfoPem(),[Text.UTF8Encoding]::new($false))}finally{$key.Dispose()}
    foreach($pem in @($tls.ServerPrivateKeyPem,$tls.ClientPrivateKeyPem,$script:signingPem)){
        foreach($line in ($pem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$canaries.Add($line.Substring(0,40))}}
    }
    $stage='stores';$source=New-Store 'source';$target=New-Store 'target'
    if($FailurePoint -ceq 'after-stores'){Write-Output 'IMMU DATA INJECTED FAILURE AFTER STORES';throw 'Intentional fresh audit failure.'}
    $stage='seed';$null=Probe $source 'immu-seed';$expected=Point $source;Assert-ImmuDataPoint $expected $expected
    $stage='capture';Owned $source
    $dump=(Invoke-Docker (Get-ImmuDataCliArguments $source.Id 'backup')).StdoutBytes
    $pin=Get-ImmuDataHash $dump;Assert-ImmuDataPacket $dump $pin
    Assert-ImmuDataPoint (Point $source) $expected
    $capture=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'generated_audit_capture.py')) $dump 30
    Assert-ImmuData ($capture.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($capture.Stderr)) 'capture-process'
    $c=$capture.Stdout|ConvertFrom-Json -AsHashtable
    Assert-ImmuData ($c.schema -ceq 'fleetory.generated-audit-capture.v1' -and $c.capturedBytesSurviveReplacement -eq $true -and
        $c.sourceReplacementRejected -eq $true -and $c.componentReportsAreSyntheticFixtures -eq $true -and $c.applicationBackupRestored -eq $false -and $c.originalInventoryV2Verified -eq $false) 'capture-scope'
    $captured=[Convert]::FromBase64String($c.backupBase64);Assert-ImmuDataPacket $captured $pin
    Assert-ImmuData ($c.backupSha256 -ceq $pin -and $c.backupBytes -eq $captured.Length -and $captured.Length -eq $dump.Length) 'captured-pin'
    $stage='native-format';Owned $target
    $null=Invoke-Docker (Get-ImmuDataCliArguments $target.Id 'verify') $captured
    $bad=$captured.Clone();$bad[30]=$bad[30] -bxor 1
    $pinRefused=$false;try{Assert-ImmuDataPacket $bad $pin}catch{$pinRefused=$true};Assert-ImmuData $pinRefused 'corrupt-pin-refusal'
    # verify-only walks framing; it is not a cryptographic transaction validator.
    $null=Invoke-Docker (Get-ImmuDataCliArguments $target.Id 'verify') $bad
    $short=[byte[]]::new(64);[Array]::Copy($captured,$short,64)
    $refused=Invoke-Docker (Get-ImmuDataCliArguments $target.Id 'verify') $short -AllowFailure
    Assert-ImmuData ($refused.ExitCode -ne 0 -and ($refused.Stderr+$refused.Stdout) -match '(?i)malformed|unexpected|EOF|corrupt') 'native-truncated-refusal'
    $stage='corrupt-restore';$corrupt=New-Store 'corrupt';Owned $corrupt
    $refused=Invoke-Docker (Get-ImmuDataCliArguments $corrupt.Id 'restore') $bad -AllowFailure
    Assert-ImmuData ($refused.ExitCode -ne 0 -and ($refused.Stderr+$refused.Stdout).Contains("transaction checksums don't match",[StringComparison]::Ordinal)) 'native-corrupt-refusal'
    $stage='restore';Owned $target;$null=Invoke-Docker (Get-ImmuDataCliArguments $target.Id 'restore') $captured
    Assert-ImmuDataPoint (Point $target) $expected
    Owned $target
    $duplicate=Invoke-Docker (Get-ImmuDataCliArguments $target.Id 'restore') $captured -AllowFailure
    Assert-ImmuData ($duplicate.ExitCode -ne 0 -and ($duplicate.Stdout+$duplicate.Stderr).Contains('cannot restore to non-empty database without --append flag',[StringComparison]::Ordinal)) 'nonempty-target-refusal'
    Assert-ImmuDataPoint (Point $target) $expected
    $null=Probe $target 'immu-reader-create';Assert-ImmuDataPoint (Point $target 'immu-reader') $expected
    $badLogin=Probe $target 'immu-wrong-password' -WrongPassword;Assert-ImmuData ($badLogin.refused -eq $true) 'wrong-password-refusal'
    $stage='signature-refusal';$snapshot=Probe $target 'immu-inspect'
    $changedSignature=[Convert]::FromBase64String($snapshot.state.signature.signature)
    $changedSignature[$changedSignature.Length-1]=$changedSignature[$changedSignature.Length-1] -bxor 1
    $snapshot.state.signature.signature=[Convert]::ToBase64String($changedSignature)
    $signatureRefused=$false;try{$null=New-ImmudbStateReceipt $snapshot.state 'fleetoryaudit' (Join-Path $root 'state-public.pem')}catch{$signatureRefused=$true}
    Assert-ImmuData $signatureRefused 'changed-state-signature'
    $stage='restart';Owned $target
    $pidText=(Invoke-Docker @('exec',$target.Id,'/bin/cat','/tmp/immudb.pid')).Stdout.Trim()
    Assert-ImmuData ($pidText -cmatch '^[1-9][0-9]{0,7}\z') 'server-pid'
    $null=Invoke-Docker @('exec',$target.Id,'/bin/kill','-TERM',$pidText)
    $stopped=$false
    for($n=0;$n -lt 40;$n++){$r=Invoke-Docker @('exec',$target.Id,'/bin/kill','-0',$pidText) -AllowFailure;if($r.ExitCode -ne 0){$stopped=$true;break};Start-Sleep -Milliseconds 200}
    Assert-ImmuData $stopped 'server-stop';Start-Server $target
    Assert-ImmuDataPoint (Point $target 'immu-reader') $expected
    Assert-ImmuDataPoint (Point $source) $expected
    $proof=[ordered]@{schema='fleetory.native-immu-data-roundtrip.v1';verified=$true;scope='fresh immudb audit-only fixture';keys=4;tx=$expected.tx;txHash=$expected.txHash;
        keyFingerprint=$expected.keyFingerprint;entriesSha256=$expected.entriesSha256;backupBytes=$captured.Length;backupSha256=$pin;
        exactKeysValuesRevisionsTransactionsVerified=$true;signedSourceTargetAndRestartVerified=$true;sourceStableAndUnchanged=$true;nativeFormatVerified=$true;nonemptyTargetRestoreRefusedWithoutChanges=$true;
        nativeCorruptionRestoreRefused=$true;verifyOnlyDoesNotValidateChecksum=$true;corruptPacketPinRefused=$true;corruptRestoreTargetDiscarded=$true;nativeTruncationRefused=$true;changedSignatureRefused=$true;targetReaderWriteRefusals=2;targetWrongPasswordRefused=$true;
        targetCredentialsRecreated=$true;sourceCredentialsRecovered=$false;restartPreservedPointAndReader=$true;capturedBytesSurvivePathReplacement=$true;
        componentReportsAreSyntheticFixtures=$true;applicationSlotIsPlaceholder=$true;applicationBackupRestored=$false;originalInventoryV2Verified=$false;
        originalInputsRead=$false;originalPkiOrProviderUsed=$false;sourceVpsAccessed=$false;serverApplicationStarted=$false;issuerActivated=$false;
        untrustedArchiveSandboxVerified=$false;sessionTokenRevocationVerified=$false;globalAtomicSnapshotClaimed=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}catch{
    if($_.Exception.Message -cmatch '^(?:Audit data|Native signer) fixture refused: ([a-z0-9-]{1,64})\z'){[Console]::Error.WriteLine('Native audit category='+$Matches[1]+'; operation='+$lastOperation+';exit='+$lastExit+'; class='+$lastClass)}
    [Console]::Error.WriteLine('Native audit roundtrip failed at '+$stage+'; type='+$_.Exception.GetType().Name+'; line='+$_.InvocationInfo.ScriptLineNumber+'. No response, packet or credential logged.')
    throw 'Native audit data roundtrip failed.'
}finally{
    $cleaning=$true;$failures=@()
    foreach($s in $auditContext.Stores){try{Remove-AuditDataStore $auditContext $s}catch{$failures+='store'}}
    if(-not $failures.Count){try{Remove-AuditDataImage $auditContext}catch{$failures+='image'}}
    if(-not $failures.Count){try{Remove-NativePublicPayload $repo $root}catch{$failures+='payload'}}
    $env:DOCKER_BUILDKIT=$previousBuildKit;$auditContext.SigningPems.Clear();$auditContext.Tls=$null;$secrets.Clear();$canaries.Clear();$tls=$script:signingPem=$dump=$captured=$capture=$c=$null;$watch.Stop()
    if($failures.Count){throw 'Native audit owned cleanup unverified; identity ledger retained.'}
    @{schema='fleetory.native-immu-cleanup.v1';fixture=$fixture;ids=@($stores|ForEach-Object {$_.Id});image=$imageName;cleanupVerified=$true;originalInputsRead=$false}|ConvertTo-Json -Compress
}
if($FailurePoint -ceq 'none'){
    $fault=Invoke-NativeBytes ([Environment]::ProcessPath) @('-NoLogo','-NoProfile','-NonInteractive','-File',$PSCommandPath,'-Python',$Python,'-FailurePoint','after-stores') -TimeoutSeconds 120
    Assert-ImmuData ($fault.ExitCode -ne 0 -and $fault.Stdout.Contains('IMMU DATA INJECTED FAILURE AFTER STORES') -and $fault.Stderr.Contains('Native audit data roundtrip failed.')) 'fault-exit'
    $records=@($fault.Stdout -split '\r?\n'|Where-Object {$_.StartsWith('{')}|ForEach-Object {$_|ConvertFrom-Json -AsHashtable}|Where-Object {$_.schema -ceq 'fleetory.native-immu-cleanup.v1'})
    Assert-ImmuData ($records.Count -eq 1 -and $records[0].cleanupVerified -eq $true -and $records[0].originalInputsRead -eq $false -and @($records[0].ids).Count -eq 2) 'fault-cleanup'
    $null=Get-ImmuDataImageName $records[0].fixture
    Assert-ImmuData ($records[0].image -ceq (Get-ImmuDataImageName $records[0].fixture)) 'fault-image-name'
    foreach($id in $records[0].ids){Assert-ImmuData ($id -cmatch '^[a-f0-9]{64}\z') 'fault-id';$r=Invoke-Docker @('inspect',$id) -AllowFailure;Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'fault-store-absence'}
    $r=Invoke-Docker @('image','inspect',$records[0].image) -AllowFailure;Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'fault-image-absence'
    Assert-ImmuData (-not (Test-Path -LiteralPath (Join-Path $repo ('artifacts/native-immu-data-'+$records[0].fixture)))) 'fault-payload-absence'
    $proof.faultCleanupVerified=$true;$proof.faultCleanupContainers=2
}
$proof.cleanupVerified=$true;$proof|ConvertTo-Json -Compress -Depth 8
$global:LASTEXITCODE=0
