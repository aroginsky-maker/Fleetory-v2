#requires -Version 7.3
param([string]$Python='',[ValidateSet('none','after-stores')][string]$FailurePoint='none')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'ImmuDataRoundtripPolicy.Tests.ps1')
foreach($helper in @('PilotNativeProcess.ps1','../../eng/pilot/ProviderRecoveryTransport.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1','PilotDisposableTls.ps1','NativeSignerFixture.ps1','NativeAuditFixture.ps1','NativeWorkerRuntime.ps1')){. (Join-Path $PSScriptRoot $helper)}
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$fixture=[Guid]::NewGuid().ToString('D');$root=Join-Path $repo ('artifacts/native-immu-data-'+$fixture)
$cliImage='codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'
$imageName=Get-ImmuDataImageName $fixture;$imageId=$null;$imageClaimed=$false;$stores=@();$stage='publish';$proof=$null;$cleaning=$false
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
function Ledger{[IO.File]::WriteAllText((Join-Path $root 'owned-stores.json'),(@{fixture=$fixture;image=$imageName;imageId=$imageId;stage=$stage;stores=$stores}|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))}
function Owned($s,[switch]$Cleanup){
    $items=@((Invoke-Docker @('inspect',$s.Id)).Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-ImmuData ($items.Count -eq 1) 'store-inspect';$i=$items[0];$created=ConvertTo-ProviderTimestamp $i.Created
    Assert-ImmuData ($s.Id -cmatch '^[a-f0-9]{64}\z' -and $i.Id -ceq $s.Id -and $i.Name -ceq ('/'+$s.Name) -and
        $i.Config.Image -ceq $imageName -and $i.Image -ceq $imageId -and $i.Config.Labels['fleetory.immu-data.session'] -ceq $s.Session -and
        $created -ge $s.Started -and $created -le [DateTimeOffset]::UtcNow.AddSeconds(5)) 'store-ownership'
    if($Cleanup){return}
    Assert-NativeStoreRuntime $i '3322:3322' 'audit'
    Assert-ImmuData ($i.HostConfig.NetworkMode -ceq 'none' -and
        (@($i.HostConfig.Tmpfs.Keys|Sort-Object)-join '|') -ceq (@($script:nativeAuditTmpfs.Keys|Sort-Object)-join '|')) 'store-network-tmpfs'
    foreach($path in $script:nativeAuditTmpfs.Keys){Assert-ImmuData ($i.HostConfig.Tmpfs[$path] -ceq $script:nativeAuditTmpfs[$path]) 'store-tmpfs'}
}
function Slot($s,[string]$Path,[string]$Value){
    Assert-ImmuData ($Path -cin @('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/client.crt','/tmp/client.key','/tmp/state.key','/tmp/immudb.toml','/tmp/cli.toml')) 'slot'
    Owned $s
    $null=Invoke-Docker @('exec','-i',$s.Id,'/bin/sh','-c','umask 077; cat > "$1"','fixture',$Path) ([Text.Encoding]::UTF8.GetBytes($Value))
    Assert-ImmuData ((Invoke-Docker @('exec',$s.Id,'stat','-c','%a:%u:%h',$Path)).Stdout.Trim() -ceq '600:3322:1') 'slot-permissions'
}
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
function Start-Server($s){
    Owned $s
    $null=Invoke-Docker @('exec','-d','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',$s.Id,'/usr/sbin/immudb','--config=/tmp/immudb.toml','--dir=/data','--address=127.0.0.1','--port=3322',
        '--auth=true','--devmode=false','--web-server=true','--web-server-port=8090','--pgsql-server=false','--metrics-server=false',
        '--certificate=/tmp/server.crt','--pkey=/tmp/server.key','--clientcas=/tmp/ca.pem','--signingKey=/tmp/state.key',
        '--pidfile=/tmp/immudb.pid','--logdir=/tmp','--logfile=fixture.log','--max-active-databases=3')
    $ready=$false
    for($n=0;$n -lt 20;$n++){try{$null=Probe $s 'audit-health';$ready=$true;break}catch{Start-Sleep -Milliseconds 200}}
    Assert-ImmuData $ready 'server-ready'
}
function New-Store([string]$Role){
    $session=[Guid]::NewGuid().ToString('D');$name='fleetory-immu-store-'+$session.Replace('-','')
    $absent=Invoke-Docker @('inspect',$name) -AllowFailure
    Assert-ImmuData ($absent.ExitCode -ne 0 -and ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|container)') 'fresh-name'
    $s=@{Id=$null;Session=$session;Name=$name;Started=[DateTimeOffset]::UtcNow;Role=$Role};$script:stores+=,$s;Ledger
    $storeArguments=@('run','-d','--rm','--name',$name,'--label',('fleetory.immu-data.session='+$session),'--network','none','--read-only','--user','3322:3322',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','384m','--cpus','1','--pids-limit','128','--ulimit','core=0',
        '--tmpfs',('/data:'+$script:nativeAuditTmpfs['/data']),'--tmpfs',('/tmp:'+$script:nativeAuditTmpfs['/tmp']),
        '--entrypoint','/bin/sh',$imageName,'-c','exec /bin/sleep 3300')
    $s.Id=(Invoke-Docker $storeArguments).Stdout.Trim();Ledger;Owned $s
    $null=Invoke-Docker @('exec',$s.Id,'/bin/mkdir','-m','700','/tmp/empty-ca-dir')
    foreach($entry in @(@('/tmp/ca.pem',$tls.RootCertificatePem),@('/tmp/server.crt',$tls.ServerCertificatePem),@('/tmp/server.key',$tls.ServerPrivateKeyPem),
        @('/tmp/client.crt',$tls.ClientCertificatePem),@('/tmp/client.key',$tls.ClientPrivateKeyPem),@('/tmp/state.key',$script:signingPem))){Slot $s $entry[0] $entry[1]}
    Slot $s '/tmp/immudb.toml' ('admin-password = "'+$secrets[$Role+'-admin']+'"'+"`n")
    Slot $s '/tmp/cli.toml' "# Fixed generated fixture profile. No ambient config.`n"
    Start-Server $s
    $script:stage=$Role+'-cli-login'
    # Upstream's nonterminal password reader consumes stdin verbatim, including LF.
    $login=Invoke-Docker (Get-ImmuDataCliArguments $s.Id 'login') ([Text.Encoding]::UTF8.GetBytes($secrets[$Role+'-admin'])) -AllowFailure
    Assert-ImmuData ($login.ExitCode -eq 0) 'cli-login-exit'
    Assert-ImmuData ($login.Stdout -match 'logged in') 'cli-login'
    return $s
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
    foreach($image in @($cliImage,$script:nativeAuditSourceImage,$script:nativeSignerImage)){
        $r=Invoke-Docker @('image','inspect',$image) -AllowFailure
        if($r.ExitCode -ne 0){$null=Invoke-Docker @('pull',$image) -TimeoutSeconds 120}
    }
    $r=Invoke-Docker @('image','inspect',$imageName) -AllowFailure
    Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'fresh-image'
    $imageClaimed=$true
    $dockerfile="FROM $($script:nativeAuditSourceImage) AS upstream`nFROM $cliImage AS cli`nFROM $($script:nativeSignerImage)`nCOPY --from=upstream /usr/sbin/immudb /usr/sbin/immudb`nCOPY --from=cli /usr/local/bin/immuadmin /usr/local/bin/immuadmin`nCOPY publish/ /tool/`nLABEL fleetory.immu-data.build=$fixture`nUSER 3322:3322`n"
    [IO.File]::WriteAllText((Join-Path $root 'Dockerfile'),$dockerfile,[Text.UTF8Encoding]::new($false))
    $archive=Invoke-NativeBytes 'tar' @('-cf','-','-C',$root,'Dockerfile','publish') -TimeoutSeconds 60
    Assert-ImmuData ($archive.ExitCode -eq 0 -and $archive.StdoutBytes.Length -gt 0 -and $archive.StdoutBytes.Length -le 16777216) 'public-code-archive'
    $null=Invoke-Docker @('build','--network','none','--pull=false','--tag',$imageName,'-') $archive.StdoutBytes -TimeoutSeconds 120
    $archive=$null
    $built=@((Invoke-Docker @('image','inspect',$imageName)).Stdout|ConvertFrom-Json -AsHashtable)
    Assert-ImmuData ($built.Count -eq 1 -and $built[0].Config.Labels['fleetory.immu-data.build'] -ceq $fixture) 'build-identity';$imageId=$built[0].Id
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
    foreach($s in $stores){try{
        $lookup=if($s.Id){$s.Id}else{$s.Name};$r=Invoke-Docker @('inspect',$lookup) -AllowFailure
        if($r.ExitCode -eq 0){if(-not $s.Id){$s.Id=@($r.Stdout|ConvertFrom-Json -AsHashtable)[0].Id};Owned $s -Cleanup;$null=Invoke-Docker @('rm','-f','-v',$s.Id);$r=Invoke-Docker @('inspect',$s.Id) -AllowFailure}
        Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'cleanup-absence'
    }catch{$failures+='store'}}
    if(-not $failures.Count -and $imageClaimed){try{
        $r=Invoke-Docker @('image','inspect',$imageName) -AllowFailure
        if($r.ExitCode -eq 0){$i=@($r.Stdout|ConvertFrom-Json -AsHashtable);Assert-ImmuData ($i.Count -eq 1 -and $i[0].Config.Labels['fleetory.immu-data.build'] -ceq $fixture -and ($null -eq $imageId -or $i[0].Id -ceq $imageId)) 'cleanup-image-owner';$null=Invoke-Docker @('image','rm',$imageName);$r=Invoke-Docker @('image','inspect',$imageName) -AllowFailure}
        Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'cleanup-image-absence'
    }catch{$failures+='image'}}
    if(-not $failures.Count){try{Remove-NativePublicPayload $repo $root}catch{$failures+='payload'}}
    $env:DOCKER_BUILDKIT=$previousBuildKit;$secrets.Clear();$canaries.Clear();$tls=$script:signingPem=$dump=$captured=$capture=$c=$null;$watch.Stop()
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
