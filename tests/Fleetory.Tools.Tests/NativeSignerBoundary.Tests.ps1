#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/ProviderRecoveryCredential.ps1')
. (Join-Path $PSScriptRoot 'NativeSignerFixture.ps1')
$session=[Guid]::NewGuid().ToString('D');$provider='a'*64;$worker='b'*64
$directory=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'generated-public-probe'))
$now=[DateTimeOffset]::UtcNow;$before=$now.AddSeconds(-1);$imageId='sha256:'+('c'*64)
$null=Get-NativeSignerWorkerArguments $session $provider $directory
$base=@{Id=$worker;Name=('/fleetory-native-signer-'+$session.Replace('-',''));Image=$imageId;Created=$now.ToString('O');
    Config=@{Image=$script:nativeSignerImage;User='1654:1654';Labels=@{'fleetory.native-signer.session'=$session;'fleetory.native-signer.role'='worker'};
        Entrypoint=@('/bin/sh');Cmd=@('-c','exec /bin/sleep 3300');Env=@('PATH=/bin','HOME=/tmp','SSL_CERT_FILE=/tmp/ca.pem','SSL_CERT_DIR=/tmp/empty-ca-dir')};
    State=@{Running=$true};NetworkSettings=@{Networks=@{}};
    Mounts=@(@{Type='bind';Source=$directory;Destination='/tool';RW=$false});
    HostConfig=@{NetworkMode=('container:'+$provider);AutoRemove=$true;ReadonlyRootfs=$true;Privileged=$false;PublishAllPorts=$false;
        PortBindings=@{};PidMode='';IpcMode='private';CapAdd=@();CapDrop=@('ALL');SecurityOpt=@('no-new-privileges');Memory=268435456;
        NanoCpus=500000000;PidsLimit=64;Binds=@();Devices=@();DeviceRequests=@();VolumesFrom=@();Tmpfs=@{'/tmp'=$script:nativeSignerTmpfs};
        Ulimits=@(@{Name='core';Soft=0;Hard=0})}}
Assert-NativeSignerWorker $base $worker $session $provider $directory $imageId $before @('PATH=/bin')
$refused=0
foreach($mutation in @(
    {param($x)$x.Id='a'*64},{param($x)$x.Name='/source'},{param($x)$x.Config.Labels['fleetory.native-signer.session']=[Guid]::NewGuid().ToString('D')},
    {param($x)$x.Created=[DateTimeOffset]::UtcNow.AddDays(-1).ToString('O')},
    {param($x)$x.HostConfig.NetworkMode='host'},{param($x)$x.HostConfig.NetworkMode='container:source'},
    {param($x)$x.Config.User='0'},{param($x)$x.HostConfig.AutoRemove=$false},{param($x)$x.HostConfig.ReadonlyRootfs=$false},
    {param($x)$x.HostConfig.Privileged=$true},{param($x)$x.HostConfig.PortBindings=@{'8200/tcp'=@{HostPort='8200'}}},
    {param($x)$x.HostConfig.CapAdd=@('SYS_ADMIN')},{param($x)$x.HostConfig.Memory=0},{param($x)$x.HostConfig.PidMode='host'},
    {param($x)$x.HostConfig.SecurityOpt=@()},{param($x)$x.Mounts[0].RW=$true},{param($x)$x.Mounts[0].Source='/live'},
    {param($x)$x.HostConfig.Tmpfs['/tmp']='rw,mode=0777'},{param($x)$x.HostConfig.Ulimits[0].Hard=-1},
    {param($x)$x.Config.Env+=@('BAO_TOKEN=not-permitted')},{param($x)$x.Config.Cmd=@('-c','sleep 99999')}
)){
    $copy=$base|ConvertTo-Json -Depth 12|ConvertFrom-Json -AsHashtable
    & $mutation $copy
    try{Assert-NativeSignerWorker $copy $worker $session $provider $directory $imageId $before @('PATH=/bin')}
    catch{if($_.Exception.Message -cnotmatch '^Native signer fixture refused: '){throw};$refused++;continue}
    throw 'Unsafe native signer worker accepted.'
}
if($refused -ne 21){throw 'Boundary tests did not all execute.'}
Write-Host 'NATIVE SIGNER BOUNDARY PASS: 21 unsafe runtime mutations refused; no Docker or original inputs.'
