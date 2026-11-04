#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/ProviderRecoveryCredential.ps1')
. (Join-Path $PSScriptRoot 'NativeSignerFixture.ps1')
. (Join-Path $PSScriptRoot 'NativeJournalFixture.ps1')
$session=[Guid]::NewGuid().ToString('D');$id='a'*64;$imageId='sha256:'+('b'*64);$now=[DateTimeOffset]::UtcNow
$null=Get-NativeJournalArguments $session
$base=@{Id=$id;Name=('/fleetory-native-journal-'+$session.Replace('-',''));Image=$imageId;Created=$now.ToString('O');
    Config=@{Image=$script:nativeJournalImage;Labels=@{'fleetory.native-journal.session'=$session};User='999:999';Entrypoint=@('/bin/sh');Cmd=@('-c','exec /bin/sleep 3300')};
    State=@{Running=$true};Mounts=@();HostConfig=@{AutoRemove=$true;NetworkMode='none';ReadonlyRootfs=$true;Privileged=$false;PublishAllPorts=$false;PortBindings=@{};
        PidMode='';IpcMode='private';CapAdd=@();CapDrop=@('ALL');SecurityOpt=@('no-new-privileges');Memory=402653184;NanoCpus=1000000000;PidsLimit=128;
        Binds=@();Devices=@();DeviceRequests=@();VolumesFrom=@();Tmpfs=$script:nativeJournalTmpfs.Clone();Ulimits=@(@{Name='core';Soft=0;Hard=0})}}
Assert-NativeJournal $base $id $session $imageId $now.AddSeconds(-1)
$refused=0
foreach($mutation in @(
    {param($x)$x.Name='/source'},{param($x)$x.Id='c'*64},{param($x)$x.Config.Labels['fleetory.native-journal.session']=[Guid]::NewGuid().ToString('D')},
    {param($x)$x.Config.User='0'},{param($x)$x.HostConfig.NetworkMode='host'},{param($x)$x.HostConfig.Privileged=$true},
    {param($x)$x.HostConfig.ReadonlyRootfs=$false},{param($x)$x.HostConfig.AutoRemove=$false},{param($x)$x.HostConfig.Memory=0},
    {param($x)$x.Mounts=@(@{Type='bind';Source='/live';Destination='/var/lib/postgresql'})},
    {param($x)$x.HostConfig.PortBindings=@{'5432/tcp'=@{HostPort='5432'}}},{param($x)$x.HostConfig.CapAdd=@('SYS_ADMIN')},
    {param($x)$x.HostConfig.PidMode='host'},{param($x)$x.Config.Cmd=@('-c','sleep 99999')},
    {param($x)$x.HostConfig.Tmpfs['/tmp']='rw,mode=0777'},{param($x)$x.HostConfig.Ulimits[0].Soft=-1}
)){
    $copy=$base|ConvertTo-Json -Depth 12|ConvertFrom-Json -AsHashtable;& $mutation $copy
    try{Assert-NativeJournal $copy $id $session $imageId $now.AddSeconds(-1)}
    catch{if($_.Exception.Message -cnotmatch '^Native signer fixture refused: journal-'){throw};$refused++;continue}
    throw 'Unsafe native journal runtime accepted.'
}
if($refused -ne 16){throw 'Journal boundary checks incomplete.'}
Write-Host 'NATIVE JOURNAL BOUNDARY PASS: 16 unsafe runtime mutations refused; no Docker or original inputs.'
