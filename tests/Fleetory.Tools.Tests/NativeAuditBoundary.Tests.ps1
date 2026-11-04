#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/ProviderRecoveryCredential.ps1')
. (Join-Path $PSScriptRoot 'NativeSignerFixture.ps1')
. (Join-Path $PSScriptRoot 'NativeAuditFixture.ps1')
$session=[Guid]::NewGuid().ToString('D');$id='a'*64;$database='b'*64;$imageId='sha256:'+('c'*64);$now=[DateTimeOffset]::UtcNow
$null=Get-NativeAuditArguments $session $database
$base=@{Id=$id;Name=('/fleetory-native-audit-'+$session.Replace('-',''));Image=$imageId;Created=$now.ToString('O');
    Config=@{Image=(Get-NativeAuditImageName $session);Labels=@{'fleetory.native-audit.session'=$session};User='3322:3322';Entrypoint=@('/bin/sh');Cmd=@('-c','exec /bin/sleep 3300')};
    State=@{Running=$true};NetworkSettings=@{Networks=@{}};Mounts=@();HostConfig=@{AutoRemove=$true;NetworkMode=('container:'+$database);ReadonlyRootfs=$true;Privileged=$false;PublishAllPorts=$false;PortBindings=@{};
        PidMode='';IpcMode='private';CapAdd=@();CapDrop=@('ALL');SecurityOpt=@('no-new-privileges');Memory=402653184;NanoCpus=1000000000;PidsLimit=128;
        Binds=@();Devices=@();DeviceRequests=@();VolumesFrom=@();Tmpfs=$script:nativeAuditTmpfs.Clone();Ulimits=@(@{Name='core';Soft=0;Hard=0})}}
Assert-NativeAudit $base $id $session $imageId $database $now.AddSeconds(-1)
$refused=0
foreach($mutation in @(
    {param($x)$x.Name='/source'},{param($x)$x.Id='b'*64},{param($x)$x.Config.Labels['fleetory.native-audit.session']=[Guid]::NewGuid().ToString('D')},
    {param($x)$x.Config.User='0'},{param($x)$x.HostConfig.NetworkMode='host'},{param($x)$x.HostConfig.NetworkMode='container:source'},
    {param($x)$x.HostConfig.Privileged=$true},{param($x)$x.HostConfig.ReadonlyRootfs=$false},{param($x)$x.HostConfig.AutoRemove=$false},
    {param($x)$x.HostConfig.Memory=0},{param($x)$x.Mounts=@(@{Type='bind';Source='/live';Destination='/data'})},
    {param($x)$x.HostConfig.PortBindings=@{'8090/tcp'=@{HostPort='8090'}}},{param($x)$x.HostConfig.CapAdd=@('SYS_ADMIN')},
    {param($x)$x.HostConfig.PidMode='host'},{param($x)$x.Config.Cmd=@('-c','sleep 99999')},
    {param($x)$x.HostConfig.Tmpfs['/data']='rw,mode=0777'},{param($x)$x.HostConfig.Ulimits[0].Soft=-1}
)){
    $copy=$base|ConvertTo-Json -Depth 12|ConvertFrom-Json -AsHashtable;& $mutation $copy
    try{Assert-NativeAudit $copy $id $session $imageId $database $now.AddSeconds(-1)}
    catch{if($_.Exception.Message -cnotmatch '^Native signer fixture refused: audit-'){throw};$refused++;continue}
    throw 'Unsafe native audit runtime accepted.'
}
if($refused -ne 17){throw 'Audit boundary checks incomplete.'}
Write-Host 'NATIVE AUDIT BOUNDARY PASS: 17 unsafe runtime mutations refused; no Docker or original inputs.'
