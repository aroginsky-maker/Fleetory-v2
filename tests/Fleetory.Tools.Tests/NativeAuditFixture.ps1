#requires -Version 7.3
. (Join-Path $PSScriptRoot 'NativeStoreFixture.ps1')
$script:nativeAuditSourceImage='codenotary/immudb:1.11.2@sha256:f2efcf6a3de73b31691e0afb8dfec972642aaf0699b93387d1ec6074aedb2953'
$script:nativeAuditTmpfs=@{'/data'='rw,noexec,nosuid,nodev,size=256m,uid=3322,gid=3322,mode=0700';'/tmp'='rw,noexec,nosuid,nodev,size=32m,uid=3322,gid=3322,mode=0700'}
$script:nativeAuditPairSecretsTmpfs='rw,noexec,nosuid,nodev,size=16m,uid=3322,gid=3322,mode=0700'
function Get-NativeAuditImageName([string]$Session){
    Assert-NativeSigner ($Session -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') 'audit-build-identity'
    return ('fleetory-native-audit-'+$Session.Replace('-','')+':fixture')
}
function Get-NativeAuditBuildDefinition([string]$Session){
    $null=Get-NativeAuditImageName $Session
    return "FROM $script:nativeAuditSourceImage AS upstream`nFROM $script:nativeSignerImage`nCOPY --from=upstream /usr/sbin/immudb /usr/sbin/immudb`nLABEL fleetory.native-audit.build=$Session`nUSER 3322:3322`n"
}
function Get-NativeAuditArguments([string]$Session,[string]$DatabaseId,[switch]$PairSecrets){
    Assert-NativeSigner ($Session -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and $DatabaseId -cmatch '^[0-9a-f]{64}$') 'audit-identity'
    $arguments=@('run','-d','--rm','--name',('fleetory-native-audit-'+$Session.Replace('-','')),'--label',('fleetory.native-audit.session='+$Session),
        '--network',('container:'+$DatabaseId),'--read-only','--user','3322:3322','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--memory','384m','--cpus','1','--pids-limit','128','--ulimit','core=0','--tmpfs',('/data:'+$script:nativeAuditTmpfs['/data']),
        '--tmpfs',('/tmp:'+$script:nativeAuditTmpfs['/tmp']))
    if($PairSecrets){$arguments+=@('--tmpfs',('/run/fleetory-native:'+$script:nativeAuditPairSecretsTmpfs))}
    return $arguments+@('--entrypoint','/bin/sh',(Get-NativeAuditImageName $Session),'-c','exec /bin/sleep 3300')
}
function Assert-NativeAudit($Info,[string]$Id,[string]$Session,[string]$ImageId,[string]$DatabaseId,[DateTimeOffset]$NotBefore,[switch]$CleanupOnly,[switch]$PairSecrets){
    $created=ConvertTo-ProviderTimestamp $Info.Created
    Assert-NativeSigner ($Id -cmatch '^[0-9a-f]{64}$' -and $Id -cne $DatabaseId -and $Info.Id -ceq $Id -and
        $Info.Name -ceq ('/fleetory-native-audit-'+$Session.Replace('-','')) -and $Info.Config.Image -ceq (Get-NativeAuditImageName $Session) -and
        $Info.Image -ceq $ImageId -and $Info.Config.Labels['fleetory.native-audit.session'] -ceq $Session -and
        $created -ge $NotBefore -and $created -le [DateTimeOffset]::UtcNow.AddSeconds(5)) 'audit-ownership'
    if($CleanupOnly){return}
    Assert-NativeStoreRuntime $Info '3322:3322' 'audit'
    Assert-NativeSigner ($Info.HostConfig.NetworkMode -ceq ('container:'+$DatabaseId) -and @($Info.NetworkSettings.Networks.Keys).Count -eq 0) 'audit-runtime'
    $expectedTmpfs=$script:nativeAuditTmpfs.Clone()
    if($PairSecrets){$expectedTmpfs['/run/fleetory-native']=$script:nativeAuditPairSecretsTmpfs}
    Assert-NativeSigner ((@($Info.HostConfig.Tmpfs.Keys|Sort-Object)-join '|') -ceq (@($expectedTmpfs.Keys|Sort-Object)-join '|')) 'audit-tmpfs'
    foreach($path in $expectedTmpfs.Keys){Assert-NativeSigner ($Info.HostConfig.Tmpfs[$path] -ceq $expectedTmpfs[$path]) 'audit-tmpfs'}
}
