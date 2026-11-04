#requires -Version 7.3
$script:nativeAuditSourceImage='codenotary/immudb:1.11.2@sha256:f2efcf6a3de73b31691e0afb8dfec972642aaf0699b93387d1ec6074aedb2953'
$script:nativeAuditTmpfs=@{'/data'='rw,noexec,nosuid,nodev,size=256m,uid=3322,gid=3322,mode=0700';'/tmp'='rw,noexec,nosuid,nodev,size=32m,uid=3322,gid=3322,mode=0700'}
function Get-NativeAuditImageName([string]$Session){
    Assert-NativeSigner ($Session -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') 'audit-build-identity'
    return ('fleetory-native-audit-'+$Session.Replace('-','')+':fixture')
}
function Get-NativeAuditBuildDefinition([string]$Session){
    $null=Get-NativeAuditImageName $Session
    return "FROM $script:nativeAuditSourceImage AS upstream`nFROM $script:nativeSignerImage`nCOPY --from=upstream /usr/sbin/immudb /usr/sbin/immudb`nLABEL fleetory.native-audit.build=$Session`nUSER 3322:3322`n"
}
function Get-NativeAuditArguments([string]$Session,[string]$DatabaseId){
    Assert-NativeSigner ($Session -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and $DatabaseId -cmatch '^[0-9a-f]{64}$') 'audit-identity'
    return @('run','-d','--rm','--name',('fleetory-native-audit-'+$Session.Replace('-','')),'--label',('fleetory.native-audit.session='+$Session),
        '--network',('container:'+$DatabaseId),'--read-only','--user','3322:3322','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--memory','384m','--cpus','1','--pids-limit','128','--ulimit','core=0','--tmpfs',('/data:'+$script:nativeAuditTmpfs['/data']),
        '--tmpfs',('/tmp:'+$script:nativeAuditTmpfs['/tmp']),'--entrypoint','/bin/sh',(Get-NativeAuditImageName $Session),'-c','exec /bin/sleep 3300')
}
function Assert-NativeAudit($Info,[string]$Id,[string]$Session,[string]$ImageId,[string]$DatabaseId,[DateTimeOffset]$NotBefore,[switch]$CleanupOnly){
    $created=ConvertTo-ProviderTimestamp $Info.Created
    Assert-NativeSigner ($Id -cmatch '^[0-9a-f]{64}$' -and $Id -cne $DatabaseId -and $Info.Id -ceq $Id -and
        $Info.Name -ceq ('/fleetory-native-audit-'+$Session.Replace('-','')) -and $Info.Config.Image -ceq (Get-NativeAuditImageName $Session) -and
        $Info.Image -ceq $ImageId -and $Info.Config.Labels['fleetory.native-audit.session'] -ceq $Session -and
        $created -ge $NotBefore -and $created -le [DateTimeOffset]::UtcNow.AddSeconds(5)) 'audit-ownership'
    if($CleanupOnly){return}
    Assert-NativeSigner ($Info.State.Running -eq $true -and $Info.HostConfig.AutoRemove -eq $true -and
        $Info.HostConfig.NetworkMode -ceq ('container:'+$DatabaseId) -and @($Info.NetworkSettings.Networks.Keys).Count -eq 0 -and
        $Info.HostConfig.ReadonlyRootfs -eq $true -and $Info.HostConfig.Privileged -eq $false -and $Info.Config.User -ceq '3322:3322' -and
        $Info.HostConfig.PublishAllPorts -eq $false -and @($Info.HostConfig.PortBindings.Keys).Count -eq 0 -and @($Info.Mounts).Count -eq 0 -and
        $Info.HostConfig.PidMode -ceq '' -and $Info.HostConfig.IpcMode -ceq 'private' -and
        ($null -eq $Info.HostConfig.CapAdd -or @($Info.HostConfig.CapAdd).Count -eq 0) -and (@($Info.HostConfig.CapDrop)-join '|') -ceq 'ALL' -and
        (@($Info.HostConfig.SecurityOpt)-join '|') -cin @('no-new-privileges','no-new-privileges:true') -and
        $Info.HostConfig.Memory -eq 402653184 -and $Info.HostConfig.NanoCpus -eq 1000000000 -and $Info.HostConfig.PidsLimit -eq 128 -and
        ($null -eq $Info.HostConfig.Binds -or @($Info.HostConfig.Binds).Count -eq 0) -and
        ($null -eq $Info.HostConfig.Devices -or @($Info.HostConfig.Devices).Count -eq 0) -and
        ($null -eq $Info.HostConfig.DeviceRequests -or @($Info.HostConfig.DeviceRequests).Count -eq 0) -and
        ($null -eq $Info.HostConfig.VolumesFrom -or @($Info.HostConfig.VolumesFrom).Count -eq 0) -and
        (@($Info.Config.Entrypoint)-join '|') -ceq '/bin/sh' -and (@($Info.Config.Cmd)-join '|') -ceq '-c|exec /bin/sleep 3300' -and
        @($Info.HostConfig.Ulimits).Count -eq 1 -and $Info.HostConfig.Ulimits[0].Name -ceq 'core' -and
        $Info.HostConfig.Ulimits[0].Soft -eq 0 -and $Info.HostConfig.Ulimits[0].Hard -eq 0) 'audit-runtime'
    Assert-NativeSigner ((@($Info.HostConfig.Tmpfs.Keys|Sort-Object)-join '|') -ceq (@($script:nativeAuditTmpfs.Keys|Sort-Object)-join '|')) 'audit-tmpfs'
    foreach($path in $script:nativeAuditTmpfs.Keys){Assert-NativeSigner ($Info.HostConfig.Tmpfs[$path] -ceq $script:nativeAuditTmpfs[$path]) 'audit-tmpfs'}
}
