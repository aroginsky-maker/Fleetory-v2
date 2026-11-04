#requires -Version 7.3
$script:nativeSignerImage='mcr.microsoft.com/dotnet/aspnet:10.0@sha256:de0ee358cdd672f7017a003bed21e9ac9ed48a27c922a59b18175b6e82fa7fee'
$script:nativeSignerTmpfs='rw,noexec,nosuid,nodev,size=32m,uid=1654,gid=1654,mode=0700'
function Assert-NativeSigner([bool]$Condition,[string]$Category) {
    if(-not $Condition){throw ('Native signer fixture refused: '+$Category)}
}
function Get-NativeSignerWorkerArguments([string]$Session,[string]$ProviderId,[string]$PublicDirectory) {
    Assert-NativeSigner ($Session -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and
        $ProviderId -cmatch '^[0-9a-f]{64}$' -and [IO.Path]::IsPathFullyQualified($PublicDirectory) -and
        $PublicDirectory -notmatch '[,\x00-\x1f]') 'identity'
    return @('run','-d','--rm','--name',('fleetory-native-signer-'+$Session.Replace('-','')),
        '--label',('fleetory.native-signer.session='+$Session),'--label','fleetory.native-signer.role=worker',
        '--network',('container:'+$ProviderId),'--user','1654:1654','--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--memory','256m','--cpus','0.5','--pids-limit','64',
        '--ulimit','core=0','--tmpfs',('/tmp:'+$script:nativeSignerTmpfs),
        '--tmpfs',('/run/fleetory-native:'+$script:nativeSignerTmpfs),
        '--mount',('type=bind,src='+$PublicDirectory+',dst=/tool,readonly'),
        '-e','HOME=/tmp','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',
        '--entrypoint','/bin/sh',$script:nativeSignerImage,'-c','exec /bin/sleep 3300')
}
function Assert-NativeSignerWorker($Info,[string]$Id,[string]$Session,[string]$ProviderId,[string]$PublicDirectory,
    [string]$ImageId,[DateTimeOffset]$NotBefore,[string[]]$BaseEnvironment,[switch]$CleanupOnly) {
    $created=ConvertTo-ProviderTimestamp $Info.Created
    Assert-NativeSigner ($Id -cmatch '^[0-9a-f]{64}$' -and $Id -cne $ProviderId -and $Info.Id -ceq $Id -and
        $Info.Name -ceq ('/fleetory-native-signer-'+$Session.Replace('-','')) -and
        $Info.Config.Image -ceq $script:nativeSignerImage -and $Info.Image -ceq $ImageId -and
        $Info.Config.Labels['fleetory.native-signer.session'] -ceq $Session -and
        $Info.Config.Labels['fleetory.native-signer.role'] -ceq 'worker' -and $created -ge $NotBefore -and
        $created -le [DateTimeOffset]::UtcNow.AddSeconds(5)) 'ownership'
    if($CleanupOnly){return}
    $expectedEnv=@($BaseEnvironment|Where-Object {($_ -split '=',2)[0] -cnotin @('HOME','SSL_CERT_FILE','SSL_CERT_DIR')})+
        @('HOME=/tmp','SSL_CERT_FILE=/tmp/ca.pem','SSL_CERT_DIR=/tmp/empty-ca-dir')
    Assert-NativeSigner ($Info.State.Running -eq $true -and $Info.HostConfig.NetworkMode -ceq ('container:'+$ProviderId) -and
        $Info.HostConfig.AutoRemove -eq $true -and $Info.HostConfig.ReadonlyRootfs -eq $true -and $Info.Config.User -ceq '1654:1654' -and
        $Info.HostConfig.Privileged -eq $false -and $Info.HostConfig.PublishAllPorts -eq $false -and
        @($Info.HostConfig.PortBindings.Keys).Count -eq 0 -and @($Info.NetworkSettings.Networks.Keys).Count -eq 0 -and
        $Info.HostConfig.PidMode -ceq '' -and $Info.HostConfig.IpcMode -ceq 'private' -and
        ($null -eq $Info.HostConfig.CapAdd -or @($Info.HostConfig.CapAdd).Count -eq 0) -and (@($Info.HostConfig.CapDrop)-join '|') -ceq 'ALL' -and
        (@($Info.HostConfig.SecurityOpt)-join '|') -cin @('no-new-privileges','no-new-privileges:true') -and
        $Info.HostConfig.Memory -eq 268435456 -and $Info.HostConfig.NanoCpus -eq 500000000 -and $Info.HostConfig.PidsLimit -eq 64 -and
        ($null -eq $Info.HostConfig.Binds -or @($Info.HostConfig.Binds).Count -eq 0) -and
        ($null -eq $Info.HostConfig.Devices -or @($Info.HostConfig.Devices).Count -eq 0) -and
        ($null -eq $Info.HostConfig.DeviceRequests -or @($Info.HostConfig.DeviceRequests).Count -eq 0) -and
        ($null -eq $Info.HostConfig.VolumesFrom -or @($Info.HostConfig.VolumesFrom).Count -eq 0) -and
        (@($Info.Config.Entrypoint)-join '|') -ceq '/bin/sh' -and (@($Info.Config.Cmd)-join '|') -ceq '-c|exec /bin/sleep 3300' -and
        (@($Info.Config.Env|Sort-Object)-join '|') -ceq (@($expectedEnv|Sort-Object)-join '|')) 'runtime'
    Assert-NativeSigner (@($Info.HostConfig.Tmpfs.Keys).Count -eq 2 -and
        $Info.HostConfig.Tmpfs['/tmp'] -ceq $script:nativeSignerTmpfs -and
        $Info.HostConfig.Tmpfs['/run/fleetory-native'] -ceq $script:nativeSignerTmpfs -and
        @($Info.HostConfig.Ulimits).Count -eq 1 -and $Info.HostConfig.Ulimits[0].Name -ceq 'core' -and
        $Info.HostConfig.Ulimits[0].Soft -eq 0 -and $Info.HostConfig.Ulimits[0].Hard -eq 0) 'ephemeral'
    Assert-NativeSigner (@($Info.Mounts).Count -eq 1 -and $Info.Mounts[0].Type -ceq 'bind' -and
        $Info.Mounts[0].Destination -ceq '/tool' -and $Info.Mounts[0].RW -eq $false -and
        $Info.Mounts[0].Source -ceq $PublicDirectory) 'public-code-mount'
}
