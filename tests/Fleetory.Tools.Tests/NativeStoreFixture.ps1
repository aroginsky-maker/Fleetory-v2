#requires -Version 7.3
# Shared store constraints; ownership, namespace and tmpfs layouts stay role-specific.
function Assert-NativeStoreRuntime($Info,[string]$User,[string]$Category){
    Assert-NativeSigner ($User -cin @('999:999','3322:3322') -and $Category -cin @('journal','audit')) 'store-profile'
    Assert-NativeSigner ($Info.State.Running -eq $true -and $Info.HostConfig.AutoRemove -eq $true -and
        $Info.HostConfig.ReadonlyRootfs -eq $true -and $Info.HostConfig.Privileged -eq $false -and $Info.Config.User -ceq $User -and
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
        $Info.HostConfig.Ulimits[0].Soft -eq 0 -and $Info.HostConfig.Ulimits[0].Hard -eq 0) ($Category+'-runtime')
}
