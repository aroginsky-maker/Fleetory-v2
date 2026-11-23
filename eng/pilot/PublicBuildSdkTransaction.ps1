#requires -Version 7.3
. (Join-Path $PSScriptRoot 'PublicBuildSdkPolicy.ps1')

# Called inside the original surviving image worker. No ID/name adoption API.
function Invoke-PublicBuildSdkTransaction($NativeClient,$ImageContext,$ImageClient,
    [scriptblock]$ControllerAlive,[scriptblock]$Ready){
    $image=[Fleetory.Pilot.PublicBuildImageCustody]::Id($ImageContext,$ImageClient)
    $session=& $NativeClient.BindSdk $ImageContext $ImageClient
    $client=$NativeClient.Invoke
    $stack=@{Fixture=$ImageContext.Fixture;ImageName=$ImageContext.ImageName;ImageId=$image;
        LifetimeSeconds=300;Stores=[Collections.Generic.List[object]]::new()}
    $store=@{Id=$null;Session=$session;Name=('fleetory-public-build-'+$session.Replace('-',''));Role='public-sdk';Started=[DateTimeOffset]::UtcNow}
    $stack.Stores.Add($store)
    $id=$null;$output=$null;$clock=[Diagnostics.Stopwatch]::StartNew()
    $observed=@{State=$null;ExitCode=$null;OutputReady=$false}
    function Assert-SdkController {
        $alive=@(& $ControllerAlive)
        if($alive.Count -ne 1 -or $alive[0] -isnot [bool] -or -not $alive[0] -or $clock.Elapsed.TotalSeconds -ge 310){throw 'Public build controller unavailable or expired.'}
    }
    function Inspect-Sdk {
        $operation=[Func[Tuple[int,byte[],byte[]]]]{& $client @('inspect',$id) $null}
        $reply=[Fleetory.Pilot.AuditContainerCustody]::Inspect($stack,$store,$client,$operation)
        if($reply.Item1 -ne 0){throw 'Public SDK inspection failed.'}
        $values=@([Text.Encoding]::UTF8.GetString($reply.Item2)|ConvertFrom-Json -AsHashtable -Depth 32)
        if($values.Count -ne 1){throw 'Public SDK inspection count refused.'}
        $info=$values[0];$hostConfig=$info.HostConfig
        $observed.State=$info.State.Status;$observed.ExitCode=$info.State.ExitCode
        if($info.Id -cne $id -or $info.Image -cne $image -or $info.Name -cne ('/'+$store.Name) -or
            $info.Config.User -cne '65534:65534' -or $info.Config.WorkingDir -cne '/work' -or
            ($info.Config.Entrypoint -join '|') -cne '/usr/bin/timeout' -or
            ($info.Config.Cmd -join '|') -cne '--signal=TERM|--kill-after=5s|300s|/bin/sh|/payload/control/build.sh' -or
            $info.Config.Labels['fleetory.public-build.session'] -cne $session -or
            $info.Config.Labels['fleetory.public-build.profile'] -cne 'retained-public-offline-build.v1' -or
            $info.Config.Labels['fleetory.public-build.context'] -cne $ImageContext.SourceContextSha256 -or
            $hostConfig.NetworkMode -cne 'none' -or -not $hostConfig.ReadonlyRootfs -or $hostConfig.AutoRemove -or $hostConfig.Privileged -or
            $hostConfig.Memory -ne 2147483648 -or $hostConfig.NanoCpus -ne 2000000000 -or $hostConfig.PidsLimit -ne 128 -or
            ($hostConfig.CapDrop -join '|') -cne 'ALL' -or $hostConfig.CapAdd -or $hostConfig.Devices -or $hostConfig.DeviceRequests -or
            $hostConfig.PidMode -cne '' -or $hostConfig.IpcMode -cne 'private' -or $hostConfig.UTSMode -cne '' -or
            @($hostConfig.Ulimits).Count -ne 1 -or $hostConfig.Ulimits[0].Name -cne 'core' -or
            $hostConfig.Ulimits[0].Hard -ne 0 -or $hostConfig.Ulimits[0].Soft -ne 0 -or
            ($hostConfig.SecurityOpt -join '|') -cne 'no-new-privileges' -or $hostConfig.Binds -or
            $hostConfig.PortBindings.Count -ne 0 -or $hostConfig.Tmpfs.Count -ne 2 -or
            $hostConfig.Tmpfs['/work'] -cne 'rw,noexec,nosuid,nodev,size=1073741824,uid=65534,gid=65534,mode=0700' -or
            $hostConfig.Tmpfs['/run/fleetory-build-tmp'] -cne 'rw,noexec,nosuid,nodev,size=67108864,uid=65534,gid=65534,mode=0700' -or
            (@($info.Config.Env|Where-Object {$_ -clike 'TMPDIR=*'}) -join '|') -cne 'TMPDIR=/run/fleetory-build-tmp'){throw 'Public SDK runtime profile refused.'}
        foreach($mount in $info.Mounts){
            if($mount.Type -cne 'tmpfs' -or $mount.Destination -cnotin @('/work','/run/fleetory-build-tmp') -or $mount.Source){throw 'Public SDK unexpected mount refused.'}
        }
        return $info
    }
    try{
        Assert-SdkController
        $arguments=Get-PublicBuildSdkArguments $image $session $ImageContext.SourceContextSha256
        $create=[Func[Tuple[int,byte[],byte[]]]]{& $client $arguments $null}
        $id=[Fleetory.Pilot.AuditContainerCustody]::Create($stack,$store,$client,$create)
        $before=Inspect-Sdk
        if($before.State.Status -cne 'created' -or $before.State.Running){throw 'Public SDK not unstarted.'}
        Assert-SdkController
        $started=& $client @('start',$id) $null
        if($started.Item1 -ne 0 -or [Text.Encoding]::ASCII.GetString($started.Item2).Trim() -cne $id){throw 'Public SDK start refused.'}
        $null=& $Ready $id
        while($true){
            Assert-SdkController
            $info=Inspect-Sdk
            if($info.State.Status -ceq 'exited'){throw 'Public SDK exited before output capture.'}
            if($info.State.Status -cne 'running' -or -not $info.State.Running){throw 'Public SDK state refused.'}
            $readyState=& $client @('exec',$id,'/bin/sh','-c','test -f /work/publish.ready') $null
            if($readyState.Item1 -notin @(0,1) -or $readyState.Item2.Length -ne 0 -or $readyState.Item3.Length -ne 0){throw 'Public SDK readiness marker refused.'}
            if($readyState.Item1 -eq 0){$observed.OutputReady=$true;break}
            Start-Sleep -Milliseconds 500
        }
        Assert-SdkController
        $capture=[Func[Tuple[int,byte[],byte[]]]]{& $client @('exec',$id,'/usr/bin/tar','-C','/work/output','-cf','-','.') $null}
        $capturedController=$ControllerAlive
        $stillAlive={
            $values=@(& $capturedController)
            return ($values.Count -eq 1 -and $values[0] -is [bool] -and $values[0])
        }.GetNewClosure()
        $output=[Fleetory.Pilot.PublicSdkOutputLease]::Capture($ImageContext,$ImageClient,$stack,$store,$client,
            [Func[bool]]$stillAlive,$clock,$capture)
        Assert-SdkController
        $released=& $client @('exec',$id,'/bin/sh','-c','printf x > /work/release') $null
        if($released.Item1 -ne 0 -or $released.Item2.Length -ne 0 -or $released.Item3.Length -ne 0){throw 'Public SDK release refused.'}
        while($true){
            Assert-SdkController
            $info=Inspect-Sdk
            if($info.State.Status -ceq 'exited'){
                if($info.State.ExitCode -ne 0){throw 'Public SDK final exit refused.'}
                break
            }
            if($info.State.Status -cne 'running'){throw 'Public SDK release state refused.'}
            Start-Sleep -Milliseconds 100
        }
    }catch{
        $diagnostic=@{state=$observed.State;exitCode=$observed.ExitCode;outputReady=$observed.OutputReady;stdoutTailBase64=$null;stderrTailBase64=$null;logReadFailed=$false}
        if($null -ne $id){
            try{
                $owned=[Fleetory.Pilot.AuditContainerCustody]::Id($stack,$store,$client)
                $logs=& $client @('logs',$owned) $null
                if($logs.Item1 -ne 0){throw 'Public SDK log inspection failed.'}
                foreach($pair in @(@('stdoutTailBase64',$logs.Item2),@('stderrTailBase64',$logs.Item3))){
                    $raw=[byte[]]$pair[1];$offset=[Math]::Max(0,$raw.Length-65536)
                    $diagnostic[$pair[0]]=[Convert]::ToBase64String($raw,$offset,$raw.Length-$offset)
                }
            }catch{$diagnostic.logReadFailed=$true}
        }
        $_.Exception.Data['PublicSdkDiagnostic']=$diagnostic
        throw
    }finally{
        if($null -ne $id){
            $owned=[Fleetory.Pilot.AuditContainerCustody]::Id($stack,$store,$client)
            $remove=[Func[Tuple[int,byte[],byte[]]]]{& $client @('rm','--force',$owned) $null}
            [Fleetory.Pilot.AuditContainerCustody]::Remove($stack,$store,$client,$remove)
            $inspect=[Func[Tuple[int,byte[],byte[]]]]{& $client @('inspect',$owned) $null}
            [Fleetory.Pilot.AuditContainerCustody]::ConfirmRemoval($stack,$store,$client,$inspect)
            if(-not [Fleetory.Pilot.AuditContainerCustody]::Closed($stack,$store,$client)){throw 'Public SDK container closure refused.'}
        }
        $clock.Stop()
    }
    $output.Complete()
    return $output
}
