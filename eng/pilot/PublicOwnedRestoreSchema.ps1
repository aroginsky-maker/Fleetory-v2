# Original live owner library. The returned SQL is public metadata, never an execution grant.
. (Join-Path $PSScriptRoot 'AuditDataResourceOwnership.ps1')
. (Join-Path $PSScriptRoot 'PilotNativeExecutableLease.ps1')
. (Join-Path $PSScriptRoot 'PilotNativeProcess.ps1')
if(-not (Get-Variable -Name publicOwnedSchemaAttempts -Scope Script -ErrorAction SilentlyContinue)){
    $script:publicOwnedSchemaAttempts=[Runtime.CompilerServices.ConditionalWeakTable[object,object]]::new()
}
function Invoke-PublicOwnedRestoreSchema([string]$Docker,[string]$DockerSha256,[string]$PrivateConfig,
    [hashtable]$ImageContext,[scriptblock]$ImageClient,[scriptblock]$ControllerAlive,[scriptblock]$Ready=$null){
    $ErrorActionPreference='Stop'
    if($null -eq $ControllerAlive -or [IO.Path]::GetFileName($Docker) -cne $(if($IsWindows){'docker.exe'}else{'docker'}) -or
        -not [IO.Path]::IsPathFullyQualified($PrivateConfig)){throw 'Original schema owner inputs refused.'}
    $image=[Fleetory.Pilot.AuditImageCustody]::Id($ImageContext,$ImageClient)
    $script:publicOwnedSchemaAttempts.Add($ImageContext,[object]::new()) # Failed attempts also consume; no reset or import.
    $clock=[Diagnostics.Stopwatch]::StartNew();$held=$null;$createdConfig=$false;$identifier=$null;$result=$null
    $store=@{Session=[guid]::NewGuid().ToString('D');Name=('fleetory-sdk-schema-'+[guid]::NewGuid().ToString('N'));Role='public-restore-schema';Started=[DateTimeOffset]::UtcNow;Id=$null}
    if(-not $ImageContext.ContainsKey('Stores')){$ImageContext.Stores=[Collections.ArrayList]::new()}
    $null=$ImageContext.Stores.Add($store)
    function Assert-SchemaOwner([switch]$Cleanup){
        if([Fleetory.Pilot.AuditImageCustody]::Id($ImageContext,$ImageClient) -cne $image){throw 'Original schema image claim changed.'}
        if(-not $Cleanup){
            $alive=@(& $ControllerAlive)
            if($alive.Count -ne 1 -or $alive[0] -isnot [bool] -or -not $alive[0] -or $clock.Elapsed.TotalSeconds -ge 75){throw 'Original schema controller unavailable or expired.'}
        }
    }
    function Schema-Native([string[]]$Arguments,[switch]$Cleanup){
        Assert-SchemaOwner -Cleanup:$Cleanup
        $endpoint=if($IsWindows){'npipe:////./pipe/dockerDesktopLinuxEngine'}else{'unix:///var/run/docker.sock'}
        $observer=if($Cleanup){$null}else{{param($Process,$Token) Assert-SchemaOwner}}
        $reply=Invoke-NativeBytes $Docker (@('--config',$PrivateConfig,'--host',$endpoint)+$Arguments) -TimeoutSeconds 15 -ObserveProcess $observer -DockerClientEnvironment -ExecutableLease $held -OutputLimit 262144
        Assert-SchemaOwner -Cleanup:$Cleanup
        return [Tuple]::Create($reply.ExitCode,$reply.StdoutBytes,$reply.StderrBytes)
    }
    try{
        Assert-SchemaOwner
        $held=[Fleetory.Pilot.NativeExecutableLease]::new($Docker,$DockerSha256)
        [Fleetory.Pilot.ExclusiveAuditDirectory]::Create($PrivateConfig);$createdConfig=$true
        $create=[Func[Tuple[int,byte[],byte[]]]]{Schema-Native @('create','--name',$store.Name,'--network=none','--read-only','--user=3322:3322','--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory=256m','--cpus=1','--pids-limit=64','--restart=no','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=67108864,uid=3322,gid=3322,mode=0700','--entrypoint=dotnet',$image,'/tool/ServerBackendProbe.dll','restore-schema')}
        $identifier=[Fleetory.Pilot.AuditContainerCustody]::Create($ImageContext,$store,$ImageClient,$create)
        if($null -ne $Ready){$null=& $Ready $identifier}
        $inspect=Schema-Native @('inspect',$identifier)
        if($inspect.Item1 -ne 0 -or $inspect.Item3.Length -ne 0){throw 'Original schema container inspection refused.'}
        $items=@([Text.Encoding]::UTF8.GetString($inspect.Item2)|ConvertFrom-Json -AsHashtable)
        if($items.Count -ne 1){throw 'Original schema container count refused.'};$v=$items[0];$h=$v.HostConfig
        if($v.Id -cne $identifier -or $v.Image -cne $image -or $v.Config.Image -cne $image -or
            $v.State.Status -cne 'created' -or $v.State.Running -or $v.State.Pid -ne 0 -or
            $v.Config.User -cne '3322:3322' -or ($v.Config.Entrypoint -join '|') -cne 'dotnet' -or
            ($v.Config.Cmd -join '|') -cne '/tool/ServerBackendProbe.dll|restore-schema' -or $h.NetworkMode -cne 'none' -or
            -not $h.ReadonlyRootfs -or $h.Privileged -or $h.AutoRemove -or $v.Mounts.Count -ne 0 -or
            $h.Memory -ne 268435456 -or $h.NanoCpus -ne 1000000000 -or $h.PidsLimit -ne 64 -or
            ($h.CapDrop -join '|') -cne 'ALL' -or ($null -ne $h.CapAdd -and @($h.CapAdd).Count -ne 0) -or
            $h.PidMode -cne '' -or $h.IpcMode -cne 'private' -or $h.UTSMode -cne '' -or
            ($null -ne $h.Binds -and @($h.Binds).Count -ne 0) -or
            ($null -ne $h.Devices -and @($h.Devices).Count -ne 0) -or
            ($null -ne $h.DeviceRequests -and @($h.DeviceRequests).Count -ne 0) -or
            ($h.SecurityOpt -join '|') -cne 'no-new-privileges:true' -or $h.RestartPolicy.Name -cne 'no' -or
            $h.Tmpfs.Count -ne 1 -or $h.Tmpfs['/tmp'] -cne 'rw,noexec,nosuid,nodev,size=67108864,uid=3322,gid=3322,mode=0700'){
            throw 'Original schema creation profile drift.'
        }
        $run=Schema-Native @('start','--attach',$identifier)
        if($run.Item1 -ne 0 -or $run.Item3.Length -ne 0 -or $run.Item2.Length -eq 0){throw 'Original native schema probe failed.'}
        $json=[Text.Json.JsonDocument]::Parse([ReadOnlyMemory[byte]]::new($run.Item2))
        try{
            $root=$json.RootElement;$keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach($property in $root.EnumerateObject()){if(-not $keys.Add($property.Name)){throw 'Duplicate schema field refused.'}}
            if((($keys|Sort-Object)-join '|') -cne 'category|databaseOpened|httpHostStarted|issuerActivated|sql' -or
                $root.GetProperty('category').GetString() -cne 'restore-schema' -or
                $root.GetProperty('databaseOpened').ValueKind -ne [Text.Json.JsonValueKind]::False -or
                $root.GetProperty('httpHostStarted').ValueKind -ne [Text.Json.JsonValueKind]::False -or
                $root.GetProperty('issuerActivated').ValueKind -ne [Text.Json.JsonValueKind]::False -or
                $root.GetProperty('sql').ValueKind -ne [Text.Json.JsonValueKind]::String){throw 'Native schema response shape refused.'}
            $sql=$root.GetProperty('sql').GetString()
            if($sql.Length -lt 1 -or $sql.Length -gt 131072){throw 'Native schema SQL bound refused.'}
            $result=@{schema='fleetory.original-owned-native-restore-schema.v1';verified=$true;sql=$sql;
                sqlSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($sql))).ToLowerInvariant();
                originalImageId=$image;originalContainerId=$identifier;databaseOpened=$false;httpHostStarted=$false;issuerActivated=$false;
                nativeDeadlineSeconds=15;targetWindowSeconds=75;hostDotnetUsed=$false;originalInputsRead=$false;phase7Complete=$false}
        }finally{$json.Dispose()}
    }finally{
        try{
            if($null -ne $identifier){
                $id=[Fleetory.Pilot.AuditContainerCustody]::Id($ImageContext,$store,$ImageClient)
                $remove=[Func[Tuple[int,byte[],byte[]]]]{Schema-Native @('rm','--force',$id) -Cleanup}
                [Fleetory.Pilot.AuditContainerCustody]::Remove($ImageContext,$store,$ImageClient,$remove)
                $absent=[Func[Tuple[int,byte[],byte[]]]]{Schema-Native @('inspect',$id) -Cleanup}
                [Fleetory.Pilot.AuditContainerCustody]::ConfirmRemoval($ImageContext,$store,$ImageClient,$absent)
            }
        }finally{
            if($createdConfig){[IO.Directory]::Delete($PrivateConfig,$false)}
            if($null -ne $held){$held.Dispose()};$clock.Stop()
        }
    }
    $result.originalContainerClaimClosed=$true;return $result
}
