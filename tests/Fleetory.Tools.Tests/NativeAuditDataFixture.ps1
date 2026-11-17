#requires -Version 7.3
# Shared fresh owned audit resources; caller owns bounded Invoke-Docker and health probe.
. (Join-Path $PSScriptRoot '../../eng/pilot/AuditDataResourceOwnership.ps1')
function Get-AuditDataLifetime($Context){
    $value=if($Context.ContainsKey('LifetimeSeconds')){$Context.LifetimeSeconds}else{3300}
    Assert-ImmuData ($value -is [int] -and $value -cin @(3300,660)) 'store-lifetime'
    return $value
}
function New-AuditDataNativeCall([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=60){
    $client=${function:Invoke-Docker}
    $operation=[Func[Tuple[int,byte[],byte[]]]]{
        $reply=& $client $Arguments $InputBytes $TimeoutSeconds -AllowFailure
        return [Tuple[int,byte[],byte[]]]::new($reply.ExitCode,$reply.StdoutBytes,$reply.StderrBytes)
    }.GetNewClosure()
    return @{Client=$client;Invoke=$operation}
}
function Invoke-AuditDataContainerOperation($Context,$Store,[ValidateSet('Create','Inspect','Remove','ConfirmRemoval')][string]$Mode,[string[]]$Arguments){
    $native=New-AuditDataNativeCall $Arguments
    switch -CaseSensitive ($Mode){
        'Create' {return [Fleetory.Pilot.AuditContainerCustody]::Create($Context,$Store,$native.Client,$native.Invoke)}
        'Inspect' {
            $reply=[Fleetory.Pilot.AuditContainerCustody]::Inspect($Context,$Store,$native.Client,$native.Invoke)
            return @{ExitCode=$reply.Item1;Stdout=[Text.Encoding]::UTF8.GetString($reply.Item2);Stderr=[Text.Encoding]::UTF8.GetString($reply.Item3)}
        }
        'Remove' {[Fleetory.Pilot.AuditContainerCustody]::Remove($Context,$Store,$native.Client,$native.Invoke)}
        'ConfirmRemoval' {[Fleetory.Pilot.AuditContainerCustody]::ConfirmRemoval($Context,$Store,$native.Client,$native.Invoke)}
    }
}
function Read-AuditDataStore($Context,$Store,[switch]$Cleanup){
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($Context,$Store,${function:Invoke-Docker})
    $reply=Invoke-AuditDataContainerOperation $Context $Store 'Inspect' @('inspect',$id)
    Assert-ImmuData ($reply.ExitCode -eq 0) 'store-inspect-exit'
    $items=@($reply.Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-ImmuData ($items.Count -eq 1) 'store-inspect';$i=$items[0];$created=ConvertTo-ProviderTimestamp $i.Created
    Assert-ImmuData ($Store.Id -cmatch '^[a-f0-9]{64}\z' -and $i.Id -ceq $Store.Id -and $i.Name -ceq ('/'+$Store.Name) -and
        $i.Config.Image -ceq $Context.ImageId -and $i.Image -ceq $Context.ImageId -and $i.Config.Labels['fleetory.immu-data.session'] -ceq $Store.Session -and
        $created -ge $Store.Started -and $created -le [DateTimeOffset]::UtcNow.AddSeconds(5)) 'store-ownership'
    if($Cleanup){return}
    Assert-NativeStoreRuntime $i '3322:3322' 'audit' (Get-AuditDataLifetime $Context)
    Assert-ImmuData ($i.HostConfig.NetworkMode -ceq 'none' -and (@($i.HostConfig.Tmpfs.Keys|Sort-Object)-join '|') -ceq (@($script:nativeAuditTmpfs.Keys|Sort-Object)-join '|')) 'store-network-tmpfs'
    foreach($path in $script:nativeAuditTmpfs.Keys){Assert-ImmuData ($i.HostConfig.Tmpfs[$path] -ceq $script:nativeAuditTmpfs[$path]) 'store-tmpfs'}
}
function Write-AuditDataSlot($Context,$Store,[string]$Path,[string]$Value){
    Assert-ImmuData ($Path -cin @('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/client.crt','/tmp/client.key','/tmp/state.key','/tmp/immudb.toml','/tmp/cli.toml') -and $Value.Length -gt 0 -and $Value.Length -le 16384) 'slot'
    Read-AuditDataStore $Context $Store
    $null=Invoke-Docker @('exec','-i',$Store.Id,'/bin/sh','-c','umask 077; cat > "$1"','fixture',$Path) ([Text.Encoding]::UTF8.GetBytes($Value))
    Assert-ImmuData ((Invoke-Docker @('exec',$Store.Id,'stat','-c','%a:%u:%h',$Path)).Stdout.Trim() -ceq '600:3322:1') 'slot-permissions'
}
function Start-AuditDataServer($Context,$Store){
    Read-AuditDataStore $Context $Store
    $null=Invoke-Docker @('exec','-d','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',$Store.Id,'/usr/sbin/immudb','--config=/tmp/immudb.toml','--dir=/data','--address=127.0.0.1','--port=3322',
        '--auth=true','--devmode=false','--web-server=true','--web-server-port=8090','--pgsql-server=false','--metrics-server=false',
        '--certificate=/tmp/server.crt','--pkey=/tmp/server.key','--clientcas=/tmp/ca.pem','--signingKey=/tmp/state.key',
        '--pidfile=/tmp/immudb.pid','--logdir=/tmp','--logfile=fixture.log','--max-active-databases=3')
    $ready=$false
    for($n=0;$n -lt 20;$n++){try{Invoke-AuditDataHealth $Store;$ready=$true;break}catch{Start-Sleep -Milliseconds 200}}
    Assert-ImmuData $ready 'server-ready'
}
function New-AuditDataStore($Context,[string]$Role){
    Assert-ImmuData ($Role -cin @('source','target','corrupt') -and $Context.SigningPems.ContainsKey($Role)) 'generated-store-role'
    $imageId=[Fleetory.Pilot.AuditImageCustody]::Id($Context,${function:Invoke-Docker})
    $session=[Guid]::NewGuid().ToString('D');$name='fleetory-immu-store-'+$session.Replace('-','')
    $absent=Invoke-Docker @('inspect',$name) -AllowFailure
    Assert-ImmuData ($absent.ExitCode -ne 0 -and ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|container)') 'fresh-name'
    $s=@{Id=$null;Session=$session;Name=$name;Started=[DateTimeOffset]::UtcNow;Role=$Role};$Context.Stores.Add($s);Write-AuditDataLedger $Context
    $arguments=@('run','-d','--rm','--name',$name,'--label',('fleetory.immu-data.session='+$session),'--network','none','--read-only','--user','3322:3322',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','384m','--cpus','1','--pids-limit','128','--ulimit','core=0',
        '--tmpfs',('/data:'+$script:nativeAuditTmpfs['/data']),'--tmpfs',('/tmp:'+$script:nativeAuditTmpfs['/tmp']),
        '--entrypoint','/bin/sh',$imageId,'-c',('exec /bin/sleep '+(Get-AuditDataLifetime $Context)))
    $null=Invoke-AuditDataContainerOperation $Context $s 'Create' $arguments
    Write-AuditDataLedger $Context;Read-AuditDataStore $Context $s
    Assert-ImmuData ((Invoke-Docker @('exec',$s.Id,'sha256sum','/tool/ServerBackendProbe.dll')).Stdout.Split(' ')[0] -ceq $Context.ProbeHash) 'probe-code-identity'
    if($Context.ContainsKey('ProbeBundle')){Assert-HistoricalProbeContainerBundle $Context $s}
    $null=Invoke-Docker @('exec',$s.Id,'/bin/mkdir','-m','700','/tmp/empty-ca-dir')
    foreach($entry in @(@('/tmp/ca.pem',$Context.Tls.RootCertificatePem),@('/tmp/server.crt',$Context.Tls.ServerCertificatePem),@('/tmp/server.key',$Context.Tls.ServerPrivateKeyPem),
        @('/tmp/client.crt',$Context.Tls.ClientCertificatePem),@('/tmp/client.key',$Context.Tls.ClientPrivateKeyPem),@('/tmp/state.key',$Context.SigningPems[$Role]))){Write-AuditDataSlot $Context $s $entry[0] $entry[1]}
    Write-AuditDataSlot $Context $s '/tmp/immudb.toml' ('admin-password = "'+$Context.Secrets[$Role+'-admin']+'"'+"`n")
    Write-AuditDataSlot $Context $s '/tmp/cli.toml' "# Fixed generated fixture profile. No ambient config.`n"
    Start-AuditDataServer $Context $s
    $login=Invoke-Docker (Get-ImmuDataCliArguments $s.Id 'login') ([Text.Encoding]::UTF8.GetBytes($Context.Secrets[$Role+'-admin'])) -AllowFailure
    Assert-ImmuData ($login.ExitCode -eq 0 -and $login.Stdout -match 'logged in') 'cli-login'
    return $s
}
function Test-AuditDataStoreClosed($Context,$Store){
    # Read-only live state; an unknown result or imported record cannot become closed.
    return [Fleetory.Pilot.AuditContainerCustody]::Closed($Context,$Store,${function:Invoke-Docker})
}
function Remove-AuditDataStore($Context,$Store){
    # An unknown create stays unknown. Never inspect by name or adopt an ID from metadata.
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($Context,$Store,${function:Invoke-Docker})
    $r=Invoke-AuditDataContainerOperation $Context $Store 'Inspect' @('inspect',$id)
    if($r.ExitCode -ne 0){
        [Fleetory.Pilot.AuditContainerCustody]::Absent($Context,$Store,${function:Invoke-Docker})
        return
    }
    Read-AuditDataStore $Context $Store -Cleanup
    Invoke-AuditDataContainerOperation $Context $Store 'Remove' @('rm','-f','-v',$id)
    Invoke-AuditDataContainerOperation $Context $Store 'ConfirmRemoval' @('inspect',$id)
}
function Invoke-AuditDataImageOperation($Context,[ValidateSet('Build','Inspect','Remove','ConfirmRemoval')][string]$Mode,[string[]]$Arguments,[byte[]]$InputBytes=$null){
    $native=New-AuditDataNativeCall $Arguments $InputBytes $(if($Mode -ceq 'Build'){120}else{60})
    switch -CaseSensitive ($Mode){
        'Build' {return [Fleetory.Pilot.AuditImageCustody]::Build($Context,$native.Client,$InputBytes,$native.Invoke)}
        'Inspect' {
            $reply=[Fleetory.Pilot.AuditImageCustody]::Inspect($Context,$native.Client,$native.Invoke)
            return @{ExitCode=$reply.Item1;Stdout=[Text.Encoding]::UTF8.GetString($reply.Item2);Stderr=[Text.Encoding]::UTF8.GetString($reply.Item3)}
        }
        'Remove' {[Fleetory.Pilot.AuditImageCustody]::Remove($Context,$native.Client,$native.Invoke)}
        'ConfirmRemoval' {[Fleetory.Pilot.AuditImageCustody]::ConfirmRemoval($Context,$native.Client,$native.Invoke)}
    }
}
function Read-AuditDataImage($Context){
    $client=${function:Invoke-Docker}
    $id=[Fleetory.Pilot.AuditImageCustody]::Id($Context,$client)
    $r=Invoke-AuditDataImageOperation $Context 'Inspect' @('image','inspect',$id)
    Assert-ImmuData ($r.ExitCode -eq 0) 'image-inspect-exit'
    $items=@($r.Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-ImmuData ($items.Count -eq 1) 'image-inspect-count';$i=$items[0]
    $created=ConvertTo-ProviderTimestamp $i.Created
    Assert-ImmuData ($i.Id -ceq $id -and $i.Config.Labels['fleetory.immu-data.build'] -ceq $Context.Fixture -and
        $i.Config.User -ceq '3322:3322' -and $created -ge [Fleetory.Pilot.AuditImageCustody]::Started($Context,$client) -and
        $created -le [DateTimeOffset]::UtcNow.AddSeconds(5) -and $i.RootFS.Type -ceq 'layers' -and
        @($i.RootFS.Layers).Count -ge 1 -and @($i.RootFS.Layers).Count -le 128) 'image-own-profile'
    # A logical namespace name is not an image reference. The build is untagged.
    Assert-ImmuData ($i.ContainsKey('RepoTags') -and $i.ContainsKey('RepoDigests') -and
        ($null -eq $i.RepoTags -or @($i.RepoTags).Count -eq 0) -and
        ($null -eq $i.RepoDigests -or @($i.RepoDigests).Count -eq 0)) 'image-no-references'
}
function Test-AuditDataImageClosed($Context){
    return [Fleetory.Pilot.AuditImageCustody]::Closed($Context,${function:Invoke-Docker})
}

function Build-AuditDataImage($Context,[string]$CliImage){
    Assert-ImmuData ($CliImage -ceq 'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd') 'fixed-cli-image'
    foreach($image in @($CliImage,$script:nativeAuditSourceImage,$script:nativeSignerImage)){
        $r=Invoke-Docker @('image','inspect',$image) -AllowFailure
        if($r.ExitCode -ne 0){$null=Invoke-Docker @('pull',$image) -TimeoutSeconds 120}
    }
    $r=Invoke-Docker @('image','inspect',$Context.ImageName) -AllowFailure
    Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'fresh-image'
    $definition="FROM $($script:nativeAuditSourceImage) AS upstream`nFROM $CliImage AS cli`nFROM $($script:nativeSignerImage)`nCOPY --from=upstream /usr/sbin/immudb /usr/sbin/immudb`nCOPY --from=cli /usr/local/bin/immuadmin /usr/local/bin/immuadmin`nCOPY publish/ /tool/`nLABEL fleetory.immu-data.build=$($Context.Fixture)`nUSER 3322:3322`n"
    [IO.File]::WriteAllText((Join-Path $Context.Root 'Dockerfile'),$definition,[Text.UTF8Encoding]::new($false))
    $archive=Invoke-NativeBytes 'tar' @('-cf','-','-C',$Context.Root,'Dockerfile','publish') -TimeoutSeconds 60
    Assert-ImmuData ($archive.ExitCode -eq 0 -and $archive.StdoutBytes.Length -gt 0 -and $archive.StdoutBytes.Length -le 16777216) 'public-code-archive'
    $null=Invoke-AuditDataImageOperation $Context 'Build' @('build','--quiet','--network','none','--pull=false','-') $archive.StdoutBytes
    Read-AuditDataImage $Context
}
function Remove-AuditDataImage($Context){
    if(-not [Fleetory.Pilot.AuditImageCustody]::Attempted($Context)){
        Assert-ImmuData ($Context.ImageClaimed -is [bool] -and -not $Context.ImageClaimed -and $null -eq $Context.ImageId) 'image-unclaimed-state'
        return
    }
    $id=[Fleetory.Pilot.AuditImageCustody]::Id($Context,${function:Invoke-Docker})
    $r=Invoke-AuditDataImageOperation $Context 'Inspect' @('image','inspect',$id)
    if($r.ExitCode -ne 0){
        [Fleetory.Pilot.AuditImageCustody]::Absent($Context,${function:Invoke-Docker})
        return
    }
    Read-AuditDataImage $Context
    Invoke-AuditDataImageOperation $Context 'Remove' @('image','rm','--no-prune',$id)
    Invoke-AuditDataImageOperation $Context 'ConfirmRemoval' @('image','inspect',$id)
}
