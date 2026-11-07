#requires -Version 7.3
# Shared fresh owned audit resources; caller owns bounded Invoke-Docker and health probe.
. (Join-Path $PSScriptRoot '../../eng/pilot/AuditDataResourceOwnership.ps1')
function Get-AuditDataLifetime($Context){
    $value=if($Context.ContainsKey('LifetimeSeconds')){$Context.LifetimeSeconds}else{3300}
    Assert-ImmuData ($value -is [int] -and $value -cin @(3300,660)) 'store-lifetime'
    return $value
}
function Read-AuditDataStore($Context,$Store,[switch]$Cleanup){
    $items=@((Invoke-Docker @('inspect',$Store.Id)).Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-ImmuData ($items.Count -eq 1) 'store-inspect';$i=$items[0];$created=ConvertTo-ProviderTimestamp $i.Created
    Assert-ImmuData ($Store.Id -cmatch '^[a-f0-9]{64}\z' -and $i.Id -ceq $Store.Id -and $i.Name -ceq ('/'+$Store.Name) -and
        $i.Config.Image -ceq $Context.ImageName -and $i.Image -ceq $Context.ImageId -and $i.Config.Labels['fleetory.immu-data.session'] -ceq $Store.Session -and
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
    $session=[Guid]::NewGuid().ToString('D');$name='fleetory-immu-store-'+$session.Replace('-','')
    $absent=Invoke-Docker @('inspect',$name) -AllowFailure
    Assert-ImmuData ($absent.ExitCode -ne 0 -and ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|container)') 'fresh-name'
    $s=@{Id=$null;Session=$session;Name=$name;Started=[DateTimeOffset]::UtcNow;Role=$Role};$Context.Stores.Add($s);Write-AuditDataLedger $Context
    $arguments=@('run','-d','--rm','--name',$name,'--label',('fleetory.immu-data.session='+$session),'--network','none','--read-only','--user','3322:3322',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','384m','--cpus','1','--pids-limit','128','--ulimit','core=0',
        '--tmpfs',('/data:'+$script:nativeAuditTmpfs['/data']),'--tmpfs',('/tmp:'+$script:nativeAuditTmpfs['/tmp']),
        '--entrypoint','/bin/sh',$Context.ImageName,'-c',('exec /bin/sleep '+(Get-AuditDataLifetime $Context)))
    $s.Id=(Invoke-Docker $arguments).Stdout.Trim();Write-AuditDataLedger $Context;Read-AuditDataStore $Context $s
    Assert-ImmuData ((Invoke-Docker @('exec',$s.Id,'sha256sum','/tool/ServerBackendProbe.dll')).Stdout.Split(' ')[0] -ceq $Context.ProbeHash) 'probe-code-identity'
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
function Remove-AuditDataStore($Context,$Store){
    $lookup=if($Store.Id){$Store.Id}else{$Store.Name};$r=Invoke-Docker @('inspect',$lookup) -AllowFailure
    if($r.ExitCode -eq 0){if(-not $Store.Id){$Store.Id=@($r.Stdout|ConvertFrom-Json -AsHashtable)[0].Id};Read-AuditDataStore $Context $Store -Cleanup;$null=Invoke-Docker @('rm','-f','-v',$Store.Id);$r=Invoke-Docker @('inspect',$Store.Id) -AllowFailure}
    Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'cleanup-absence'
}
function Build-AuditDataImage($Context,[string]$CliImage){
    foreach($image in @($CliImage,$script:nativeAuditSourceImage,$script:nativeSignerImage)){
        $r=Invoke-Docker @('image','inspect',$image) -AllowFailure
        if($r.ExitCode -ne 0){$null=Invoke-Docker @('pull',$image) -TimeoutSeconds 120}
    }
    $r=Invoke-Docker @('image','inspect',$Context.ImageName) -AllowFailure
    Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'fresh-image'
    $Context.ImageClaimed=$true
    $definition="FROM $($script:nativeAuditSourceImage) AS upstream`nFROM $CliImage AS cli`nFROM $($script:nativeSignerImage)`nCOPY --from=upstream /usr/sbin/immudb /usr/sbin/immudb`nCOPY --from=cli /usr/local/bin/immuadmin /usr/local/bin/immuadmin`nCOPY publish/ /tool/`nLABEL fleetory.immu-data.build=$($Context.Fixture)`nUSER 3322:3322`n"
    [IO.File]::WriteAllText((Join-Path $Context.Root 'Dockerfile'),$definition,[Text.UTF8Encoding]::new($false))
    $archive=Invoke-NativeBytes 'tar' @('-cf','-','-C',$Context.Root,'Dockerfile','publish') -TimeoutSeconds 60
    Assert-ImmuData ($archive.ExitCode -eq 0 -and $archive.StdoutBytes.Length -gt 0 -and $archive.StdoutBytes.Length -le 16777216) 'public-code-archive'
    $null=Invoke-Docker @('build','--network','none','--pull=false','--tag',$Context.ImageName,'-') $archive.StdoutBytes -TimeoutSeconds 120
    $built=@((Invoke-Docker @('image','inspect',$Context.ImageName)).Stdout|ConvertFrom-Json -AsHashtable)
    Assert-ImmuData ($built.Count -eq 1 -and $built[0].Config.Labels['fleetory.immu-data.build'] -ceq $Context.Fixture) 'build-identity'
    $Context.ImageId=$built[0].Id
}
function Remove-AuditDataImage($Context){
    if(-not $Context.ImageClaimed){return}
    $r=Invoke-Docker @('image','inspect',$Context.ImageName) -AllowFailure
    if($r.ExitCode -eq 0){$i=@($r.Stdout|ConvertFrom-Json -AsHashtable);Assert-ImmuData ($i.Count -eq 1 -and $i[0].Config.Labels['fleetory.immu-data.build'] -ceq $Context.Fixture -and ($null -eq $Context.ImageId -or $i[0].Id -ceq $Context.ImageId)) 'cleanup-image-owner';$null=Invoke-Docker @('image','rm',$Context.ImageName);$r=Invoke-Docker @('image','inspect',$Context.ImageName) -AllowFailure}
    Assert-ImmuData ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'cleanup-image-absence'
}
