#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$controllerRepo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $controllerRepo 'eng/pilot/ProviderRecoveryController.ps1')
. (Join-Path $PSScriptRoot 'ProviderRecoveryFixture.ps1')
$controllerRoot=Join-Path ([IO.Path]::GetTempPath()) ('fleetory-controller-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($controllerRoot)
$script:controllerRefusals=0
function Assert-ControllerTest([bool] $Value,[string] $Code){if(-not $Value){throw ('Controller test failed: '+$Code)}}
function Refuse-Controller([scriptblock] $Action){
    $refused=$false
    try{$null=& $Action}catch{$refused=$true}
    Assert-ControllerTest $refused 'unsafe request accepted'
    $script:controllerRefusals++
}
function Copy-ControllerObject($Value){return $Value|ConvertTo-Json -Depth 16|ConvertFrom-Json -AsHashtable}
$image='ghcr.io/openbao/openbao:2.7.1@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf'
$contexts=[Collections.Generic.List[object]]::new()
try {
    $plan=New-ControllerFixturePlan $controllerRoot
    $hash=Get-ControllerFixtureHash $plan
    $grant=New-ControllerFixtureGrant $plan $hash
    $now=[DateTimeOffset]::UtcNow
    Assert-ProviderPlan $plan $grant $hash 'synthetic-fixture' $now
    Refuse-Controller {Invoke-ProviderRecoveryController $plan $grant $hash $controllerRoot {} {} 'retained-provider'}
    foreach($change in @(@{decision='denied'},@{planSha256=('0'*64)},@{operationId=[Guid]::NewGuid().ToString('D')},
        @{scope='retained-provider'},@{evidenceRef=''},@{permission='root'},
        @{expiresUtc=$now.AddSeconds(-1).ToString('O')},@{issuedUtc=$now.AddSeconds(5).ToString('O')},
        @{issuedUtc=$now.AddSeconds(-1).ToString('O');expiresUtc=$now.AddSeconds(-1).AddTicks(36000000001).ToString('O')})){
        $bad=Copy-ControllerObject $grant;foreach($key in $change.Keys){$bad[$key]=$change[$key]}
        Refuse-Controller {Assert-ProviderPlan $plan $bad $hash 'synthetic-fixture' $now}
    }
    Refuse-Controller {Assert-ProviderPlan $plan $null $hash 'synthetic-fixture' $now}
    foreach($kind in @('code','extra-code','host','key','source-id')){
        $badPlan=Copy-ControllerObject $plan
        switch($kind){
            'code' {$badPlan.codePins['ProviderRecoveryController.ps1']='0'*64}
            'extra-code' {$badPlan.codePins['other.ps1']='0'*64}
            'host' {$badPlan.ssh.Address='192.0.2.18'}
            'key' {$badPlan.transitKey='fleetory-command'}
            'source-id' {$badPlan.sourceContainerIds=@('not-a-container')}
        }
        Refuse-Controller {Assert-ProviderPlan $badPlan $grant $hash 'synthetic-fixture' $now}
    }
    $ctx=New-ProviderAttempt $plan $hash $controllerRoot ([DateTimeOffset]::UtcNow.AddMinutes(59));$contexts.Add($ctx)
    Refuse-Controller {New-ProviderAttempt $plan $hash $controllerRoot ([DateTimeOffset]::UtcNow.AddMinutes(30))}
    $ctx.Journal.Dispose()
    Refuse-Controller {New-ProviderAttempt $plan $hash $controllerRoot ([DateTimeOffset]::UtcNow.AddMinutes(30))}
    # A new process also sees the durable claim after the first process has closed it.
    $pwsh=Join-Path $PSHOME $(if($IsWindows){'pwsh.exe'}else{'pwsh'})
    $child=Join-Path $controllerRoot 'check-attempt.ps1'
    [IO.File]::WriteAllText($child,'param($p) try{$s=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$s.Dispose();exit 99}catch [IO.IOException]{exit 23}')
    $result=Invoke-NativeBytes $pwsh @('-NoProfile','-File',$child,$ctx.JournalPath) -TimeoutSeconds 10
    Assert-ControllerTest ($result.ExitCode -eq 23) 'durable marker missing in child process'
    $plan.operationId=[Guid]::NewGuid().ToString('D')
    Refuse-Controller {New-ProviderAttempt $plan $hash ([IO.Path]::GetTempPath()) ([DateTimeOffset]::UtcNow.AddMinutes(59))}
    $ctx=New-ProviderAttempt $plan $hash $controllerRoot ([DateTimeOffset]::UtcNow.AddMinutes(59));$contexts.Add($ctx)
    $ctx.Phase='create'
    $ctx.HostClockUtc=[DateTimeOffset]::UtcNow.AddSeconds(-25)
    $ctx.HostClockElapsed=$ctx.Clock.Elapsed
    $leaseBound=Get-ProviderLeaseNotBefore $ctx
    Assert-ControllerTest ($leaseBound -ge $ctx.HostClockUtc -and $leaseBound -lt [DateTimeOffset]::UtcNow.AddSeconds(-24)) 'remote clock lower bound'
    $run=Get-ProviderContainerArguments $plan.operationId 'restore'
    foreach($replacement in @(@{at=0;value='pull'},@{at=([Array]::IndexOf($run,'none'));value='host'},
        @{at=([Array]::IndexOf($run,'100:1000'));value='0'},@{at=($run.Length-1);value='sleep 36000'})){
        $badRun=[string[]]$run.Clone();$badRun[$replacement.at]=$replacement.value
        Refuse-Controller {Assert-ProviderDockerRequest $ctx $badRun}
    }
    Assert-ProviderDockerRequest $ctx $run
    Refuse-Controller {Assert-ProviderDockerRequest $ctx $run}
    Refuse-Controller {Assert-ProviderDockerRequest $ctx @('inspect',$plan.sourceContainerName)}
    Refuse-Controller {Assert-ProviderDockerRequest $ctx @('exec',('a'*64),'/usr/bin/bao','status')}
    $ctx.TargetId='d'*64;$ctx.OwnershipVerified=$true
    $ctx.ImageId='sha256:'+('e'*64)
    $baseInfo=@{Id=('d'*64);Name=('/'+$ctx.TargetName);Image=$ctx.ImageId;Created=[DateTimeOffset]::UtcNow.ToString('O');
        Config=@{Image=$image;User='100:1000';Entrypoint=@('/bin/sh');Cmd=@('-c','exec /bin/busybox sleep 3300');
            Labels=@{'com.fleetory.openbao-recovery.role'='restore';'com.fleetory.openbao-recovery.session'=$plan.operationId}};
        State=@{Running=$true};Mounts=@();NetworkSettings=@{Networks=@{none=@{}}};
        HostConfig=@{AutoRemove=$true;NetworkMode='none';ReadonlyRootfs=$true;Privileged=$false;PublishAllPorts=$false;
            Memory=402653184;NanoCpus=300000000;PidsLimit=128;CapAdd=$null;CapDrop=@('ALL');PortBindings=@{};
            PidMode='';IpcMode='private';Binds=$null;Devices=@();DeviceRequests=$null;VolumesFrom=$null;
            SecurityOpt=@('no-new-privileges');Tmpfs=@{'/tmp'='rw,noexec,nosuid,nodev,size=32m,uid=100,gid=1000,mode=0700';
                '/openbao/data'='rw,noexec,nosuid,nodev,size=256m,uid=100,gid=1000,mode=0700'}}}
    Assert-ProviderOwnedMetadata $ctx $baseInfo
    foreach($mutation in @(
        {param($x)$x.Id='a'*64},{param($x)$x.Name='/fixture-source'},
        {param($x)$x.Config.Labels['com.fleetory.openbao-recovery.session']=[Guid]::NewGuid().ToString('D')},
        {param($x)$x.Created=[DateTimeOffset]::UtcNow.AddHours(-1).ToString('O')},
        {param($x)$x.Created=[DateTimeOffset]::UtcNow.AddHours(1).ToString('O')},
        {param($x)$x.Config.User='0'},{param($x)$x.Config.Cmd=@('-c','sleep 36000')},
        {param($x)$x.HostConfig.AutoRemove=$false},{param($x)$x.HostConfig.NetworkMode='host'},
        {param($x)$x.HostConfig.Privileged=$true},{param($x)$x.HostConfig.PublishAllPorts=$true},
        {param($x)$x.HostConfig.Memory=0},{param($x)$x.HostConfig.CapAdd=@('SYS_ADMIN')},
        {param($x)$x.HostConfig.PortBindings=@{'8200/tcp'=@{HostPort='8200'}}},
        {param($x)$x.HostConfig.Binds=@('/source:/openbao/data')},
        {param($x)$x.HostConfig.PidMode='host'},{param($x)$x.HostConfig.SecurityOpt=@()},
        {param($x)$x.HostConfig.Tmpfs['/tmp']='rw,mode=0777'},
        {param($x)$x.NetworkSettings.Networks=@{bridge=@{}}}
    )){
        $badInfo=Copy-ControllerObject $baseInfo;& $mutation $badInfo
        Refuse-Controller {Assert-ProviderOwnedMetadata $ctx $badInfo}
    }
    foreach($unsafeArguments in @(@('exec',('a'*64),'/usr/bin/bao','status'),@('exec','-u','0',('d'*64),'/usr/bin/bao','status'),
        @('exec',('d'*64),'/bin/sh','-c','rm -rf /'),@('exec',('d'*64),'/usr/bin/bao','token','lookup','secret'),
        @('rm','-f','-v',('d'*64)))){Refuse-Controller {Assert-ProviderDockerRequest $ctx $unsafeArguments}}
    $ctx.Phase='force'
    $force=@('operator','raft','snapshot','restore','-force','/tmp/raft.snapshot')
    Assert-ProviderBaoRequest $ctx $force;Refuse-Controller {Assert-ProviderBaoRequest $ctx $force}
    $ctx.Phase='credential'
    $rootArgs=@('write','-format=json','sys/generate-root/attempt','-')
    Assert-ProviderBaoRequest $ctx $rootArgs;Refuse-Controller {Assert-ProviderBaoRequest $ctx $rootArgs}
    $ctx.ShareReads=1
    $unseal=@('write','-format=json','sys/unseal','-')
    Assert-ProviderBaoRequest $ctx $unseal;Assert-ProviderBaoRequest $ctx $unseal
    Refuse-Controller {Assert-ProviderBaoRequest $ctx $unseal}
    $quorum=@('write','-format=json','sys/generate-root/update','-')
    Assert-ProviderBaoRequest $ctx $quorum;Refuse-Controller {Assert-ProviderBaoRequest $ctx $quorum}
    Assert-ProviderBaoRequest $ctx $unseal;Refuse-Controller {Assert-ProviderBaoRequest $ctx $unseal}
    $tokenArgs=@('write','-format=json','auth/token/create-orphan','policies=fixture-recovered-signer',
        'no_default_policy=true','ttl=300s','explicit_max_ttl=300s','renewable=false')
    Assert-ProviderBaoRequest $ctx $tokenArgs;Refuse-Controller {Assert-ProviderBaoRequest $ctx $tokenArgs}
    $challenge='fleetory-provider-recovery-probe/v1:'+$plan.operationId
    $signArgs=@('write','-format=json','transit/sign/fleetory-recovery-fixture/sha2-256',
        ('input='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($challenge))),
        'key_version=1','marshaling_algorithm=jws','prehashed=false')
    Assert-ProviderBaoRequest $ctx $signArgs;Refuse-Controller {Assert-ProviderBaoRequest $ctx $signArgs}
    $signArgs[3]='input=command-envelope';Refuse-Controller {Assert-ProviderBaoRequest $ctx $signArgs}
    $ctx.Expires=[DateTimeOffset]::UtcNow.AddSeconds(-1)
    Refuse-Controller {Get-ProviderRequestTimeout $ctx}
    $ctx.Expires=[DateTimeOffset]::UtcNow.AddMinutes(30)
    Refuse-Controller {Get-ProviderRequestTimeout $ctx 121}
    $sharePath=Join-Path $controllerRoot 'share'
    [IO.File]::WriteAllBytes($sharePath,[Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(33))))
    $ref=@{path=$sharePath;bytes=44;mtimeUtc=[IO.File]::GetLastWriteTimeUtc($sharePath).ToString('O')}
    Assert-ControllerTest ((Read-ProviderReference 'share' $ref).Length -eq 44) 'generated share read'
    if($IsWindows){
        $lock=Open-ProviderInput $sharePath 44 44
        try {Refuse-Controller {[IO.File]::WriteAllBytes($sharePath,[byte[]]::new(44))}}
        finally {$lock.Dispose()}
    }
    Refuse-Controller {Open-ProviderInput $sharePath 43 44}
    Refuse-Controller {Open-ProviderInput (Join-Path $controllerRoot '../share') 44 44}
    $ref.mtimeUtc=[DateTimeOffset]::UtcNow.AddDays(-1).ToString('O')
    Refuse-Controller {Read-ProviderReference 'share' $ref}
    $script:forbiddenMaterialReads=0
    $noRead={param($kind,$reference) $script:forbiddenMaterialReads++;throw 'Input reader must not run.'}
    foreach($fault in @('memory','clock','host','existing','lifetime','run-lost','cleanup-lost','source-id')){
        $plan.operationId=[Guid]::NewGuid().ToString('D');$hash=Get-ControllerFixtureHash $plan;$grant=New-ControllerFixtureGrant $plan $hash
        if($fault -ceq 'lifetime'){$grant.expiresUtc=[DateTimeOffset]::UtcNow.AddMinutes(30).ToString('O')}
        $script:mockOperations=[Collections.Generic.List[string]]::new()
        $mock={param($request)
            $script:mockOperations.Add($request.Kind+':'+($request.Arguments -join ' '))
            if($request.Kind -ceq 'host-preflight'){
                if($fault -ceq 'host'){return New-ControllerFixtureResult 'invalid'}
                $memory=if($fault -ceq 'memory'){1}else{1048576}
                $utc=if($fault -ceq 'clock'){1}else{[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()}
                return New-ControllerFixtureResult ($memory.ToString()+"`n"+$utc.ToString())
            }
            switch($request.Arguments[0]){
                'image' {return New-ControllerFixtureResult ('{"id":"sha256:'+('e'*64)+'","digests":["ghcr.io/openbao/openbao@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf"]}')}
                'inspect' {
                    if($fault -ceq 'cleanup-lost' -and $script:mockOperations.Count -gt 4){throw 'Synthetic disconnected transport'}
                    if($fault -ceq 'existing'){return New-ControllerFixtureResult '[{}]'}
                    return New-ControllerFixtureResult '' 1 'No such object'
                }
                'run' {if($fault -ceq 'source-id'){return New-ControllerFixtureResult ('a'*64)};throw 'Synthetic lost run response'}
                default {throw 'Unapproved mock operation'}
            }
        }
        $proof=Invoke-ProviderRecoveryController $plan $grant $hash $controllerRoot $mock $noRead 'synthetic-fixture'
        Assert-ControllerTest (-not $proof.verified -and $proof.snapshotReads -eq 0 -and $proof.shareReads -eq 0) 'preflight crossed material boundary'
        Assert-ControllerTest ($proof.cleanupVerified -eq ($fault -cne 'cleanup-lost')) 'cleanup result inaccurate'
        $expectedCode=switch($fault){'memory'{'host-capacity-clock'}'clock'{'host-preflight'}'host'{'host-preflight'}
            'existing'{'new-target-inspection'}'source-id'{'new-target-id'}'lifetime'{'grant-target-expiry'}default{$null}}
        if($null -ne $expectedCode){Assert-ControllerTest ($proof.failureCode -ceq $expectedCode) 'wrong preflight refusal branch'}
        $script:controllerRefusals++
    }
    Assert-ControllerTest ($script:forbiddenMaterialReads -eq 0) 'original reader was called'
    Write-Host ('PROVIDER CONTROLLER CONTRACT PASS: '+$script:controllerRefusals+' refusals; durable marker; no network or original material reads.')
}
finally {
    foreach($ctx in $contexts){$ctx.Journal.Dispose();$ctx.Clock.Stop()}
    foreach($file in [IO.Directory]::EnumerateFiles($controllerRoot)){[IO.File]::Delete($file)}
    [IO.Directory]::Delete($controllerRoot)
}
