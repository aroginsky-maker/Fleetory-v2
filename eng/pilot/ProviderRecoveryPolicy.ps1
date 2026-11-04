#requires -Version 7.3
# Closed policy for one target-only provider restore. No network or original-input reads here.
. (Join-Path $PSScriptRoot 'ProviderRecoveryCredential.ps1')
function Assert-ProviderCondition([bool] $Value, [string] $Code) {
    if (-not $Value) { throw ('Provider recovery refused: '+$Code) }
}
function Assert-PrivateOperatorAcl([string] $Path) {
    $allowed=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    $writeMask=[Security.AccessControl.FileSystemRights]'Write,Delete,ChangePermissions,TakeOwnership,DeleteSubdirectoriesAndFiles'
    foreach($rule in (Get-Acl -LiteralPath $Path).Access){
        if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow){
            $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            Assert-ProviderCondition ($sid -in $allowed -or ($rule.FileSystemRights -band $writeMask) -eq 0) 'operator-write-acl'
        }
    }
}
function Get-ProviderCodePins {
    $pins = [ordered]@{}
    foreach($name in @('Invoke-ProviderRecovery.ps1','ProviderRecoveryController.ps1','ProviderRecoveryPolicy.ps1',
        'ProviderRecoveryTransport.ps1','ProviderRecoveryRuntime.ps1','ProviderRecoveryCredential.ps1',
        'PilotNativeProcess.ps1','PilotCaptureStream.ps1','PilotDisposableTls.ps1')) {
        $pins[$name]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return $pins
}
function Assert-ProviderPlan($Plan, $Grant, [string] $PlanHash, [string] $ExpectedScope, [DateTimeOffset] $Now) {
    Assert-ProviderCondition ($Plan.schema -ceq 'fleetory.provider-recovery-plan.v1' -and
        $ExpectedScope -cin @('retained-provider','synthetic-fixture') -and $Plan.scope -ceq $ExpectedScope) 'plan-scope'
    Assert-ProviderCondition ($Plan.operationId -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and
        $PlanHash -cmatch '^[0-9a-f]{64}$') 'plan-identity'
    Assert-ProviderCondition ($null -ne $Grant -and $Grant.schema -ceq 'fleetory.provider-recovery-grant.v1' -and
        $Grant.scope -ceq $ExpectedScope -and $Grant.operationId -ceq $Plan.operationId -and
        $Grant.planSha256 -ceq $PlanHash -and $Grant.decision -ceq 'approved' -and
        $Grant.permission -ceq 'one-target-restore-four-share-submissions-one-root-one-300s-probe' -and
        $Grant.evidenceRef -cmatch '^[^\x00-\x1f]{1,512}$') 'grant-binding'
    $issued=ConvertTo-ProviderTimestamp $Grant.issuedUtc
    $expires=ConvertTo-ProviderTimestamp $Grant.expiresUtc
    Assert-ProviderCondition ($issued -le $Now -and $expires -gt $Now -and
        ($expires-$issued).Ticks -gt 0 -and ($expires-$issued).Ticks -le [TimeSpan]::FromHours(1).Ticks) 'grant-expiry'
    $pins=Get-ProviderCodePins
    Assert-ProviderCondition ((@($Plan.codePins.Keys|Sort-Object)-join '|') -ceq (@($pins.Keys|Sort-Object)-join '|')) 'code-pin-set'
    foreach($name in $pins.Keys) { Assert-ProviderCondition ($Plan.codePins[$name] -ceq $pins[$name]) 'code-pin' }
    Assert-ProviderCondition ($Plan.snapshot.bytes -ge 4096 -and $Plan.snapshot.bytes -le 67108864 -and
        $Plan.snapshot.sha256 -cmatch '^[0-9a-f]{64}$' -and $Plan.share.bytes -eq 44 -and
        $Plan.clusterId -cmatch '^[0-9a-f-]{36}$' -and $Plan.publicSpkiSha256 -cmatch '^[0-9a-f]{64}$') 'input-reference'
    $expectedKey=if($ExpectedScope -ceq 'retained-provider'){'fleetory-command'}else{'fleetory-recovery-fixture'}
    $expectedAudit=if($ExpectedScope -ceq 'retained-provider'){'pilot-file'}else{'fixture-file'}
    Assert-ProviderCondition ($Plan.transitKey -ceq $expectedKey -and $Plan.auditName -ceq $expectedAudit -and
        $Plan.sourceContainerName -cmatch '^[a-z0-9][a-z0-9_.-]{0,127}$' -and
        $Plan.sourceContainerName -cne ('fleetory-bao-restore-'+$Plan.operationId.Replace('-','')) -and
        [IO.Path]::IsPathFullyQualified($Plan.stateDirectory)) 'closed-profile'
    foreach($id in $Plan.sourceContainerIds) { Assert-ProviderCondition ($id -cmatch '^[0-9a-f]{64}$') 'source-id' }
    # The renderer independently validates the exact public host ledger and fingerprint without SSH.
    $sshPin=$Plan.ssh
    $null=Get-ProviderSshArguments @sshPin -PublicDockerArguments @('version')
}

function Open-ProviderInput([string] $Path, [long] $Length, [long] $Limit) {
    Assert-ProviderCondition ([IO.Path]::IsPathFullyQualified($Path) -and
        $Path -notmatch '(^|[\\/])\.\.?([\\/]|$)|[\x00-\x1f]|~[0-9]|^\\\\') 'input-path'
    $item=Get-Item -LiteralPath $Path -Force
    $cursor=$item
    while($null -ne $cursor) {
        Assert-ProviderCondition (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'input-link'
        $cursor=if($cursor -is [IO.DirectoryInfo]){$cursor.Parent}else{$cursor.Directory}
    }
    Assert-ProviderCondition (-not $item.PSIsContainer -and $item.Length -eq $Length -and $Length -le $Limit) 'input-size'
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if($stream.Length -ne $Length){$stream.Dispose();throw 'Provider recovery refused: input-open-size'}
    return $stream
}

function New-ProviderAttempt($Plan, [string] $PlanHash, [string] $StateDirectory, [DateTimeOffset] $Expires) {
    Assert-ProviderCondition ([IO.Path]::GetFullPath($StateDirectory) -ceq [IO.Path]::GetFullPath($Plan.stateDirectory)) 'state-directory-binding'
    $directory=Get-Item -LiteralPath $StateDirectory -Force
    Assert-ProviderCondition ($directory.PSIsContainer -and
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'state-directory'
    $path=Join-Path $directory.FullName ('provider-attempt-'+$Plan.operationId+'.jsonl')
    # CreateNew is a durable one-attempt claim, held even after failure. Never reset/delete it automatically.
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $ctx=@{Plan=$Plan;PlanHash=$PlanHash;Journal=$stream;JournalPath=$path;Clock=[Diagnostics.Stopwatch]::StartNew();
        Expires=$Expires;TargetId=$null;TargetName=('fleetory-bao-restore-'+$Plan.operationId.Replace('-',''));
        RunClaimed=$false;ForceClaimed=$false;RootClaimed=$false;TokenClaimed=$false;SignatureClaimed=$false;
        ShareSubmissions=0;SnapshotReads=0;ShareReads=0;Phase='preflight';OwnershipVerified=$false;Cleanup=$false;
        CreatedNotBefore=[DateTimeOffset]::UtcNow;ImageId=$null;TargetAbsent=$false}
    try { Write-ProviderEvent $ctx 'attempt-consumed' } catch { $stream.Dispose();throw }
    return $ctx
}
function Write-ProviderEvent($Context, [string] $Event) {
    Assert-ProviderCondition ($Event -cmatch '^[a-z-]{1,64}$' -and $Context.Journal.Length -lt 16384) 'journal-bound'
    $text=@{event=$Event;operationId=$Context.Plan.operationId;planSha256=$Context.PlanHash;
        utc=[DateTimeOffset]::UtcNow.ToString('O');targetId=$Context.TargetId}|ConvertTo-Json -Compress
    $bytes=[Text.Encoding]::UTF8.GetBytes($text+"`n")
    $Context.Journal.Write($bytes,0,$bytes.Length)
    $Context.Journal.Flush($true)
}
function Get-ProviderRequestTimeout($Context, [int] $Requested=90) {
    $limit=if($Context.Cleanup){3540}else{3240}
    $remaining=[Math]::Min($limit-$Context.Clock.Elapsed.TotalSeconds,($Context.Expires-[DateTimeOffset]::UtcNow).TotalSeconds)
    Assert-ProviderCondition ($Requested -ge 1 -and $Requested -le 120 -and $remaining -ge 1) 'operation-deadline'
    return [int][Math]::Min($Requested,[Math]::Floor($remaining))
}
function Get-ProviderLeaseNotBefore($Context) {
    # Remote preflight time is a lower bound observed before its response arrived.
    # Advance it with monotonic elapsed time rather than assuming identical host/operator UTC.
    return $Context.HostClockUtc.Add($Context.Clock.Elapsed-$Context.HostClockElapsed)
}
function Test-ProviderArguments([string[]] $Left,[string[]] $Right) {
    return (($Left|ConvertTo-Json -Compress) -ceq ($Right|ConvertTo-Json -Compress))
}
function Assert-ProviderOwnedMetadata($Context,$Info,[switch] $CleanupOnly) {
    $created=ConvertTo-ProviderTimestamp $Info.Created
    Assert-ProviderCondition ($Info.Id -cmatch '^[0-9a-f]{64}$' -and
        $Info.Id -cnotin @($Context.Plan.sourceContainerIds) -and
        ($null -eq $Context.TargetId -or $Info.Id -ceq $Context.TargetId) -and
        $Info.Name -ceq ('/'+$Context.TargetName) -and $Info.Config.Image -ceq $image -and
        $Info.Image -ceq $Context.ImageId -and $created -ge $Context.CreatedNotBefore -and
        $created -le [DateTimeOffset]::UtcNow.AddSeconds(30) -and
        $Info.Config.Labels['com.fleetory.openbao-recovery.role'] -ceq 'restore' -and
        $Info.Config.Labels['com.fleetory.openbao-recovery.session'] -ceq $Context.Plan.operationId) 'owned-target'
    if(-not $CleanupOnly) {
        Assert-ProviderCondition ($Info.State.Running -eq $true -and $Info.HostConfig.AutoRemove -eq $true -and
            $Info.HostConfig.NetworkMode -ceq 'none' -and $Info.HostConfig.ReadonlyRootfs -eq $true -and
            $Info.HostConfig.Privileged -eq $false -and $Info.Config.User -ceq '100:1000' -and
            $Info.HostConfig.PublishAllPorts -eq $false -and
            (@($Info.Config.Entrypoint)-join '|') -ceq '/bin/sh' -and
            (@($Info.Config.Cmd)-join '|') -ceq '-c|exec /bin/busybox sleep 3300' -and
            $Info.HostConfig.Memory -eq 402653184 -and $Info.HostConfig.NanoCpus -eq 300000000 -and
            $Info.HostConfig.PidsLimit -eq 128 -and ($null -eq $Info.HostConfig.CapAdd -or @($Info.HostConfig.CapAdd).Count -eq 0) -and
            (@($Info.HostConfig.CapDrop)-join '|') -ceq 'ALL' -and
            @($Info.HostConfig.PortBindings.Keys).Count -eq 0 -and @($Info.Mounts).Count -eq 0) 'target-isolation'
        Assert-ProviderCondition ($Info.HostConfig.PidMode -ceq '' -and $Info.HostConfig.IpcMode -ceq 'private' -and
            ($null -eq $Info.HostConfig.Binds -or @($Info.HostConfig.Binds).Count -eq 0) -and
            ($null -eq $Info.HostConfig.Devices -or @($Info.HostConfig.Devices).Count -eq 0) -and
            ($null -eq $Info.HostConfig.DeviceRequests -or @($Info.HostConfig.DeviceRequests).Count -eq 0) -and
            ($null -eq $Info.HostConfig.VolumesFrom -or @($Info.HostConfig.VolumesFrom).Count -eq 0) -and
            (@($Info.NetworkSettings.Networks.Keys)-join '|') -ceq 'none' -and
            ((@($Info.HostConfig.SecurityOpt)-join '|') -cin @('no-new-privileges','no-new-privileges:true')) -and
            (@($Info.HostConfig.Tmpfs.Keys|Sort-Object)-join '|') -ceq '/openbao/data|/tmp' -and
            $Info.HostConfig.Tmpfs['/tmp'] -ceq 'rw,noexec,nosuid,nodev,size=32m,uid=100,gid=1000,mode=0700' -and
            $Info.HostConfig.Tmpfs['/openbao/data'] -ceq 'rw,noexec,nosuid,nodev,size=256m,uid=100,gid=1000,mode=0700') 'target-namespaces-tmpfs'
    }
    $Context.TargetId=[string]$Info.Id
    $Context.OwnershipVerified=$true
}

function Assert-ProviderDockerRequest($Context,[string[]] $Arguments) {
    $null=Get-ProviderRequestTimeout $Context
    $verb=$Arguments[0]
    if($verb -ceq 'image') {
        Assert-ProviderCondition ($Context.Phase -ceq 'preflight' -and
            (Test-ProviderArguments $Arguments @('image','inspect','--format','{"id":{{json .Id}},"digests":{{json .RepoDigests}}}',$image))) 'image-request'
        return
    }
    if($verb -ceq 'run') {
        # Even a delayed run response must leave the 55-minute target inside the approved lease.
        Assert-ProviderCondition (($Context.Expires-[DateTimeOffset]::UtcNow).TotalSeconds -ge 3480) 'grant-target-expiry'
        Assert-ProviderCondition ($Context.Phase -ceq 'create' -and -not $Context.RunClaimed -and
            (Test-ProviderArguments $Arguments (Get-ProviderContainerArguments $Context.Plan.operationId 'restore'))) 'run-once-profile'
        $Context.RunClaimed=$true; return
    }
    if($verb -ceq 'inspect') {
        Assert-ProviderCondition (($Context.RunClaimed -or $Context.Phase -ceq 'create') -and $Arguments.Count -eq 2 -and
            ($Arguments[1] -ceq $Context.TargetName -or ($Context.TargetId -and $Arguments[1] -ceq $Context.TargetId))) 'inspect-target'
        return
    }
    Assert-ProviderCondition ($Context.OwnershipVerified -and $Context.TargetId -cmatch '^[0-9a-f]{64}$') 'target-not-bound'
    if($verb -ceq 'rm') {
        Assert-ProviderCondition ($Context.Cleanup -and
            (Test-ProviderArguments $Arguments @('rm','-f','-v',$Context.TargetId))) 'cleanup-target'
        return
    }
    Assert-ProviderCondition ($verb -ceq 'exec' -and -not $Context.Cleanup) 'operation-allowlist'
    $offset=1
    if($Arguments[1] -cin @('-i','-d')){$offset++}
    Assert-ProviderCondition ($Arguments[$offset] -ceq $Context.TargetId) 'exec-target'
    $command=@($Arguments[($offset+1)..($Arguments.Length-1)])
    $bao=$null
    if($command[0] -ceq '/usr/bin/bao'){$bao=@($command|Select-Object -Skip 1)}
    elseif($command.Count -ge 5 -and (Test-ProviderArguments $command[0..3] @('/bin/sh','-c','IFS= read -r t || exit 120; BAO_TOKEN="$t" exec /usr/bin/bao "$@"','bao'))){$bao=@($command|Select-Object -Skip 4)}
    if($null -ne $bao){ Assert-ProviderBaoRequest $Context $bao; return }
    $allowed=@(
        @('/bin/sh','-c','/usr/bin/bao server -config=/tmp/openbao.hcl >/tmp/bao.log 2>&1'),
        @('/bin/busybox','killall','bao'),@('/bin/busybox','cat','/tmp/raft.snapshot'),
        @('/bin/busybox','stat','-c','%a:%u:%g','/openbao/data/audit.log'))
    foreach($path in @('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/openbao.hcl','/tmp/raft.snapshot')) {
        $allowed+=,@('/bin/sh','-c','umask 077; cat > "$1"','sh',$path)
    }
    foreach($candidate in $allowed){if(Test-ProviderArguments $command $candidate){return}}
    throw 'Provider recovery refused: exec-allowlist'
}
function Assert-ProviderBaoRequest($Context,[string[]] $Arguments) {
    $key=$Context.Plan.transitKey
    if(Test-ProviderArguments $Arguments @('write','-format=json','sys/unseal','-')) {
        if($Context.ShareReads -eq 1) {
            Assert-ProviderCondition ($Context.ShareSubmissions -cin @(0,1,3)) 'share-submission-bound'
            $Context.ShareSubmissions++
        }
        return
    }
    $fixed=@(@('status','-format=json'),@('operator','init','-key-shares=1','-key-threshold=1','-format=json'),
        @('operator','raft','snapshot','restore','/tmp/raft.snapshot'),
        @('read','-format=json',('transit/keys/'+$key)),@('read',('transit/keys/'+$key)),
        @('read','-format=json','auth/token/lookup-self'),@('token','revoke','-self'),
        @('write','-format=json','-force','sys/generate-root/attempt'),
        @('policy','write','fixture-recovered-signer','-'),
        @('write','transit/keys/forbidden-fixture','type=ecdsa-p256'),@('write','-force','auth/token/create-orphan'),
        @('write','sys/policies/acl/forbidden-fixture','policy='),@('write','-force','auth/token/renew-self'))
    foreach($candidate in $fixed){if(Test-ProviderArguments $Arguments $candidate){return}}
    if(Test-ProviderArguments $Arguments @('operator','raft','snapshot','restore','-force','/tmp/raft.snapshot')){
        Assert-ProviderCondition (-not $Context.ForceClaimed -and $Context.Phase -ceq 'force') 'force-once'
        $Context.ForceClaimed=$true;return
    }
    if(Test-ProviderArguments $Arguments @('write','-format=json','sys/generate-root/attempt','-')){
        Assert-ProviderCondition ($Context.Phase -ceq 'credential' -and $Context.ForceClaimed -and -not $Context.RootClaimed) 'root-once'
        $Context.RootClaimed=$true;return
    }
    if(Test-ProviderArguments $Arguments @('write','-format=json','sys/generate-root/update','-')){
        Assert-ProviderCondition ($Context.RootClaimed -and $Context.ShareSubmissions -eq 2) 'root-quorum-once'
        $Context.ShareSubmissions++;return
    }
    if(Test-ProviderArguments $Arguments @('write','-format=json','auth/token/create-orphan','policies=fixture-recovered-signer',
        'no_default_policy=true','ttl=300s','explicit_max_ttl=300s','renewable=false')){
        Assert-ProviderCondition ($Context.Phase -ceq 'credential' -and $Context.RootClaimed -and -not $Context.TokenClaimed) 'probe-token-once'
        $Context.TokenClaimed=$true;return
    }
    $challenge='fleetory-provider-recovery-probe/v1:'+ $Context.Plan.operationId
    if(Test-ProviderArguments $Arguments @('write','-format=json',('transit/sign/'+$key+'/sha2-256'),
        ('input='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($challenge))),
        'key_version=1','marshaling_algorithm=jws','prehashed=false')){
        Assert-ProviderCondition ($Context.TokenClaimed -and -not $Context.SignatureClaimed -and $Context.ShareSubmissions -eq 4) 'signature-once'
        $Context.SignatureClaimed=$true;return
    }
    throw 'Provider recovery refused: bao-allowlist'
}
