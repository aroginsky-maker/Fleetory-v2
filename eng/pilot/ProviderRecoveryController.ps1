#requires -Version 7.3
. (Join-Path $PSScriptRoot 'ProviderRecoveryTransport.ps1')
. (Join-Path $PSScriptRoot 'ProviderRecoveryPolicy.ps1')
. (Join-Path $PSScriptRoot 'PilotNativeProcess.ps1')

function Read-ProviderReference([string] $Kind,$Reference) {
    $stream=Open-ProviderInput $Reference.path $Reference.bytes 67108864
    try {
        if($Kind -ceq 'share') {
            Assert-ProviderCondition (([IO.File]::GetLastWriteTimeUtc($Reference.path)).Ticks -eq
                (ConvertTo-ProviderTimestamp $Reference.mtimeUtc).UtcTicks) 'share-reference-time'
        }
        $bytes=[byte[]]::new([int]$Reference.bytes)
        $stream.ReadExactly($bytes)
        return ,$bytes
    } finally { $stream.Dispose() }
}

function Invoke-ProviderRecoveryController($Plan,$Grant,[string] $PlanHash,[string] $StateDirectory,
    [scriptblock] $Transport,[scriptblock] $InputReader,[string] $ExpectedScope) {
    if($ExpectedScope -ceq 'retained-provider') {
        $caller=(Get-PSCallStack)[1].ScriptName
        Assert-ProviderCondition ($IsWindows -and $null -eq $Transport -and $null -eq $InputReader -and
            [string]::Equals([IO.Path]::GetFullPath($caller),(Join-Path $PSScriptRoot 'Invoke-ProviderRecovery.ps1'),[StringComparison]::OrdinalIgnoreCase)) 'real-entry-only'
    }else{
        Assert-ProviderCondition ($ExpectedScope -ceq 'synthetic-fixture' -and $null -ne $Transport -and $null -ne $InputReader) 'fixture-adapter-only'
    }
    Assert-ProviderPlan $Plan $Grant $PlanHash $ExpectedScope ([DateTimeOffset]::UtcNow)
    # Copy metadata so callbacks cannot mutate the approved policy through the caller's original object.
    $Plan=$Plan|ConvertTo-Json -Depth 16|ConvertFrom-Json -AsHashtable
    if($ExpectedScope -ceq 'retained-provider') {
        $fixedHostPin=$Plan.ssh.Clone()
        $fixedSshExecutable=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'System32/OpenSSH/ssh.exe'
        $Transport={param($request)
            Assert-ProviderCondition ($request.Address -ceq $fixedHostPin.Address) 'request-host'
            $arguments=if($request.Kind -ceq 'host-preflight'){
                Get-ProviderSshArguments @fixedHostPin -HostPreflight
            }else{
                Assert-ProviderCondition ($request.Kind -ceq 'docker') 'request-kind'
                Get-ProviderSshArguments @fixedHostPin -PublicDockerArguments $request.Arguments
            }
            Invoke-NativeBytes $fixedSshExecutable $arguments $request.InputBytes $request.TimeoutSeconds
        }
        $InputReader={param($kind,$reference) Assert-PrivateOperatorAcl $reference.path;Read-ProviderReference $kind $reference}
    }
    $ctx=New-ProviderAttempt $Plan $PlanHash $StateDirectory (ConvertTo-ProviderTimestamp $Grant.expiresUtc)
    $image='ghcr.io/openbao/openbao:2.7.1@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf'
    $session=$Plan.operationId
    $records=[Collections.Generic.List[object]]::new()
    $providerTransitKey=$Plan.transitKey
    $providerAuditName=$Plan.auditName
    $script:forceRestoreClaimed=$false
    $script:credentialCanaries=[Collections.Generic.List[string]]::new()
    $script:credentialRecoveryStage='controller'
    $script:lastForbiddenCode=0
    $script:credentialLeaseDiagnostic=$null
    $targetRoot=$bootstrapRoot=$bootstrapShare=$share=$token=$snapshot=$material=$public=$null
    $success=$cleanupVerified=$false
    $failureStage='preflight'
    $failureCode=$null
    $ctx.PublicHost=$Plan.ssh.Address
    function Assert-True([bool] $Condition,[string] $Message) { Assert-ProviderCondition $Condition 'native-acceptance' }
    function Send-ControllerRequest([string] $Kind,[string[]] $Arguments,[byte[]] $Bytes,[int] $Timeout=90) {
        $timeoutBound=Get-ProviderRequestTimeout $ctx $Timeout
        $result=& $Transport ([pscustomobject]@{Kind=$Kind;Address=$ctx.PublicHost;Arguments=$Arguments;InputBytes=$Bytes;TimeoutSeconds=$timeoutBound})
        Assert-ProviderCondition ($null -ne $result -and $null -ne $result.ExitCode) 'transport-result'
        $null=Get-ProviderRequestTimeout $ctx
        return $result
    }
    function Invoke-Docker([string[]] $Arguments,[byte[]] $InputBytes=$null,[int] $TimeoutSeconds=90,[switch] $AllowFailure) {
        Assert-ProviderDockerRequest $ctx $Arguments
        $result=Send-ControllerRequest 'docker' $Arguments $InputBytes $TimeoutSeconds
        if($Arguments[0] -ceq 'run' -and $result.ExitCode -eq 0) {
            $candidate=$result.Stdout.Trim()
            Assert-ProviderCondition ($candidate -cmatch '^[0-9a-f]{64}$' -and $candidate -cnotin @($Plan.sourceContainerIds)) 'new-target-id'
            $ctx.TargetId=$candidate
            Write-ProviderEvent $ctx 'target-created'
        }
        if($Arguments[0] -ceq 'inspect' -and $result.ExitCode -eq 0) {
            $items=@($result.Stdout|ConvertFrom-Json -AsHashtable)
            Assert-ProviderCondition ($items.Count -eq 1 -and $ctx.RunClaimed) 'new-target-inspection'
            Assert-ProviderOwnedMetadata $ctx $items[0] -CleanupOnly:$ctx.Cleanup
        }
        if(-not $AllowFailure){Assert-ProviderCondition ($result.ExitCode -eq 0) 'native-command'}
        return $result
    }
    . (Join-Path $PSScriptRoot 'ProviderRecoveryRuntime.ps1')
    . (Join-Path $PSScriptRoot 'ProviderRecoveryCredential.ps1')
    . (Join-Path $PSScriptRoot 'PilotDisposableTls.ps1')
    function Read-ControllerMaterial([string] $Kind) {
        $null=Assert-Owned $ctx.TargetId 'restore'
        if($Kind -ceq 'snapshot'){
            Assert-ProviderCondition ($ctx.Phase -ceq 'bootstrap' -and $ctx.SnapshotReads -eq 0) 'snapshot-read-once'
            $ctx.SnapshotReads++
        }else{
            Assert-ProviderCondition ($ctx.Phase -ceq 'restored-sealed' -and $ctx.ShareReads -eq 0 -and
                $ctx.ForceClaimed -and (Get-Status $ctx.TargetId).sealed -eq $true) 'share-read-once'
            $ctx.ShareReads++
        }
        $bytes=[byte[]](& $InputReader $Kind $Plan[$Kind])
        if($Kind -ceq 'snapshot'){$ctx.SnapshotLoads++}else{$ctx.ShareLoads++}
        Assert-ProviderCondition ($bytes.Length -eq $Plan[$Kind].bytes) 'material-size'
        if($Kind -ceq 'snapshot'){Assert-SnapshotReference $bytes $Plan.snapshot.sha256}
        return ,$bytes
    }
    try {
        $hostInfo=Send-ControllerRequest 'host-preflight' @() $null 15
        $values=@($hostInfo.Stdout.Trim() -split '\r?\n')
        Assert-ProviderCondition ($hostInfo.ExitCode -eq 0 -and $values.Count -eq 2 -and
            $values[0] -cmatch '^[0-9]{1,12}$' -and $values[1] -cmatch '^[0-9]{10}$') 'host-preflight'
        $hostUtc=[DateTimeOffset]::FromUnixTimeSeconds([long]$values[1])
        Assert-ProviderCondition ([long]$values[0] -ge 524288 -and
            [Math]::Abs(($hostUtc-[DateTimeOffset]::UtcNow).TotalSeconds) -le 30) 'host-capacity-clock'
        $ctx.CreatedNotBefore=$hostUtc.AddSeconds(-1)
        $ctx.HostClockUtc=$hostUtc
        $ctx.HostClockElapsed=$ctx.Clock.Elapsed
        $imageInfo=Invoke-Docker @('image','inspect','--format','{"id":{{json .Id}},"digests":{{json .RepoDigests}}}',$image)
        $imageData=Get-Json $imageInfo.Stdout
        Assert-ProviderCondition ($imageData.id -cmatch '^sha256:[0-9a-f]{64}$' -and
            @($imageData.digests|Where-Object {$_ -ceq 'ghcr.io/openbao/openbao@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf'}).Count -eq 1) 'pinned-image'
        $ctx.ImageId=$imageData.id
        $ctx.Phase='create'
        $absent=Invoke-Docker @('inspect',$ctx.TargetName) -AllowFailure
        Assert-ProviderCondition ($absent.ExitCode -ne 0 -and
            ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|container)') 'target-already-exists'
        $id=New-Container 'restore'
        $records[0].StartedUtc=$ctx.CreatedNotBefore
        $null=Assert-Owned $id 'restore'
        $ctx.Phase='bootstrap';$failureStage='bootstrap'
        $material=New-PilotDisposableTlsMaterial
        Write-ContainerFile $id '/tmp/ca.pem' ([Text.Encoding]::UTF8.GetBytes($material.RootCertificatePem))
        Write-ContainerFile $id '/tmp/server.crt' ([Text.Encoding]::UTF8.GetBytes($material.ServerCertificatePem))
        Write-ContainerFile $id '/tmp/server.key' ([Text.Encoding]::UTF8.GetBytes($material.ServerPrivateKeyPem))
        Start-Bao $id 'restore'
        $init=Get-Json (Invoke-Bao $id @('operator','init','-key-shares=1','-key-threshold=1','-format=json')).Stdout
        $bootstrapRoot=[string]$init.root_token;$bootstrapShare=[string]$init.unseal_keys_b64[0]
        $script:credentialCanaries.Add($bootstrapRoot);$script:credentialCanaries.Add($bootstrapShare)
        $null=Invoke-Unseal $id $bootstrapShare
        $bootstrapCluster=[string](Wait-Active $id).cluster_id
        Assert-ProviderCondition ($bootstrapCluster -cne $Plan.clusterId) 'fresh-bootstrap-cluster'
        $snapshot=Read-ControllerMaterial 'snapshot'
        Write-ContainerFile $id '/tmp/raft.snapshot' $snapshot
        Assert-SnapshotReference (Get-SnapshotBytes $id) $Plan.snapshot.sha256
        $normal=Invoke-Bao $id @('operator','raft','snapshot','restore','/tmp/raft.snapshot') $bootstrapRoot -AllowFailure
        Assert-ProviderCondition ($normal.ExitCode -ne 0 -and ($normal.Stdout+$normal.Stderr) -match '(?i)Code:\s*400' -and
            ($normal.Stdout+$normal.Stderr) -match '(?i)(seal|shamir|unseal)' -and
            (Get-Status $id).cluster_id -ceq $bootstrapCluster) 'foreign-seal-refusal'
        $ctx.Phase='force';$failureStage='force'
        Assert-FreshTargetForForceRestore $id $bootstrapCluster
        $null=Invoke-Bao $id @('operator','raft','snapshot','restore','-force','/tmp/raft.snapshot') $bootstrapRoot -TimeoutSeconds 120
        $sealed=$false
        for($n=0;$n -lt 40;$n++){
            try {if((Get-Status $id).sealed -eq $true){$sealed=$true;break}}catch{}
            Start-Sleep -Milliseconds 250
        }
        if(-not $sealed){
            $null=Invoke-Docker @('exec',$id,'/bin/busybox','killall','bao') -AllowFailure
            Start-Sleep -Milliseconds 300;Start-Bao $id 'restore'
        }
        Assert-ProviderCondition ((Get-Status $id).sealed -eq $true) 'restored-seal'
        $wrong=Invoke-Unseal $id $bootstrapShare -AllowFailure
        Assert-ProviderCondition ($wrong.ExitCode -ne 0 -and ($wrong.Stdout+$wrong.Stderr) -match '(?i)Code:\s*400') 'bootstrap-share-refusal'
        $ctx.Phase='restored-sealed';$failureStage='original-share'
        $shareBytes=Read-ControllerMaterial 'share'
        $share=[Text.UTF8Encoding]::new($false,$true).GetString($shareBytes)
        Assert-ProviderCondition ($share -cmatch '^[A-Za-z0-9+/]{43}[A-Za-z0-9+/=]$') 'share-encoding'
        $decodedShare=[Convert]::FromBase64String($share)
        Assert-ProviderCondition ($decodedShare.Length -cin @(32,33) -and [Convert]::ToBase64String($decodedShare) -ceq $share) 'share-encoding'
        $script:credentialCanaries.Add($share)
        $null=Invoke-Unseal $id $share
        Assert-ProviderCondition ((Wait-Active $id).cluster_id -ceq $Plan.clusterId) 'retained-cluster'
        Assert-RecoveryEndpointDisabled $id
        Assert-Forbidden $id $bootstrapRoot @('read',('transit/keys/'+$providerTransitKey)) 'Bootstrap root'
        $ctx.Phase='credential';$failureStage='credential'
        Restart-RecoveryCredentialTarget $id $Plan.clusterId $share -RecoveryWindow
        $targetRoot=Get-RecoveredTargetRoot $id $share
        $policy='path "transit/keys/'+$providerTransitKey+'" { capabilities = ["read"] }'+"`n"+
            'path "transit/sign/'+$providerTransitKey+'/sha2-256" { capabilities = ["update"] }'+"`n"+
            'path "auth/token/lookup-self" { capabilities = ["read"] }'+"`n"+
            'path "auth/token/revoke-self" { capabilities = ["update"] }'
        $null=Invoke-Bao $id @('policy','write','fixture-recovered-signer','-') $targetRoot ([Text.Encoding]::UTF8.GetBytes($policy))
        $createdAfter=Get-ProviderLeaseNotBefore $ctx
        $response=Invoke-AuthenticatedJson $id $targetRoot @('write','-format=json','auth/token/create-orphan',
            'policies=fixture-recovered-signer','no_default_policy=true','ttl=300s','explicit_max_ttl=300s','renewable=false')
        $token=[string]$response.auth.client_token
        $script:credentialCanaries.Add($token)
        $before=Get-Data $id $token @('read','-format=json','auth/token/lookup-self')
        Assert-TargetCredentialLease $before $createdAfter
        $null=Invoke-Bao $id @('token','revoke','-self') $targetRoot
        Assert-Forbidden $id $targetRoot @('read',('transit/keys/'+$providerTransitKey)) 'Revoked target root'
        Restart-RecoveryCredentialTarget $id $Plan.clusterId $share
        Assert-RecoveryEndpointDisabled $id
        $after=Get-Data $id $token @('read','-format=json','auth/token/lookup-self')
        Assert-TargetCredentialLease $after $createdAfter
        Assert-ProviderCondition ($before.id -ceq $after.id -and $before.accessor -ceq $after.accessor -and
            $before.expire_time -ceq $after.expire_time -and $before.creation_time -eq $after.creation_time -and
            $after.ttl -le $before.ttl) 'lease-continuity'
        foreach($command in @(@('write','transit/keys/forbidden-fixture','type=ecdsa-p256'),
            @('write','-force','auth/token/create-orphan'),@('write','sys/policies/acl/forbidden-fixture','policy='),
            @('write','-force','auth/token/renew-self'))){Assert-Forbidden $id $token $command 'Restricted probe'}
        $public=Get-TransitPublic $id $token
        Assert-ProviderCondition ($public.Hash -ceq $Plan.publicSpkiSha256) 'retained-public-key'
        Assert-Signature $id $token $public ('fleetory-provider-recovery-probe/v1:'+$Plan.operationId)
        $null=Invoke-Bao $id @('token','revoke','-self') $token
        Assert-Forbidden $id $token @('read',('transit/keys/'+$providerTransitKey)) 'Revoked probe'
        $audit=Invoke-Docker @('exec',$id,'/bin/busybox','stat','-c','%a:%u:%g','/openbao/data/audit.log')
        Assert-ProviderCondition ($audit.Stdout.Trim() -ceq '600:100:1000' -and $ctx.ShareSubmissions -eq 4) 'audit-and-share-bound'
        $success=$true;Write-ProviderEvent $ctx 'acceptance-passed'
    }
    catch {
        $failureCode=if($_.Exception.Message -cmatch '^Provider recovery refused: ([a-z-]+)$'){$Matches[1]}
            else{'native-'+$_.Exception.GetType().Name+'-line'+$_.InvocationInfo.ScriptLineNumber}
        Write-ProviderEvent $ctx 'operation-failed'
    }
    finally {
        $ctx.Cleanup=$true
        if($ctx.RunClaimed){
            try {
                $inspection=Invoke-Docker @('inspect',$ctx.TargetName) -AllowFailure
                if($inspection.ExitCode -ne 0){
                    Assert-ProviderCondition (($inspection.Stderr+$inspection.Stdout) -match '(?i)no such (object|container)') 'cleanup-inspect'
                }else{
                    $null=Invoke-Docker @('rm','-f','-v',$ctx.TargetId)
                    $gone=Invoke-Docker @('inspect',$ctx.TargetName) -AllowFailure
                    Assert-ProviderCondition ($gone.ExitCode -ne 0 -and ($gone.Stderr+$gone.Stdout) -match '(?i)no such (object|container)') 'cleanup-absence'
                }
                $cleanupVerified=$true
            }catch{}
        }else{$cleanupVerified=$true}
        Write-ProviderEvent $ctx $(if($cleanupVerified){'cleanup-verified'}else{'cleanup-unconfirmed'})
        $ctx.Journal.Dispose();$ctx.Clock.Stop()
        if($public){$public.Key.Dispose()}
        if($material){$material.ServerPrivateKeyPem=$null}
        $targetRoot=$bootstrapRoot=$bootstrapShare=$share=$shareBytes=$decodedShare=$token=$snapshot=$null
    }
    $proof=[ordered]@{schema='fleetory.provider-recovery-controller-proof.v1';operationId=$Plan.operationId;scope=$ExpectedScope;
        planSha256=$PlanHash;verified=($success -and $cleanupVerified);failureStage=$(if($success){$null}else{$failureStage});
        failureCode=$failureCode;
        cleanupVerified=$cleanupVerified;independentExpirySeconds=3300;snapshotReads=$ctx.SnapshotReads;shareReads=$ctx.ShareReads;
        snapshotInputLoads=$ctx.SnapshotLoads;shareInputLoads=$ctx.ShareLoads;
        shareSubmissions=$ctx.ShareSubmissions;forceRestoreClaimed=$ctx.ForceClaimed;targetRootClaimed=$ctx.RootClaimed;
        probeTokenClaimed=$ctx.TokenClaimed;nonCommandSignatureClaimed=$ctx.SignatureClaimed;sourceProviderApiCalls=0;
        productionTokensIssued=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
    $json=$proof|ConvertTo-Json -Compress
    foreach($canary in $script:credentialCanaries){Assert-ProviderCondition ($canary.Length -lt 12 -or
        -not $json.Contains($canary,[StringComparison]::Ordinal)) 'proof-canary'}
    $script:credentialCanaries.Clear()
    return $proof
}
