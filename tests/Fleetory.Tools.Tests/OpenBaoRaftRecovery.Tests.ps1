#requires -Version 7.3
# Disposable, synthetic OpenBao Raft recovery acceptance. Never targets operator state.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
& (Join-Path $PSScriptRoot 'OpenBaoTargetCredential.Tests.ps1')
& (Join-Path $PSScriptRoot 'ProviderRecoveryTransport.Tests.ps1')
& (Join-Path $PSScriptRoot 'ProviderRecoveryController.Tests.ps1')
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$tlsFactory = Join-Path $PSScriptRoot 'PilotDisposableTls.ps1'
$image = 'ghcr.io/openbao/openbao:2.7.1@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf'
$digest = '6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf'
$session = [Guid]::NewGuid().ToString('D').ToLowerInvariant()
$records = [Collections.Generic.List[object]]::new()
$sourceId = $null
$targetId = $null
$material = $null
$sourceShare = $null
$sourceRoot = $null
$targetShare = $null
$targetRoot = $null
$signToken = $null
$snapshotToken = $null
$snapshot = $null
$sourceKey = $null
$restoredKey = $null
$expiredToken = $null
$script:credentialCanaries = [Collections.Generic.List[string]]::new()
$script:credentialRecoveryStage = 'not-started'
$script:lastForbiddenCode = 0
$script:credentialLeaseDiagnostic = $null
$controllerRecovery=$null
$stage = 'preflight'
$safeDetail = ''
$successJson = $null
$script:forceRestoreClaimed = $false
. (Join-Path $PSScriptRoot 'OpenBaoTargetCredential.ps1')
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

. (Join-Path $PSScriptRoot 'PilotNativeProcess.ps1')
. (Join-Path $repoRoot 'eng/pilot/ProviderRecoveryTransport.ps1')
function Invoke-Docker([string[]] $Arguments, [byte[]] $InputBytes = $null, [int] $TimeoutSeconds = 90, [switch] $AllowFailure) {
    if ($IsLinux) {
        $nativeResults = @(Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments)) $InputBytes $TimeoutSeconds)
    } else {
        $nativeResults = @(Invoke-NativeBytes 'docker' (@('--context','desktop-linux') + $Arguments) $InputBytes $TimeoutSeconds)
    }
    if ($nativeResults.Count -ne 1 -or $null -eq $nativeResults[0] -or $nativeResults[0] -is [array]) {
        $types = @($nativeResults | ForEach-Object { if ($null -eq $_) { 'null' } else { $_.GetType().Name } }) -join ','
        throw ('Native process result shape was invalid: count=' + $nativeResults.Count + ';types=' + $types)
    }
    $result = $nativeResults[0]
    if (-not $AllowFailure -and $result.ExitCode -ne 0) { throw 'Disposable container operation failed.' }
    return $result
}

$providerTransitKey='fleetory-recovery-fixture'
$providerAuditName='fixture-file'
. (Join-Path $repoRoot 'eng/pilot/ProviderRecoveryRuntime.ps1')

try {
    if (-not (Test-Path -LiteralPath $tlsFactory -PathType Leaf)) { throw 'Disposable TLS helper is missing.' }
    . $tlsFactory
    $material = New-PilotDisposableTlsMaterial
    $stage = 'image'
    $imageInspectArguments = @('image','inspect','--format','{{json .RepoDigests}}',$image)
    $imageCheck = Invoke-Docker $imageInspectArguments -AllowFailure
    if ($imageCheck.ExitCode -ne 0) {
        $null = Invoke-Docker @('pull',$image) -TimeoutSeconds 120
        $imageCheck = Invoke-Docker $imageInspectArguments
    }
    Assert-True ($imageCheck.Stdout -match [regex]::Escape($digest)) 'Pinned OpenBao image digest is not locally available.'
    $stage = 'create-source'
    $sourceId = New-Container 'source'
    $null = Assert-Owned $sourceId 'source'
    $stage = 'source-files'
    $rootBytes = [Text.Encoding]::UTF8.GetBytes($material.RootCertificatePem)
    $certBytes = [Text.Encoding]::UTF8.GetBytes($material.ServerCertificatePem)
    $keyBytes = [Text.Encoding]::UTF8.GetBytes($material.ServerPrivateKeyPem)
    foreach ($id in @($sourceId)) {
        Write-ContainerFile $id '/tmp/ca.pem' $rootBytes
        Write-ContainerFile $id '/tmp/server.crt' $certBytes
        Write-ContainerFile $id '/tmp/server.key' $keyBytes
    }
    $stage = 'source-start'
    Start-Bao $sourceId 'source'
    $stage = 'source-init'
    $initResult = Invoke-Bao $sourceId @('operator','init','-key-shares=1','-key-threshold=1','-format=json')
    $init = Get-Json $initResult.Stdout
    $sourceShare = [string]$init.unseal_keys_b64[0]
    $sourceRoot = [string]$init.root_token
    Assert-True ($sourceShare.Length -gt 16 -and $sourceRoot.Length -gt 16) 'Source initialization omitted synthetic credentials.'
    $stage = 'source-unseal-command'
    $null = Invoke-Unseal $sourceId $sourceShare
    $stage = 'source-active-state'
    $sourceStatus = Wait-Active $sourceId
    $sourceCluster = [string]$sourceStatus.cluster_id
    $sourceNode = Get-RaftNodeId $sourceId $sourceRoot
    Assert-True ($sourceCluster.Length -gt 8 -and $sourceNode -like 'source-*') 'Source cluster identity was invalid.'
    $stage = 'transit-setup'
    $null = Invoke-Bao $sourceId @('secrets','enable','transit') $sourceRoot
    $null = Invoke-Bao $sourceId @('write','transit/keys/fleetory-recovery-fixture','type=ecdsa-p256','exportable=false','allow_plaintext_backup=false') $sourceRoot
    $signerPolicy = "path `"transit/keys/fleetory-recovery-fixture`" { capabilities = [`"read`"] }`npath `"transit/sign/fleetory-recovery-fixture/sha2-256`" { capabilities = [`"update`"] }`npath `"auth/token/lookup-self`" { capabilities = [`"read`"] }"
    $snapshotPolicy = "path `"sys/storage/raft/snapshot`" { capabilities = [`"read`"] }`npath `"auth/token/lookup-self`" { capabilities = [`"read`"] }"
    $null = Invoke-Bao $sourceId @('policy','write','fixture-signer','-') $sourceRoot ([Text.Encoding]::UTF8.GetBytes($signerPolicy))
    $null = Invoke-Bao $sourceId @('policy','write','fixture-snapshot','-') $sourceRoot ([Text.Encoding]::UTF8.GetBytes($snapshotPolicy))
    $signerTokenResponse = Invoke-AuthenticatedJson $sourceId $sourceRoot @('write','-format=json','auth/token/create-orphan','policies=fixture-signer','no_default_policy=true','ttl=1h','explicit_max_ttl=1h','renewable=false')
    $signToken = [string]$signerTokenResponse.auth.client_token
    if (-not $signToken) { $signToken=[string]$signerTokenResponse.data.client_token }
    $snapshotTokenResponse = Invoke-AuthenticatedJson $sourceId $sourceRoot @('write','-format=json','auth/token/create-orphan','policies=fixture-snapshot','no_default_policy=true','ttl=1h','explicit_max_ttl=1h','renewable=false')
    $snapshotToken = [string]$snapshotTokenResponse.auth.client_token
    if (-not $snapshotToken) { $snapshotToken=[string]$snapshotTokenResponse.data.client_token }
    $sourceKey = Get-TransitPublic $sourceId $signToken
    $challenge = 'synthetic-raft-recovery-' + $session
    Assert-Signature $sourceId $signToken $sourceKey $challenge
    $signerBefore = Get-Data $sourceId $signToken @('read','-format=json','auth/token/lookup-self')
    $snapshotBefore = Get-Data $sourceId $snapshotToken @('read','-format=json','auth/token/lookup-self')
    $expiredResponse = Invoke-AuthenticatedJson $sourceId $sourceRoot @('write','-format=json','auth/token/create-orphan',
        'policies=fixture-signer','no_default_policy=true','ttl=20s','explicit_max_ttl=20s','renewable=false')
    $expiredToken = [string]$expiredResponse.auth.client_token
    $expiredBefore = Get-Data $sourceId $expiredToken @('read','-format=json','auth/token/lookup-self')
    Assert-True ($expiredBefore.ttl -gt 0 -and $expiredBefore.creation_ttl -eq 20 -and $expiredBefore.renewable -eq $false) 'Short source credential was not live before capture.'
    $stage = 'revoke-source-root'
    $null = Invoke-Bao $sourceId @('token','revoke','-self') $sourceRoot
    Assert-Forbidden $sourceId $sourceRoot @('read','transit/keys/fleetory-recovery-fixture') 'Revoked source root'
    Assert-Forbidden $sourceId $signToken @('write','transit/keys/forbidden-fixture','type=ecdsa-p256') 'Signer management policy'
    $stage = 'snapshot'
    $snapshotResult = Invoke-Bao $sourceId @('operator','raft','snapshot','save','/tmp/raft.snapshot') $snapshotToken -TimeoutSeconds 120
    Assert-True ($snapshotResult.ExitCode -eq 0) 'Raft snapshot save failed.'
    $snapshot = Get-SnapshotBytes $sourceId
    Assert-True ($snapshot.Length -ge 4096 -and $snapshot.Length -le 67108864) 'Raft snapshot size was outside the fixture bound.'
    Assert-True ([DateTimeOffset]::UtcNow -lt (ConvertTo-ProviderTimestamp $expiredBefore.expire_time)) 'Short credential expired before the snapshot was captured.'
    $trustedHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($snapshot)).ToLowerInvariant()
    Assert-SnapshotReference $snapshot $trustedHash
    $stage = 'tamper-and-target-ownership-guards'
    $tampered = [byte[]]$snapshot.Clone()
    $tampered[$tampered.Length-1] = $tampered[$tampered.Length-1] -bxor 1
    $truncated = [byte[]]$snapshot[0..($snapshot.Length - 2)]
    Assert-SnapshotReferenceRejects $tampered $trustedHash 'Byte-flipped snapshot'
    Assert-SnapshotReferenceRejects $truncated $trustedHash 'Truncated snapshot'
    Assert-SnapshotReferenceRejects $snapshot ('0' * 64) 'Wrong expected snapshot hash'
    try { $null=Assert-Owned $sourceId 'restore'; throw 'Source container was accepted as a restore target.' } catch { if ($_.Exception.Message -eq 'Source container was accepted as a restore target.') { throw } }
    $stage = 'create-fresh-target'
    $targetId = New-Container 'restore'
    $targetInfo = Assert-Owned $targetId 'restore'
    $stage = 'target-files-and-start'
    foreach ($path in @('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key')) {
        $bytes = switch ($path) { '/tmp/ca.pem' {$rootBytes} '/tmp/server.crt' {$certBytes} '/tmp/server.key' {$keyBytes} }
        Write-ContainerFile $targetId $path $bytes
    }
    Start-Bao $targetId 'restore'
    $stage = 'target-init'
    $targetInitResult = Invoke-Bao $targetId @('operator','init','-key-shares=1','-key-threshold=1','-format=json')
    $targetInit = Get-Json $targetInitResult.Stdout
    $targetShare = [string]$targetInit.unseal_keys_b64[0]
    $targetRoot = [string]$targetInit.root_token
    Assert-True ($targetShare -cne $sourceShare -and $targetRoot -cne $sourceRoot) 'Fresh target reused source bootstrap credentials.'
    $null = Invoke-Unseal $targetId $targetShare
    $targetStatus = Wait-Active $targetId
    $targetClusterBefore = [string]$targetStatus.cluster_id
    $targetNode = Get-RaftNodeId $targetId $targetRoot
    Assert-True ($targetClusterBefore -cne $sourceCluster -and $targetNode -like 'restore-*' -and $targetNode -cne $sourceNode) 'Fresh target identity was not distinct.'
    $stage = 'snapshot-integrity-before-restore'
    $recheckedHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($snapshot)).ToLowerInvariant()
    Assert-True ($recheckedHash -ceq $trustedHash) 'Retained snapshot hash changed before target transfer.'
    Write-ContainerFile $targetId '/tmp/raft.snapshot' $snapshot
    $copied = Get-SnapshotBytes $targetId
    Assert-SnapshotReference $copied $trustedHash
    $stage = 'normal-seal-mismatch-denial'
    $normal = Invoke-Bao $targetId @('operator','raft','snapshot','restore','/tmp/raft.snapshot') $targetRoot -AllowFailure
    $normalText = $normal.Stdout + "`n" + $normal.Stderr
    Assert-True ($normal.ExitCode -ne 0 -and $normalText -match '(?i)Code:\s*400' -and
        $normalText -match '(?i)(seal|shamir|unseal)') 'Normal restore did not explicitly reject the different seal with HTTP 400.'
    $stillUsable = Get-Status $targetId
    Assert-True ($stillUsable.initialized -eq $true -and $stillUsable.sealed -eq $false -and
        $stillUsable.cluster_id -ceq $targetClusterBefore) 'Normal restore denial damaged fresh bootstrap state.'
    Assert-SnapshotReference (Get-SnapshotBytes $targetId) $trustedHash
    $stage = 'fresh-target-force-restore'
    Assert-FreshTargetForForceRestore $targetId $targetClusterBefore
    $forced = Invoke-Bao $targetId @('operator','raft','snapshot','restore','-force','/tmp/raft.snapshot') $targetRoot -TimeoutSeconds 120 -AllowFailure
    Assert-True ($forced.ExitCode -eq 0) 'Fresh isolated target force restore failed.'
    $reuseRejected = $false
    try {
        Assert-FreshTargetForForceRestore $targetId $targetClusterBefore
        throw 'Reused restore target passed the one-use guard.'
    } catch {
        if ($_.Exception.Message -eq 'Reused restore target passed the one-use guard.') { throw }
        $reuseRejected = $true
    }
    Assert-True $reuseRejected 'The restore target reuse guard did not reject a second restore attempt.'
    $stage = 'restored-seal-proof'
    $sealedAfter = $false
    for ($try=0; $try -lt 40; $try++) {
        try { $postStatus=Get-Status $targetId; $sealedAfter=($postStatus.sealed -eq $true); if ($sealedAfter) { break } } catch { }
        Start-Sleep -Milliseconds 250
    }
    if (-not $sealedAfter) {
        $null = Invoke-Docker @('exec',$targetId,'/bin/busybox','killall','bao') -AllowFailure
        Start-Sleep -Milliseconds 400
        $null = Invoke-Docker @('exec','-d',$targetId,'/usr/bin/bao','server','-config=/tmp/openbao.hcl')
        for ($try=0; $try -lt 40; $try++) { try { $postStatus=Get-Status $targetId; if ($postStatus.sealed) { $sealedAfter=$true; break } } catch { }; Start-Sleep -Milliseconds 250 }
    }
    Assert-True $sealedAfter 'Restored Raft state did not seal for original-share verification.'
    $bootstrapUnseal = Invoke-Unseal $targetId $targetShare -AllowFailure
    $bootstrapUnsealText = $bootstrapUnseal.Stdout + "`n" + $bootstrapUnseal.Stderr
    Assert-True ($bootstrapUnseal.ExitCode -ne 0 -and $bootstrapUnsealText -match '(?i)Code:\s*400' -and
        (Get-Status $targetId).sealed -eq $true) 'Fresh bootstrap share was not explicitly rejected with HTTP 400 while restored state stayed sealed.'
    $originalUnseal = Invoke-Unseal $targetId $sourceShare -AllowFailure
    Assert-True ($originalUnseal.ExitCode -eq 0) 'Original fixture share did not unseal restored state.'
    $restoredStatus = Wait-Active $targetId
    Assert-True ([string]$restoredStatus.cluster_id -ceq $sourceCluster) 'Restore did not preserve source cluster identity.'
    $stage = 'restored-authorization-and-key-proof'
    Assert-Forbidden $targetId $sourceRoot @('read','transit/keys/fleetory-recovery-fixture') 'Revoked source root after restore'
    Assert-Forbidden $targetId $targetRoot @('read','transit/keys/fleetory-recovery-fixture') 'Fresh bootstrap root after restore'
    Assert-Forbidden $targetId $signToken @('write','transit/keys/forbidden-fixture','type=ecdsa-p256') 'Restored signer management policy'
    $restoredKey = Get-TransitPublic $targetId $signToken
    Assert-True ([Security.Cryptography.CryptographicOperations]::FixedTimeEquals($restoredKey.Spki,$sourceKey.Spki) -and $restoredKey.Hash -ceq $sourceKey.Hash -and $restoredKey.Version -eq $sourceKey.Version -and $restoredKey.Flags -ceq $sourceKey.Flags) 'Restored Transit key differs from source public key or policy flags.'
    Assert-Signature $targetId $signToken $restoredKey ($challenge + '-after-restore-' + [Guid]::NewGuid().ToString('N'))
    $signerAfter = Get-Data $targetId $signToken @('read','-format=json','auth/token/lookup-self')
    $snapshotAfter = Get-Data $targetId $snapshotToken @('read','-format=json','auth/token/lookup-self')
    foreach ($pair in @(@($signerBefore,$signerAfter),@($snapshotBefore,$snapshotAfter))) {
        Assert-True ($pair[0].id -ceq $pair[1].id -and $pair[0].accessor -ceq $pair[1].accessor -and
            $pair[0].creation_time -ceq $pair[1].creation_time -and $pair[0].expire_time -ceq $pair[1].expire_time -and
            [int64]$pair[1].ttl -le [int64]$pair[0].ttl) 'Restored orphan token identity or lifetime changed.'
    }
    $stage = 'target-credential-ownership-refusals'
    $wrongRoleDenied = $wrongIdDenied = $false
    try { Assert-RecoveryCredentialTarget $sourceId 'source' }
    catch { $wrongRoleDenied = $_.Exception.Message -ceq 'Credential recovery requires the already-restored fixture target.' }
    try { Assert-RecoveryCredentialTarget $sourceId 'restore' }
    catch { $wrongIdDenied = $_.Exception.Message -match '^Container isolation checks failed: .*roleAndSession' }
    Assert-True ($wrongRoleDenied -and $wrongIdDenied) 'Synthetic source was accepted as a credential-recovery target.'
    $stage = 'expired-and-fresh-target-credential-proof'
    $credentialRecovery = Test-RestoredTargetCredential $targetId $sourceId $sourceCluster $sourceShare $expiredToken $expiredBefore $restoredKey $challenge
    $stage = 'audit-proof'
    $sourceAudit = Invoke-Docker @('exec',$sourceId,'/bin/busybox','stat','-c','%a:%u:%g','/openbao/data/audit.log')
    $targetAudit = Invoke-Docker @('exec',$targetId,'/bin/busybox','stat','-c','%a:%u:%g','/openbao/data/audit.log')
    $sourceAuditMode = $sourceAudit.Stdout.Trim()
    $targetAuditMode = $targetAudit.Stdout.Trim()
    Assert-True ($sourceAudit.ExitCode -eq 0 -and $sourceAuditMode -match '^600:100:1000$' -and
        $targetAudit.ExitCode -eq 0 -and $targetAuditMode -match '^600:100:1000$') 'Declarative file audit was not active on source and restore with private permissions.'
    $stage = 'native-controller'
    . (Join-Path $repoRoot 'eng/pilot/ProviderRecoveryController.ps1')
    . (Join-Path $PSScriptRoot 'ProviderRecoveryFixture.ps1')
    $controllerFixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('fleetory-controller-native-'+[Guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($controllerFixtureRoot)
    try {
        $controllerFixtureConfig=Join-Path $controllerFixtureRoot 'empty-docker-config'
        $null=[IO.Directory]::CreateDirectory($controllerFixtureConfig)
        $controllerFixturePlan=New-ControllerFixturePlan $controllerFixtureRoot $sourceId
        $controllerFixturePlan.clusterId=$sourceCluster
        $controllerFixturePlan.publicSpkiSha256=$sourceKey.Hash
        $controllerFixturePlan.snapshot.bytes=$snapshot.Length
        $controllerFixturePlan.snapshot.sha256=$trustedHash
        $controllerFixturePlan.sourceContainerName=$records[0].Name
        $controllerFixtureHash=Get-ControllerFixtureHash $controllerFixturePlan
        $controllerFixtureGrant=New-ControllerFixtureGrant $controllerFixturePlan $controllerFixtureHash
        $controllerFixtureSnapshotInput=[byte[]]$snapshot.Clone()
        $controllerFixtureShareInput=[Text.Encoding]::UTF8.GetBytes($sourceShare)
        $controllerFixtureReader={param($kind,$reference)
            if($kind -ceq 'snapshot'){return ,$controllerFixtureSnapshotInput}
            if($kind -ceq 'share'){$script:controllerFixtureShareWasRead=$true;return ,$controllerFixtureShareInput}
            throw 'Unknown generated fixture slot.'
        }
        $controllerFixtureTransport={param($request)
            if($request.Kind -ceq 'host-preflight'){
                return New-ControllerFixtureResult ("1048576`n"+[DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
            }
            $reply=if($IsLinux){
                Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $request.Arguments)) $request.InputBytes $request.TimeoutSeconds
            }else{
                Invoke-NativeBytes 'docker' (@('--config',$controllerFixtureConfig,'--host','npipe:////./pipe/dockerDesktopLinuxEngine')+$request.Arguments) $request.InputBytes $request.TimeoutSeconds
            }
            if($script:controllerFixtureDisconnectAfterShare -and $script:controllerFixtureShareWasRead -and
                $request.Arguments -ccontains 'sys/unseal'){
                $script:controllerFixtureDisconnectAfterShare=$false
                throw 'Generated transport response lost after retained-fixture unseal.'
            }
            return $reply
        }
        $script:controllerFixtureShareWasRead=$false
        $script:controllerFixtureDisconnectAfterShare=$false
        $controllerFixtureOldCanaries=$script:credentialCanaries
        $controllerRecovery=Invoke-ProviderRecoveryController $controllerFixturePlan $controllerFixtureGrant $controllerFixtureHash $controllerFixtureRoot $controllerFixtureTransport $controllerFixtureReader 'synthetic-fixture'
        $script:credentialCanaries=$controllerFixtureOldCanaries
        if(-not $controllerRecovery.verified){
            $safeDetail=($controllerRecovery|ConvertTo-Json -Compress)
            throw 'Generated controller native acceptance failed.'
        }
        $controllerFixturePlan.operationId=[Guid]::NewGuid().ToString('D')
        $controllerFixtureHash=Get-ControllerFixtureHash $controllerFixturePlan
        $controllerFixtureGrant=New-ControllerFixtureGrant $controllerFixturePlan $controllerFixtureHash
        $script:controllerFixtureShareWasRead=$false
        $script:controllerFixtureDisconnectAfterShare=$true
        $controllerInterrupted=Invoke-ProviderRecoveryController $controllerFixturePlan $controllerFixtureGrant $controllerFixtureHash $controllerFixtureRoot $controllerFixtureTransport $controllerFixtureReader 'synthetic-fixture'
        $script:credentialCanaries=$controllerFixtureOldCanaries
        Assert-True (-not $controllerInterrupted.verified -and $controllerInterrupted.cleanupVerified -and
            $controllerInterrupted.shareReads -eq 1 -and $controllerInterrupted.shareSubmissions -eq 1 -and
            -not $controllerInterrupted.targetRootClaimed) 'Interrupted generated target was not safely removed.'
    }
    finally {
        $controllerFixtureSnapshotInput=$controllerFixtureShareInput=$null
        foreach($file in [IO.Directory]::EnumerateFiles($controllerFixtureRoot)){[IO.File]::Delete($file)}
        if([IO.Directory]::Exists($controllerFixtureConfig)){[IO.Directory]::Delete($controllerFixtureConfig)}
        [IO.Directory]::Delete($controllerFixtureRoot)
    }
    $stage = 'complete'
    $successJson = [pscustomobject]@{
        schema = 'fleetory.openbao-raft-recovery.v1'
        verified = $true
        imageDigest = $digest
        snapshotBytes = $snapshot.Length
        snapshotSha256 = $trustedHash
        sourceClusterId = $sourceCluster
        restoredClusterId = [string]$restoredStatus.cluster_id
        publicSpkiSha256 = $restoredKey.Hash
        transitKeyVersion = $restoredKey.Version
        transitNonExportable = $true
        plaintextBackupDisabled = $true
        freshSignatureVerified = $true
        oldShareAccepted = $true
        freshBootstrapShareRejected = $true
        revokedSourceRootDenied403 = $true
        freshBootstrapRootDenied403 = $true
        signerManagementDenied403 = $true
        orphanTokenIdentityAndExpiryPreserved = $true
        tokenTtlNotIncreased = $true
        distinctNodeIds = $true
        sourceAuditMode = $sourceAuditMode
        targetAuditMode = $targetAuditMode
        snapshotExcludesAuditLog = $true
        restoreForceAfterExplicitNormalSeal400 = $true
        restoreRetryRejected = $reuseRejected
        network = 'none'
        publishedPorts = 0
        hostMounts = 0
        independentTargetExpirySeconds = 3300
        targetAutoRemove = $true
        linuxRemoteShellTransport = $IsLinux
        humanApprovalVerified = $false
        productionCustodyVerified = $false
        shortCredentialCapturedWhileLive = $true
        recoveryWindowSourceRoleAndIdRefused = $true
        targetCredentialRecovery = $credentialRecovery
        controllerRecovery = $controllerRecovery
        controllerInterrupted = $controllerInterrupted
        credentialCanariesAbsent = $true
    } | ConvertTo-Json -Compress
    foreach ($secret in (@($sourceShare,$sourceRoot,$targetShare,$targetRoot,$signToken,$snapshotToken,$expiredToken) + $script:credentialCanaries.ToArray())) {
        if ($secret.Length -gt 12 -and $successJson.Contains($secret,[StringComparison]::Ordinal)) { throw 'Synthetic credential appeared in the public result.' }
    }
}
catch {
    $message = [string]$_.Exception.Message
    $safeDetail = 'type=' + $_.Exception.GetType().Name + ';line=' + [string]$_.InvocationInfo.ScriptLineNumber
    if ($stage -ceq 'native-controller' -and $null -ne $controllerRecovery) { $safeDetail = ($controllerRecovery|ConvertTo-Json -Compress) }
    if ($stage -ceq 'expired-and-fresh-target-credential-proof' -and $script:credentialRecoveryStage -cmatch '^[a-z-]{1,64}$') {
        $safeDetail += ';credential=' + $script:credentialRecoveryStage + ';lastDenialCode=' + $script:lastForbiddenCode
        if ($null -ne $script:credentialLeaseDiagnostic) { $safeDetail += ';leaseMetadata=' + ($script:credentialLeaseDiagnostic | ConvertTo-Json -Compress) }
    }
    if ($message -match '^Container isolation checks failed: ([A-Za-z,]+)$') { $safeDetail = 'isolation=' + $Matches[1] }
    if ($message -match '^OpenBao active state mismatch: ([A-Za-z0-9=;]+)$') { $safeDetail = 'status=' + $Matches[1] }
    if ($message -match '^Native process result shape was invalid: (count=[0-9]+;types=[A-Za-z0-9.,]+)$') { $safeDetail = $Matches[1] }
    switch -CaseSensitive ($message) {
        'Pinned OpenBao image digest is not locally available.' { $safeDetail='image=digest-mismatch' }
        'Native process did not start.' { $safeDetail='process=start-failed' }
        'Native process deadline exceeded.' { $safeDetail='process=deadline' }
        'Bounded native process I/O failed.' { $safeDetail='process=bounded-io' }
        'Disposable container operation failed.' { $safeDetail='docker=command-failed' }
        'OpenBao returned an invalid JSON response.' { $safeDetail='response=invalid-json' }
    }
    [Console]::Error.WriteLine("Synthetic OpenBao Raft recovery failed at stage=$stage $safeDetail. No credential or raw response is emitted.")
    exit 1
}finally {
    $sourceShare=$null; $sourceRoot=$null; $targetShare=$null; $targetRoot=$null
    if ($null -ne $sourceKey) { $sourceKey.Key.Dispose() }
    if ($null -ne $restoredKey) { $restoredKey.Key.Dispose() }
    $signToken=$null; $snapshotToken=$null; $snapshot=$null; $expiredToken=$null
    $script:credentialCanaries.Clear()
    if ($null -ne $material) {
        $material.RootCertificatePem=$null; $material.ServerCertificatePem=$null; $material.ServerPrivateKeyPem=$null
    }
    Remove-OwnedContainers
}
if ($null -ne $successJson) { [Console]::Out.WriteLine($successJson) }
