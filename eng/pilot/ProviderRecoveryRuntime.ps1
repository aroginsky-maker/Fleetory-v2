#requires -Version 7.3
# Shared native primitives; all Docker requests pass through the caller policy/transport.
function Invoke-Bao([string] $ContainerId, [string[]] $BaoArguments, [string] $Token = $null,
    [byte[]] $Body = $null, [int] $TimeoutSeconds = 90, [switch] $AllowFailure) {
    if ([string]::IsNullOrEmpty($Token)) {
        $prefix = if ($null -ne $Body) { @('exec','-i',$ContainerId,'/usr/bin/bao') } else { @('exec',$ContainerId,'/usr/bin/bao') }
        $cliProcessArguments = $prefix + $BaoArguments
        return Invoke-Docker $cliProcessArguments $Body $TimeoutSeconds -AllowFailure:$AllowFailure
    }
    $tokenPrefix = [Text.Encoding]::UTF8.GetBytes(([string]$Token + [char]10))
    $bodyLength = if ($null -eq $Body) { 0 } else { $Body.Length }
    $combined = [byte[]]::new($tokenPrefix.Length + $bodyLength)
    [Array]::Copy($tokenPrefix, 0, $combined, 0, $tokenPrefix.Length)
    if ($null -ne $Body -and $Body.Length -gt 0) { [Array]::Copy($Body, 0, $combined, $tokenPrefix.Length, $Body.Length) }
    $cliProcessArguments = @('exec','-i',$ContainerId,'/bin/sh','-c',
        'IFS= read -r t || exit 120; BAO_TOKEN="$t" exec /usr/bin/bao "$@"','bao') + $BaoArguments
    return Invoke-Docker $cliProcessArguments $combined $TimeoutSeconds -AllowFailure:$AllowFailure
}
function Get-Json([string] $Text) {
    try { return $Text | ConvertFrom-Json -AsHashtable -Depth 32 }
    catch { throw 'OpenBao returned an invalid JSON response.' }
}

function New-Container([string] $Role) {
    $name = 'fleetory-bao-' + $Role + '-' + $session.Replace('-', '')
    $record = [pscustomobject]@{ Id=$null; Name=$name; Role=$Role; StartedUtc=[DateTimeOffset]::UtcNow }
    $records.Add($record)
    $arguments = Get-ProviderContainerArguments $session $Role
    $result = Invoke-Docker $arguments
    $id = $result.Stdout.Trim()
    if ($id -notmatch '^[0-9a-f]{64}$') { throw 'Docker returned an invalid owned container identifier.' }
    $record.Id = $id
    return $id
}
function Assert-Owned([string] $Id, [string] $Role) {
    $result = Invoke-Docker @('inspect',$Id)
    $items = @(Get-Json $result.Stdout)
    Assert-True ($items.Count -eq 1) 'Owned container inspection was ambiguous.'
    $info = $items[0]
    $labels = $info['Config']['Labels']
    $tmpfs = $info['HostConfig']['Tmpfs']
    $tmpfsKeys = @($tmpfs.Keys | Sort-Object)
    $portBindings = @($info['HostConfig']['PortBindings'].Keys)
    $hostMounts = $info['HostConfig']['Mounts']
    $containerMounts = @($info['Mounts'])
    $securityOptions = @($info['HostConfig']['SecurityOpt'])
    $noNewPrivileges = $securityOptions -contains 'no-new-privileges' -or $securityOptions -contains 'no-new-privileges:true'
    $checks = [ordered]@{
        identity = $info['Id'] -eq $Id -and $info['Config']['Image'] -eq $image
        roleAndSession = $labels['com.fleetory.openbao-recovery.role'] -eq $Role -and $labels['com.fleetory.openbao-recovery.session'] -eq $session
        runtimeIdentity = $info['Config']['User'] -eq '100:1000'
        independentExpiry = $info['HostConfig']['AutoRemove'] -eq $true -and
            (@($info['Config']['Entrypoint']) -join '|') -ceq '/bin/sh' -and
            (@($info['Config']['Cmd']) -join '|') -ceq '-c|exec /bin/busybox sleep 3300'
        readonlyNetwork = $info['HostConfig']['ReadonlyRootfs'] -eq $true -and $info['HostConfig']['NetworkMode'] -eq 'none' -and $info['HostConfig']['Privileged'] -eq $false
        droppedCapabilities = @($info['HostConfig']['CapDrop'] | Where-Object { $_ -eq 'ALL' }).Count -eq 1
        namespaces = $info['HostConfig']['PidMode'] -eq '' -and $info['HostConfig']['IpcMode'] -eq 'private'
        noPublishedPorts = $portBindings.Count -eq 0
        noHostMounts = ($null -eq $hostMounts -or @($hostMounts).Count -eq 0) -and $containerMounts.Count -eq 0
        exactTmpfs = (($tmpfsKeys -join '|') -ceq '/openbao/data|/tmp')
        tmpfsFlags = $tmpfs['/tmp'] -match '(^|,)noexec(,|$)' -and $tmpfs['/tmp'] -match '(^|,)nosuid(,|$)' -and $tmpfs['/tmp'] -match '(^|,)nodev(,|$)' -and $tmpfs['/tmp'] -match '(^|,)uid=100(,|$)' -and $tmpfs['/tmp'] -match '(^|,)gid=1000(,|$)' -and $tmpfs['/tmp'] -match '(^|,)mode=0700(,|$)' -and
            $tmpfs['/openbao/data'] -match '(^|,)noexec(,|$)' -and $tmpfs['/openbao/data'] -match '(^|,)nosuid(,|$)' -and $tmpfs['/openbao/data'] -match '(^|,)nodev(,|$)' -and $tmpfs['/openbao/data'] -match '(^|,)uid=100(,|$)' -and $tmpfs['/openbao/data'] -match '(^|,)gid=1000(,|$)' -and $tmpfs['/openbao/data'] -match '(^|,)mode=0700(,|$)'
        noNewPrivileges = $noNewPrivileges
        resourceLimits = $info['HostConfig']['Memory'] -eq 402653184 -and $info['HostConfig']['NanoCpus'] -eq 300000000 -and $info['HostConfig']['PidsLimit'] -eq 128
    }
    $failures = @($checks.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key })
    if ($failures.Count -gt 0) { throw ('Container isolation checks failed: ' + ($failures -join ',')) }
    return $info
}
function Write-ContainerFile([string] $Id, [string] $Path, [byte[]] $Bytes) {
    $result = Invoke-Docker @('exec','-i',$Id,'/bin/sh','-c','umask 077; cat > "$1"','sh',$Path) $Bytes
    if ($result.ExitCode -ne 0) { throw 'Could not write synthetic container material.' }
}

function Start-Bao([string] $Id, [string] $Role, [switch] $RecoveryWindow) {
    if ($RecoveryWindow) { Assert-RecoveryCredentialTarget $Id $Role }
    $rootEndpointDisabled = if ($RecoveryWindow) { 'false' } else { 'true' }
    $node = $Role + '-' + $session
    $config = @"
ui = false
api_addr = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
disable_mlock = true
storage "raft" {
  path = "/openbao/data"
  node_id = "$node"
}
listener "tcp" {
  address = "127.0.0.1:8200"
  cluster_address = "127.0.0.1:8201"
  disable_unauthed_generate_root_endpoints = $rootEndpointDisabled
  tls_cert_file = "/tmp/server.crt"
  tls_key_file = "/tmp/server.key"
}
audit "file" "$providerAuditName" {
  options {
    file_path = "/openbao/data/audit.log"
    mode = "0600"
    log_raw = "false"
  }
}
"@
    Write-ContainerFile $Id '/tmp/openbao.hcl' ([Text.Encoding]::UTF8.GetBytes($config))
    $start = Invoke-Docker @('exec','-d',$Id,'/bin/sh','-c','/usr/bin/bao server -config=/tmp/openbao.hcl >/tmp/bao.log 2>&1')
    if ($start.ExitCode -ne 0) { throw 'OpenBao server process failed to start.' }
    for ($try=0; $try -lt 40; $try++) {
        $status = Invoke-Bao $Id @('status','-format=json') -AllowFailure
        if ($status.Stdout -match '"initialized"') { return }
        Start-Sleep -Milliseconds 250
    }
    throw 'OpenBao did not become ready.'
}

function Get-Status([string] $Id) {
    $result = Invoke-Bao $Id @('status','-format=json') -AllowFailure
    if ($result.Stdout -notmatch '^\s*\{') { throw 'OpenBao status is unavailable.' }
    return Get-Json $result.Stdout
}

function Wait-Active([string] $Id) {
    $status = $null
    for ($try=0; $try -lt 60; $try++) {
        $status = Get-Status $Id
        if ($status.initialized -eq $true -and $status.sealed -eq $false -and
            $status.ha_enabled -eq $true -and $status.leader_address -eq 'https://127.0.0.1:8200') { return $status }
        Start-Sleep -Milliseconds 300
    }
    $safeKeys = @($status.Keys | Sort-Object) -join ','
    $stateFlags = 'initialized=' + [string]$status.initialized + ';sealed=' + [string]$status.sealed + ';haEnabled=' + [string]$status.ha_enabled + ';leaderExpected=' + [string]($status.leader_address -ceq 'https://127.0.0.1:8200') + ';keys=' + $safeKeys
    throw ('OpenBao active state mismatch: ' + $stateFlags)
}
function Invoke-Unseal([string] $Id, [string] $Share, [switch] $AllowFailure) {
    $body = [Text.Encoding]::UTF8.GetBytes((@{ key=$Share } | ConvertTo-Json -Compress))
    return Invoke-Bao $Id @('write','-format=json','sys/unseal','-') -Body $body -AllowFailure:$AllowFailure
}

function Get-RaftNodeId([string] $Id, [string] $Token) {
    $response = Invoke-AuthenticatedJson $Id $Token @('operator','raft','list-peers','-format=json')
    $servers = @()
    if ($null -ne $response.data.config -and $null -ne $response.data.config.servers) {
        $servers = @($response.data.config.servers)
    } elseif ($null -ne $response.data.servers) {
        $servers = @($response.data.servers)
    }
    $leaders = @($servers | Where-Object { $_.leader -eq $true })
    if ($leaders.Count -ne 1) { throw 'Raft peer listing did not identify exactly one leader.' }
    $nodeId = [string]$leaders[0].node_id
    if (-not $nodeId) { $nodeId=[string]$leaders[0].id }
    if (-not $nodeId) { $nodeId=[string]$leaders[0].server_id }
    if (-not $nodeId) { throw 'Raft peer listing omitted the node ID.' }
    return $nodeId
}
function Invoke-AuthenticatedJson([string] $Id, [string] $Token, [string[]] $Arguments, [int] $TimeoutSeconds = 90) {
    $result = Invoke-Bao $Id $Arguments $Token -TimeoutSeconds $TimeoutSeconds
    return Get-Json $result.Stdout
}

function Get-Data([string] $Id, [string] $Token, [string[]] $Arguments) {
    $response = Invoke-AuthenticatedJson $Id $Token $Arguments
    if ($null -eq $response.data) { throw 'Authenticated OpenBao response omitted data.' }
    return $response.data
}

function Assert-Forbidden([string] $Id, [string] $Token, [string[]] $Arguments, [string] $Label) {
    $result = Invoke-Bao $Id $Arguments $Token -AllowFailure
    $text = $result.Stdout + "`n" + $result.Stderr
    $script:lastForbiddenCode = if ($text -match '(?i)Code:\s*([0-9]{3})') { [int]$Matches[1] } else { 0 }
    Assert-True ($result.ExitCode -ne 0 -and $text -match '(?i)Code:\s*403') "$Label did not return explicit HTTP 403."
}

function Get-TransitPublic([string] $Id, [string] $Token) {
    $data = Get-Data $Id $Token @('read','-format=json',('transit/keys/'+$providerTransitKey))
    Assert-True ($data.type -eq 'ecdsa-p256' -and $data.exportable -eq $false -and
        $data.allow_plaintext_backup -eq $false -and $data.latest_version -eq 1) 'Transit key flags or version changed.'
    $pem = [string]$data.keys.'1'.public_key
    $key = [Security.Cryptography.ECDsa]::Create()
    try {
        $key.ImportFromPem($pem)
        $spki = $key.ExportSubjectPublicKeyInfo()
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($spki)).ToLowerInvariant()
        return [pscustomobject]@{ Key=$key; Spki=$spki; Hash=$hash; Version=[int]$data.latest_version; Flags=($data.type+':'+$data.exportable+':'+$data.allow_plaintext_backup) }
    }
    catch { $key.Dispose(); throw 'Transit public key could not be parsed.' }
}

function Assert-Signature([string] $Id, [string] $Token, $Public, [string] $Challenge) {
    $challengeBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Challenge))
    $arguments = @('write','-format=json',('transit/sign/'+$providerTransitKey+'/sha2-256'),
        ('input=' + $challengeBase64),'key_version=1','marshaling_algorithm=jws','prehashed=false')
    $response = Invoke-AuthenticatedJson $Id $Token $arguments
    $signatureParts = ([string]$response.data.signature).Split(':')
    Assert-True ($signatureParts.Count -eq 3 -and $signatureParts[0] -ceq 'vault' -and $signatureParts[1] -ceq 'v1') 'Transit did not return the expected JWS signature format.'
    $normalized = $signatureParts[2].Replace('-','+').Replace('_','/')
    while (($normalized.Length % 4) -ne 0) { $normalized += '=' }
    $signatureBytes = [Convert]::FromBase64String($normalized)
    Assert-True ($signatureBytes.Length -eq 64) 'Transit JWS signature did not contain a P-256 P1363 signature.'
    $verifier = [Security.Cryptography.ECDsa]::Create()
    try {
        $bytesRead = 0
        $verifier.ImportSubjectPublicKeyInfo($Public.Spki,[ref]$bytesRead)
        $valid = $verifier.VerifyData([Text.Encoding]::UTF8.GetBytes($Challenge),$signatureBytes,
            [Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        Assert-True $valid 'Transit signature did not verify under the retained public key.'
    }
    finally { $verifier.Dispose() }
}
function Assert-SnapshotReference([byte[]] $Bytes, [string] $ExpectedHash) {
    if ($ExpectedHash -notmatch '^[0-9a-f]{64}$' -or $Bytes.Length -lt 4096 -or $Bytes.Length -gt 67108864) {
        throw 'Snapshot reference is outside its expected bounds.'
    }
    $actualHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
    if (-not [string]::Equals($actualHash,$ExpectedHash,[StringComparison]::Ordinal)) {
        throw 'Snapshot bytes did not match the retained hash.'
    }
}

function Assert-SnapshotReferenceRejects([byte[]] $Bytes, [string] $ExpectedHash, [string] $Label) {
    $rejected = $false
    try { Assert-SnapshotReference $Bytes $ExpectedHash } catch { $rejected = $true }
    Assert-True $rejected "$Label was accepted by the snapshot reference guard."
}
function Assert-FreshTargetForForceRestore([string] $Id, [string] $BootstrapClusterId) {
    if ($script:forceRestoreClaimed) { throw 'Restore target has already been used.' }
    $null = Assert-Owned $Id 'restore'
    $status = Get-Status $Id
    if ($status.initialized -ne $true -or $status.sealed -ne $false -or $status.cluster_id -cne $BootstrapClusterId) {
        throw 'Restore target is not the expected fresh bootstrap cluster.'
    }
    $script:forceRestoreClaimed = $true
}
function Get-SnapshotBytes([string] $Id) {
    $result = Invoke-Docker @('exec',$Id,'/bin/busybox','cat','/tmp/raft.snapshot')
    return ,$result.StdoutBytes
}

function Remove-OwnedContainers {
    $failures = [Collections.Generic.List[string]]::new()
    for ($recordIndex = $records.Count - 1; $recordIndex -ge 0; $recordIndex--) {
        $record = $records[$recordIndex]
        $inspectTarget = if ($record.Id) { $record.Id } else { $record.Name }
        $inspection = Invoke-Docker @('inspect',$inspectTarget) -AllowFailure
        if ($inspection.ExitCode -ne 0 -and -not $inspection.Stdout) {
            if (($inspection.Stderr + $inspection.Stdout) -match '(?i)(no such object|no such container|not found)') { continue }
            $failures.Add($record.Role + ':inspect-failed')
            continue
        }
        try {
            $items = @(Get-Json $inspection.Stdout)
            if ($items.Count -ne 1) { throw 'inspect-count' }
            $info = $items[0]
            $labels = $info.Config.Labels
            $metadataChecks = [ordered]@{
                id = $info.Id -match '^[0-9a-f]{64}$' -and (-not $record.Id -or $info.Id -ceq $record.Id)
                name = $info.Name -ceq ('/' + $record.Name)
                image = $info.Config.Image -ceq $image
                role = $labels['com.fleetory.openbao-recovery.role'] -ceq $record.Role
                session = $labels['com.fleetory.openbao-recovery.session'] -ceq $session
            }
            if ($info.Created -is [DateTimeOffset]) {
                $createdUtc = $info.Created
            } elseif ($info.Created -is [DateTime]) {
                $createdUtc = [DateTimeOffset]::new($info.Created)
            } else {
                $createdUtc = [DateTimeOffset]::Parse([string]$info.Created,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
            }
            $metadataChecks.createdAfterFixture = $createdUtc -ge $record.StartedUtc
            $failedChecks = @($metadataChecks.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key })
            if ($failedChecks.Count -gt 0) {
                $failures.Add($record.Role + ':' + ($failedChecks -join ','))
                continue
            }
            $record.Id = [string]$info.Id
            $removed = Invoke-Docker @('rm','-f','-v',$record.Id) -AllowFailure
            if ($removed.ExitCode -ne 0) { $failures.Add($record.Role + ':remove-failed') }
        } catch {
            $failures.Add($record.Role + ':validation-' + $_.Exception.GetType().Name)
        }
    }
    if ($failures.Count -gt 0) { throw ('Owned synthetic container cleanup could not be verified: ' + ($failures -join ';')) }
}
