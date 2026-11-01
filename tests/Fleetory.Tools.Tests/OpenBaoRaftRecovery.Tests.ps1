#requires -Version 7.3
# Disposable, synthetic OpenBao Raft recovery acceptance. Never targets operator state.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
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
$stage = 'preflight'
$safeDetail = ''
$successJson = $null
$script:forceRestoreClaimed = $false
$captureStreamScript = Join-Path $PSScriptRoot 'PilotCaptureStream.ps1'
. $captureStreamScript
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-NativeBytes([string] $Executable, [string[]] $Arguments, [byte[]] $InputBytes = $null, [int] $TimeoutSeconds = 90) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $true
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 120) { throw 'Native process timeout is outside bounds.' }
    foreach ($argument in $Arguments) { $null = $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = [Fleetory.Tests.PilotCaptureStream]::new(67108864)
    $stderr = [Fleetory.Tests.PilotCaptureStream]::new(1048576)
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $processStarted = $false
    $stdoutTask = $null
    $stderrTask = $null
    $writeTask = $null
    try {
        if (-not $process.Start()) { throw 'Native process did not start.' }
        $processStarted = $true
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
        if ($null -ne $InputBytes -and $InputBytes.Length -gt 0) {
            $writeTask = $process.StandardInput.BaseStream.WriteAsync($InputBytes,0,$InputBytes.Length)
            $inputClosed = $false
        } else {
            $process.StandardInput.Close()
            $writeTask = [Threading.Tasks.Task]::CompletedTask
            $inputClosed = $true
        }
        while ($true) {
            if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Native process deadline exceeded.' }
            if ($stdoutTask.IsFaulted -or $stderrTask.IsFaulted -or $writeTask.IsFaulted) { throw 'Bounded native process I/O failed.' }
            if ($writeTask.IsCompleted -and -not $inputClosed) {
                $null = $writeTask.GetAwaiter().GetResult()
                $process.StandardInput.Close()
                $inputClosed = $true
            }
            if ($process.HasExited -and $stdoutTask.IsCompleted -and $stderrTask.IsCompleted -and $writeTask.IsCompleted) { break }
            Start-Sleep -Milliseconds 20
        }
        $null = $stdoutTask.GetAwaiter().GetResult()
        $null = $stderrTask.GetAwaiter().GetResult()
        $null = $writeTask.GetAwaiter().GetResult()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdoutBytes = $stdout.ToArray()
            StderrBytes = $stderr.ToArray()
            Stdout = [Text.Encoding]::UTF8.GetString($stdout.ToArray())
            Stderr = [Text.Encoding]::UTF8.GetString($stderr.ToArray())
        }
    }
    finally {
        if ($processStarted -and -not $process.HasExited) {
            try { $process.Kill($true) } catch { }
            try { $null = $process.WaitForExit(2000) } catch { }
        }
        foreach ($task in @($stdoutTask,$stderrTask,$writeTask)) {
            if ($null -ne $task -and -not $task.IsCompleted) { try { $null = $task.Wait(2000) } catch { } }
        }
        $stopwatch.Stop()
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
}
function Invoke-Docker([string[]] $Arguments, [byte[]] $InputBytes = $null, [int] $TimeoutSeconds = 90, [switch] $AllowFailure) {
    $nativeResults = @(Invoke-NativeBytes 'docker' $Arguments $InputBytes $TimeoutSeconds)
    if ($nativeResults.Count -ne 1 -or $null -eq $nativeResults[0] -or $nativeResults[0] -is [array]) {
        $types = @($nativeResults | ForEach-Object { if ($null -eq $_) { 'null' } else { $_.GetType().Name } }) -join ','
        throw ('Native process result shape was invalid: count=' + $nativeResults.Count + ';types=' + $types)
    }
    $result = $nativeResults[0]
    if (-not $AllowFailure -and $result.ExitCode -ne 0) { throw 'Disposable container operation failed.' }
    return $result
}

function Invoke-Bao([string] $ContainerId, [string[]] $BaoArguments, [string] $Token = $null,
    [byte[]] $Body = $null, [int] $TimeoutSeconds = 90, [switch] $AllowFailure) {
    if ($null -eq $Token) {
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
    $arguments = @('run','-d','--name',$name,'--label',"com.fleetory.openbao-recovery.role=$Role",
        '--label',"com.fleetory.openbao-recovery.session=$session",'--network','none','--user','100:1000',
        '--read-only','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=32m,uid=100,gid=1000,mode=0700',
        '--tmpfs','/openbao/data:rw,noexec,nosuid,nodev,size=256m,uid=100,gid=1000,mode=0700',
        '--memory','384m','--cpus','0.30','--pids-limit','128','--cap-drop','ALL',
        '--security-opt','no-new-privileges:true','-e','BAO_ADDR=https://127.0.0.1:8200',
        '-e','BAO_CACERT=/tmp/ca.pem','--entrypoint','/bin/sh',$image,'-c','exec /bin/busybox sleep 36000')
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

function Start-Bao([string] $Id, [string] $Role) {
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
  tls_cert_file = "/tmp/server.crt"
  tls_key_file = "/tmp/server.key"
}
audit "file" "fixture-file" {
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
    Assert-True ($result.ExitCode -ne 0 -and $text -match '(?i)Code:\s*403') "$Label did not return explicit HTTP 403."
}

function Get-TransitPublic([string] $Id, [string] $Token) {
    $data = Get-Data $Id $Token @('read','-format=json','transit/keys/fleetory-recovery-fixture')
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
    $arguments = @('write','-format=json','transit/sign/fleetory-recovery-fixture/sha2-256',
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
try {
    if (-not (Test-Path -LiteralPath $tlsFactory -PathType Leaf)) { throw 'Disposable TLS helper is missing.' }
    . $tlsFactory
    $material = New-PilotDisposableTlsMaterial
    $stage = 'image'
    $imageCheck = Invoke-Docker @('image','inspect','--format','{{json .RepoDigests}}',$image)
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
    $stage = 'revoke-source-root'
    $null = Invoke-Bao $sourceId @('token','revoke','-self') $sourceRoot
    Assert-Forbidden $sourceId $sourceRoot @('read','transit/keys/fleetory-recovery-fixture') 'Revoked source root'
    Assert-Forbidden $sourceId $signToken @('write','transit/keys/forbidden-fixture','type=ecdsa-p256') 'Signer management policy'
    $stage = 'snapshot'
    $snapshotResult = Invoke-Bao $sourceId @('operator','raft','snapshot','save','/tmp/raft.snapshot') $snapshotToken -TimeoutSeconds 120
    Assert-True ($snapshotResult.ExitCode -eq 0) 'Raft snapshot save failed.'
    $snapshot = Get-SnapshotBytes $sourceId
    Assert-True ($snapshot.Length -ge 4096 -and $snapshot.Length -le 67108864) 'Raft snapshot size was outside the fixture bound.'
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
    $stage = 'audit-proof'
    $sourceAudit = Invoke-Docker @('exec',$sourceId,'/bin/busybox','stat','-c','%a:%u:%g','/openbao/data/audit.log')
    $targetAudit = Invoke-Docker @('exec',$targetId,'/bin/busybox','stat','-c','%a:%u:%g','/openbao/data/audit.log')
    $sourceAuditMode = $sourceAudit.Stdout.Trim()
    $targetAuditMode = $targetAudit.Stdout.Trim()
    Assert-True ($sourceAudit.ExitCode -eq 0 -and $sourceAuditMode -match '^600:100:1000$' -and
        $targetAudit.ExitCode -eq 0 -and $targetAuditMode -match '^600:100:1000$') 'Declarative file audit was not active on source and restore with private permissions.'
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
        humanApprovalVerified = $false
        productionCustodyVerified = $false
    } | ConvertTo-Json -Compress
}
catch {
    $message = [string]$_.Exception.Message
    $safeDetail = 'type=' + $_.Exception.GetType().Name + ';line=' + [string]$_.InvocationInfo.ScriptLineNumber
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
    $signToken=$null; $snapshotToken=$null; $snapshot=$null
    if ($null -ne $material) {
        $material.RootCertificatePem=$null; $material.ServerCertificatePem=$null; $material.ServerPrivateKeyPem=$null
    }
    Remove-OwnedContainers
}
if ($null -ne $successJson) { [Console]::Out.WriteLine($successJson) }
