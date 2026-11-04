#requires -Version 7.3
# Generated public pins and synthetic bytes only. No SSH connection or private key read.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'PilotNativeProcess.ps1')
. (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'eng/pilot/ProviderRecoveryTransport.ps1')
function Assert-Transport([bool] $Condition, [string] $Label) {
    if (-not $Condition) { throw ('Provider transport assertion failed: ' + $Label) }
}
$script:transportRefusals = 0
function Assert-TransportRefusal([scriptblock] $Action, [string] $Expected) {
    try { $null = & $Action }
    catch {
        if ($_.Exception.Message -cne $Expected) { throw 'Provider transport refusal had an unexpected diagnostic.' }
        $script:transportRefusals++
        return
    }
    throw 'Unsafe provider transport request was accepted.'
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('fleetory-public-transport-' + [Guid]::NewGuid().ToString('N'))
try {
$null = [IO.Directory]::CreateDirectory($testRoot)
$ledger = Join-Path $testRoot 'public known hosts'
$identity = Join-Path $testRoot 'absent private identity'
$address = '192.0.2.17'
$header = [Convert]::FromHexString('0000000b7373682d6564323535313900000020')
$keyBytes = [byte[]]::new(51)
[Array]::Copy($header,$keyBytes,$header.Length)
[Array]::Copy([Security.Cryptography.RandomNumberGenerator]::GetBytes(32),0,$keyBytes,19,32)
$keyText = [Convert]::ToBase64String($keyBytes)
$fingerprint = 'SHA256:' + [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData($keyBytes)).TrimEnd('=')
$line = $address + ' ssh-ed25519 ' + $keyText + "`n"
$encoding = [Text.UTF8Encoding]::new($false)
function Set-PublicLedger([string] $Text) {
    [IO.File]::WriteAllText($ledger,$Text,$encoding)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($Text))).ToLowerInvariant()
}
$sha = Set-PublicLedger $line
$pin = @{Address=$address;KnownHostsFile=$ledger;KnownHostsSha256=$sha;HostFingerprint=$fingerprint;IdentityFile=$identity}
$pwsh = Join-Path $PSHOME $(if($IsWindows){'pwsh.exe'}else{'pwsh'})
$session = [Guid]::NewGuid().ToString('D')
    $run = @(Get-ProviderContainerArguments $session 'restore')
    Assert-Transport ($run[0] -ceq 'run' -and $run[1] -ceq '--rm' -and
        $run[-1] -ceq 'exec /bin/busybox sleep 3300' -and $run -ccontains 'none' -and
        $run -ccontains '100:1000' -and $run -ccontains '--read-only') 'independent expiry and isolated run'
    Assert-TransportRefusal { Get-ProviderContainerArguments $session 'live' } 'Invalid disposable provider identity.'
    Assert-TransportRefusal { Get-ProviderContainerArguments '../source' 'restore' } 'Invalid disposable provider identity.'
    Assert-TransportRefusal { ConvertTo-ProviderShellCommand @() } 'Public argument count is outside bounds.'
    Assert-TransportRefusal { ConvertTo-ProviderShellCommand (@('x')*257) } 'Public argument count is outside bounds.'
    foreach ($unsafe in @("a`nb","a`0b",('a'*16385))) {
        Assert-TransportRefusal { ConvertTo-ProviderShellCommand @($unsafe) } 'Public argument is outside bounds.'
    }
    Assert-TransportRefusal { ConvertTo-ProviderShellCommand @(("'"*16384),("'"*16384)) } 'Public command is outside bounds.'
    $ssh = @(Get-ProviderSshArguments @pin -PublicDockerArguments @('inspect','not-a-live-target'))
    Assert-Transport ($ssh[-1].Contains('/usr/bin/sudo -n -- /usr/bin/docker --config',[StringComparison]::Ordinal) -and
        $ssh[-1].Contains('--host unix:///var/run/docker.sock',[StringComparison]::Ordinal) -and
        $ssh[-1].EndsWith("'inspect' 'not-a-live-target'",[StringComparison]::Ordinal)) 'noninteractive Docker-only elevation, isolated config and explicit daemon'
    # -G parses installed OpenSSH configuration without connecting or opening an identity key.
    $parsed = Invoke-NativeBytes 'ssh' (@('-G') + $ssh) -TimeoutSeconds 10
    Assert-Transport ($parsed.ExitCode -eq 0) 'installed OpenSSH accepts rendered options'
    foreach ($entry in @(('hostname '+$address),'user ubuntu','batchmode yes','stricthostkeychecking true',
        'identitiesonly yes','identityagent none','forwardagent no','clearallforwardings yes',
        'permitlocalcommand no','hostkeyalgorithms ssh-ed25519','updatehostkeys false',
        'controlmaster false','passwordauthentication no','kbdinteractiveauthentication no',
        'connectionattempts 1','connecttimeout 10','serveraliveinterval 5','serveralivecountmax 2')) {
        Assert-Transport (($parsed.Stdout -split '\r?\n') -ccontains $entry) ('OpenSSH option '+$entry)
    }
    Assert-Transport ($parsed.Stdout -notmatch '(?m)^(controlpath|proxycommand|proxyjump) (?!none\r?$)') 'no multiplexing or proxy from ambient config'
    Assert-Transport ($parsed.Stdout.Contains('userknownhostsfile '+$ledger.Replace('\','/'),[StringComparison]::Ordinal)) 'space-containing host ledger path'
    Assert-Transport (-not [IO.File]::Exists($identity)) 'no private key needed for configuration parsing'
    foreach ($change in @(
        @{Address='host.invalid'},@{Address='192.000.2.17'},@{Address='::1'},
        @{IdentityFile='relative'},@{KnownHostsFile=$ledger+'%h'},@{IdentityFile=$identity+'${HOME}'},
        @{KnownHostsSha256=('0'*64)},@{HostFingerprint=('SHA256:'+('A'*43))}
    )) {
        $candidate = $pin.Clone()
        foreach($field in $change.Keys){$candidate[$field]=$change[$field]}
        $expected = if($change.ContainsKey('Address')){'SSH destination must be a canonical IPv4 literal.'}
            elseif($change.ContainsKey('IdentityFile') -or $change.ContainsKey('KnownHostsFile')){'SSH file path must be absolute and literal.'}
            elseif($change.ContainsKey('KnownHostsSha256')){'SSH public pin hash differs from the approved reference.'}
            else{'SSH host fingerprint differs from the approved reference.'}
        Assert-TransportRefusal { Get-ProviderSshArguments @candidate -PublicDockerArguments @('version') } $expected
    }
    $candidate = $pin.Clone()
    $candidate.KnownHostsSha256 = 'bad'
    Assert-TransportRefusal { Get-ProviderSshArguments @candidate -PublicDockerArguments @('version') } 'SSH public pin is malformed.'
    $badWire = [byte[]]$keyBytes.Clone()
    $badWire[0] = 1
    $candidate = $pin.Clone()
    $candidate.KnownHostsSha256 = Set-PublicLedger ($address+' ssh-ed25519 '+[Convert]::ToBase64String($badWire)+"`n")
    Assert-TransportRefusal { Get-ProviderSshArguments @candidate -PublicDockerArguments @('version') } 'SSH public key encoding is invalid.'
    $candidate.KnownHostsSha256 = Set-PublicLedger ('x'*1025)
    Assert-TransportRefusal { Get-ProviderSshArguments @candidate -PublicDockerArguments @('version') } 'SSH public pin size is outside bounds.'
    foreach ($badLedger in @(($line+$line),$line.Replace($address,'192.0.2.18'),$line.Replace('ssh-ed25519','ssh-rsa'),($line+'# extra'))) {
        $candidate = $pin.Clone()
        $candidate.KnownHostsSha256 = Set-PublicLedger $badLedger
        Assert-TransportRefusal { Get-ProviderSshArguments @candidate -PublicDockerArguments @('version') } 'SSH public pin must contain exactly the selected host and Ed25519 key.'
    }
    $null = Set-PublicLedger $line
    $body = [byte[]]::new(4096)
    [Security.Cryptography.RandomNumberGenerator]::Fill($body)
    $copyScript = '[Console]::OpenStandardInput().CopyTo([Console]::OpenStandardOutput())'
    $copied = Invoke-NativeBytes $pwsh @('-NoProfile','-NonInteractive','-Command',$copyScript) $body 10
    Assert-Transport ($copied.ExitCode -eq 0 -and [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($copied.StdoutBytes,$body)) 'binary stdin roundtrip'
    $oldHost = $env:DOCKER_HOST
    try {
        $env:DOCKER_HOST='tcp://192.0.2.17:2375'
        $environment = Invoke-NativeBytes $pwsh @('-NoProfile','-NonInteractive','-Command','[Console]::Write([string]::IsNullOrEmpty($env:DOCKER_HOST))') -TimeoutSeconds 10
        Assert-Transport ($environment.ExitCode -eq 0 -and $environment.Stdout -ceq 'True') 'child Docker environment cleared'
    } finally { $env:DOCKER_HOST=$oldHost }
    Assert-TransportRefusal { Invoke-NativeBytes $pwsh @() -TimeoutSeconds 0 } 'Native process timeout is outside bounds.'
    Assert-TransportRefusal { Invoke-NativeBytes $pwsh @() -TimeoutSeconds 121 } 'Native process timeout is outside bounds.'
    Assert-TransportRefusal { Invoke-NativeBytes $pwsh @() ([byte[]]::new(67108865)) } 'Native process input is outside bounds.'
    Assert-TransportRefusal { Invoke-NativeBytes $pwsh @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -TimeoutSeconds 1 } 'Native process deadline exceeded.'
    foreach ($destination in @('OpenStandardOutput','OpenStandardError')) {
        $count = if($destination -ceq 'OpenStandardOutput'){1025}else{17}
        $flood = '$s=[Console]::'+$destination+'();$b=[byte[]]::new(65536);for($n=0;$n -lt '+$count+';$n++){$s.Write($b,0,$b.Length)}'
        Assert-TransportRefusal { Invoke-NativeBytes $pwsh @('-NoProfile','-NonInteractive','-Command',$flood) -TimeoutSeconds 20 } 'Bounded native process I/O failed.'
    }
    $shellVerified = $false
    if ($IsLinux) {
        $words = @('',"a'b",'$(touch /should-not-exist)','; false','spaces and \slashes','UTF8-Ж')
        $command = ConvertTo-ProviderShellCommand (@('/usr/bin/printf','%s\0') + $words)
        $roundtrip = Invoke-NativeBytes '/bin/sh' @('-c',$command) -TimeoutSeconds 10
        $expected = $encoding.GetBytes(($words -join [char]0)+[char]0)
        Assert-Transport ($roundtrip.ExitCode -eq 0 -and [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($roundtrip.StdoutBytes,$expected)) 'literal POSIX argv roundtrip'
        $shellVerified = $true
    }
    Assert-Transport ($script:transportRefusals -eq 29) ('all refusal cases ran, observed='+$script:transportRefusals)
    Write-Host ('PROVIDER RECOVERY TRANSPORT PASS: 29 refusals; SSH config parsed offline; binary/timeout/I-O bounds; POSIX shell='+$shellVerified+'; no connection or original inputs.')
}
finally {
    if ([IO.Directory]::Exists($testRoot)) {
        [IO.File]::Delete((Join-Path $testRoot 'public known hosts'))
        [IO.Directory]::Delete($testRoot)
    }
}
