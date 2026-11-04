#requires -Version 7.3
# Public argument models only. Rendering a request never starts SSH or grants recovery authority.
function Get-ProviderContainerArguments([string] $Session, [string] $Role) {
    if ($Session -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
        $Role -cnotin @('source','restore')) { throw 'Invalid disposable provider identity.' }
    $name = 'fleetory-bao-' + $Role + '-' + $Session.Replace('-','')
    return @('run','--rm','-d','--name',$name,'--label',"com.fleetory.openbao-recovery.role=$Role",
        '--label',"com.fleetory.openbao-recovery.session=$Session",'--network','none','--user','100:1000',
        '--read-only','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=32m,uid=100,gid=1000,mode=0700',
        '--tmpfs','/openbao/data:rw,noexec,nosuid,nodev,size=256m,uid=100,gid=1000,mode=0700',
        '--memory','384m','--cpus','0.30','--pids-limit','128','--cap-drop','ALL',
        '--security-opt','no-new-privileges:true','-e','BAO_ADDR=https://127.0.0.1:8200',
        '-e','BAO_CACERT=/tmp/ca.pem','--entrypoint','/bin/sh',
        'ghcr.io/openbao/openbao:2.7.1@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf',
        '-c','exec /bin/busybox sleep 3300')
}

function ConvertTo-ProviderShellCommand([string[]] $PublicArguments) {
    if ($null -eq $PublicArguments -or $PublicArguments.Count -lt 1 -or $PublicArguments.Count -gt 256) {
        throw 'Public argument count is outside bounds.'
    }
    $words = [Collections.Generic.List[string]]::new()
    $length = 0
    foreach ($argument in $PublicArguments) {
        if ($null -eq $argument -or $argument.Length -gt 16384 -or $argument -match '[\x00-\x1f\x7f]') {
            throw 'Public argument is outside bounds.'
        }
        # A shell must interpret each word literally, including quotes, substitutions and empty strings.
        $quote = [string][char]39
        $word = $quote + $argument.Replace($quote, ($quote + '"' + $quote + '"' + $quote)) + $quote
        $length += $word.Length + 1
        if ($length -gt 65536) { throw 'Public command is outside bounds.' }
        $words.Add($word)
    }
    return $words -join ' '
}

function Get-ProviderDockerShellCommand([string[]] $PublicArguments,[switch]$ClassicBuilder) {
    # No inherited Docker config, proxy injection, credential helper or alternate daemon.
    $wrapper = 'set -eu; unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION DOCKER_CUSTOM_HEADERS; umask 077; d=$(/usr/bin/mktemp -d /tmp/fleetory-provider-cli.XXXXXXXXXX); trap ''/bin/rmdir -- "$d" || exit 125'' EXIT; trap ''exit 129'' HUP; trap ''exit 130'' INT; trap ''exit 143'' TERM; /usr/bin/sudo -n -- /usr/bin/docker --config "$d" --host unix:///var/run/docker.sock "$@"'
    if($ClassicBuilder){
        if($null -eq $PublicArguments -or $PublicArguments.Count -lt 1 -or $PublicArguments[0] -cne 'build'){
            throw 'Classic builder mode requires the build verb.'
        }
        # sudo normally drops this public setting; preserve only the value forced here.
        $wrapper='DOCKER_BUILDKIT=0; export DOCKER_BUILDKIT; '+$wrapper.Replace('/usr/bin/sudo -n -- /usr/bin/docker',
            '/usr/bin/sudo -n --preserve-env=DOCKER_BUILDKIT -- /usr/bin/docker')
    }
    return ConvertTo-ProviderShellCommand (@('/bin/sh','-c',$wrapper,'provider-docker') + $PublicArguments)
}

function Get-ProviderSshArguments([string] $Address, [string] $KnownHostsFile, [string] $KnownHostsSha256,
    [string] $HostFingerprint, [string] $IdentityFile, [string[]] $PublicDockerArguments, [switch] $HostPreflight) {
    if ($HostPreflight -and $null -ne $PublicDockerArguments -and $PublicDockerArguments.Count -gt 0) { throw 'Ambiguous SSH request.' }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address,[ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $Address) {
        throw 'SSH destination must be a canonical IPv4 literal.'
    }
    foreach ($path in @($KnownHostsFile,$IdentityFile)) {
        if (-not [IO.Path]::IsPathFullyQualified($path) -or $path -match '[\x00-\x1f\x7f%\"$]') {
            throw 'SSH file path must be absolute and literal.'
        }
    }
    if ($KnownHostsSha256 -cnotmatch '^[0-9a-f]{64}$' -or $HostFingerprint -cnotmatch '^SHA256:[A-Za-z0-9+/]{43}$') {
        throw 'SSH public pin is malformed.'
    }
    # Hold the public ledger open while checking its hash and its single explicit host/key entry.
    $item = Get-Item -LiteralPath $KnownHostsFile -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer) {
        throw 'SSH public pin must be an ordinary file.'
    }
    $stream = [IO.File]::Open($KnownHostsFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 32 -or $stream.Length -gt 1024) { throw 'SSH public pin size is outside bounds.' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $stream.ReadExactly($bytes)
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        if ($hash -cne $KnownHostsSha256) { throw 'SSH public pin hash differs from the approved reference.' }
        $line = [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        $pattern = '\A' + [regex]::Escape($Address) + ' ssh-ed25519 ([A-Za-z0-9+/]+={0,2})\r?\n?\z'
        if ($line -cnotmatch $pattern) { throw 'SSH public pin must contain exactly the selected host and Ed25519 key.' }
        $key = [Convert]::FromBase64String($Matches[1])
        $expectedHeader = [Convert]::FromHexString('0000000b7373682d6564323535313900000020')
        if ($key.Length -ne 51 -or
            -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals([byte[]]$key[0..18],$expectedHeader)) {
            throw 'SSH public key encoding is invalid.'
        }
        $fingerprint = 'SHA256:' + [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData($key)).TrimEnd('=')
        if ($fingerprint -cne $HostFingerprint) { throw 'SSH host fingerprint differs from the approved reference.' }
    }
    finally { $stream.Dispose() }
    # OpenSSH config path tokens need quotes inside the -o argument, even with ProcessStartInfo.ArgumentList.
    $ledgerPath = if ($IsWindows) { $KnownHostsFile.Replace('\','/') } else { $KnownHostsFile.Replace('\','\\') }
    $ledgerOption = 'UserKnownHostsFile="' + $ledgerPath + '"'
    $command = if ($HostPreflight) {
        ConvertTo-ProviderShellCommand @('/bin/sh','-c','set -eu; /usr/bin/awk ''/^MemAvailable:/ {print $2}'' /proc/meminfo; /bin/date -u +%s')
    } else { Get-ProviderDockerShellCommand $PublicDockerArguments }
    return @('-F','none','-T','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
        '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no',
        '-o','ProxyCommand=none','-o','ProxyJump=none','-o','StrictHostKeyChecking=yes',
        '-o',$ledgerOption,'-o','GlobalKnownHostsFile=none','-o','HostKeyAlgorithms=ssh-ed25519',
        '-o','UpdateHostKeys=no','-o','CanonicalizeHostname=no','-o','ControlMaster=no',
        '-o','ControlPath=none','-o','ControlPersist=no','-o','ConnectTimeout=10',
        '-o','ConnectionAttempts=1','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',
        '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
        '-i',$IdentityFile,'-l','ubuntu','--',$Address,$command)
}
