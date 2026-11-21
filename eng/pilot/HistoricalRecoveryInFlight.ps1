# Generated-only native create. The original client remains held until coordinator exit is observed.
function New-HistoricalChildStart([string]$Executable){
    $start=[Diagnostics.ProcessStartInfo]::new($Executable)
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.Environment.Clear()
    foreach($name in @('PATH','SystemRoot','WINDIR','HOME','USERPROFILE','APPDATA','LOCALAPPDATA','ProgramData','TEMP','TMP','TMPDIR')){
        $value=[Environment]::GetEnvironmentVariable($name)
        if($null -ne $value){$start.Environment[$name]=$value}
    }
    return $start
}

function Get-HistoricalNativeBirth([Diagnostics.Process]$Process){
    Assert-ImmuData ($null -ne $Process -and -not $Process.HasExited -and $Process.Id -gt 0) 'inflight-native-live'
    if($IsWindows){
        return @{kind='windows-filetime';token=$Process.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)}
    }
    Assert-ImmuData $IsLinux 'inflight-native-platform'
    $stream=[IO.File]::Open('/proc/'+$Process.Id+'/stat',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try{
        $buffer=[byte[]]::new(4097);$count=0
        while($count -lt $buffer.Length){
            $read=$stream.Read($buffer,$count,$buffer.Length-$count)
            if($read -eq 0){break};$count+=$read
        }
        Assert-ImmuData ($count -gt 0 -and $count -le 4096) 'inflight-native-stat-bound'
        $text=[Text.Encoding]::ASCII.GetString($buffer,0,$count)
    }finally{$stream.Dispose()}
    $end=$text.LastIndexOf(')')
    Assert-ImmuData ($text.StartsWith(([string]$Process.Id+' ('),[StringComparison]::Ordinal) -and $end -gt 0) 'inflight-native-stat'
    $fields=$text.Substring($end+1).Trim().Split(' ',[StringSplitOptions]::RemoveEmptyEntries)
    Assert-ImmuData ($fields.Count -ge 20 -and $fields[0] -cnotin @('Z','X') -and
        $fields[19] -cmatch '^[1-9][0-9]{0,19}\z' -and -not $Process.HasExited) 'inflight-native-stat'
    return @{kind='linux-proc-start-ticks';token=$fields[19]}
}

function Invoke-HistoricalInFlightDocker([string[]]$Arguments,$Request,$Token,$InputStream,$OutputStream){
    Assert-ImmuData ($Arguments.Count -gt 2 -and $Arguments[0] -ceq 'run' -and $Arguments[1] -ceq '-d') 'inflight-original-arguments'
    $docker=(Get-Command $(if($IsWindows){'docker.exe'}else{'docker'}) -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    Assert-ImmuData ($Request.python -is [string] -and [IO.Path]::IsPathFullyQualified($Request.python) -and
        (Test-Path -LiteralPath $Request.python -PathType Leaf)) 'inflight-python'
    $secret=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
    $clientApi=(Invoke-Docker @('version','--format','{{.Client.APIVersion}}')).Stdout.Trim()
    Assert-ImmuData ($clientApi -cmatch '^1\.[0-9]{2}\z') 'inflight-client-api'
    $gateRequest=@{image=$Request.imageId;nonce=$Request.session;token=$secret;docker=$docker;clientApiVersion=$clientApi;
        dockerSha256=(Get-ImmuDataHash ([IO.File]::ReadAllBytes($docker)))}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($gateRequest|ConvertTo-Json -Compress))
    $gateStart=New-HistoricalChildStart $Request.python
    foreach($part in @('-B',(Join-Path $PSScriptRoot 'historical/historical_create_gate.py'),'--request-sha256',(Get-ImmuDataHash $bytes))){$gateStart.ArgumentList.Add($part)}
    $gate=$null;$native=$null;$output=[Fleetory.Tests.PilotCaptureStream]::new(128)
    $errorOutput=[Fleetory.Tests.PilotCaptureStream]::new(4096);$gateError=[Fleetory.Tests.PilotCaptureStream]::new(8192)
    $copies=@();$directory=$null;$configuration=$null;$phase='startup'
    $drain=$null
    try{
        $gate=[Diagnostics.Process]::Start($gateStart)
        $gateErrors=$gate.StandardError.BaseStream.CopyToAsync($gateError);$copies+=,$gateErrors
        Send-IndependentFrame $gate.StandardInput.BaseStream $bytes $Token
        $bound=(Read-IndependentFrame $gate.StandardOutput.BaseStream $Token 512)|ConvertFrom-Json -AsHashtable -Depth 3
        Assert-ImmuData ($bound.Count -eq 4 -and $bound.stage -ceq 'bound' -and $bound.pid -eq $gate.Id -and
            $bound.port -is [long] -and $bound.port -gt 0 -and $bound.port -le 65535 -and
            $bound.version -cmatch '^1\.[0-9]{2}\z') 'inflight-gate-bound'
        $phase='configuration'
        $parent=Join-Path $repo ('artifacts/native-audit-controller-'+$Request.fixture)
        Assert-ImmuData ((Test-Path -LiteralPath $parent -PathType Container) -and
            ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'inflight-parent'
        $directory=Join-Path $parent ('create-config-'+$Request.session)
        Assert-ImmuData (-not (Test-Path -LiteralPath $directory)) 'inflight-config-fresh'
        $null=New-Item -ItemType Directory -Path $directory
        if(-not $IsWindows){[IO.File]::SetUnixFileMode($directory,[IO.UnixFileMode]448)}
        $configuration=Join-Path $directory 'config.json'
        [IO.File]::WriteAllText($configuration,(@{HttpHeaders=@{'X-Fleetory-Create-Nonce'=$secret}}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
        if(-not $IsWindows){[IO.File]::SetUnixFileMode($configuration,[IO.UnixFileMode]384)}
        $start=New-HistoricalChildStart $docker
        $createArguments=[Collections.Generic.List[string]]::new();$privateScratch=0
        for($index=2;$index -lt $Arguments.Count;$index++){
            $part=$Arguments[$index]
            if($index -gt 2 -and $Arguments[$index-1] -ceq '--tmpfs' -and
                $part -ceq ('/tmp:'+$script:nativeAuditTmpfs['/tmp'])){
                $part='/run/fleetory-native-create:'+$script:nativeAuditTmpfs['/tmp'];$privateScratch++
            }
            $createArguments.Add($part)
        }
        Assert-ImmuData ($privateScratch -eq 1) 'inflight-private-scratch'
        foreach($part in (@('--config',$directory,'--host',('tcp://127.0.0.1:'+$bound.port),'create','--pull=never')+$createArguments.ToArray())){
            $start.ArgumentList.Add($part)
        }
        $phase='native-start'
        $native=[Diagnostics.Process]::Start($start)
        $null=$native.Handle
        $birth=Get-HistoricalNativeBirth $native
        $stdout=$native.StandardOutput.BaseStream.CopyToAsync($output);$stderr=$native.StandardError.BaseStream.CopyToAsync($errorOutput)
        $copies+=,$stdout;$copies+=,$stderr;$native.StandardInput.Close()
        $phase='held-response'
        $held=(Read-IndependentFrame $gate.StandardOutput.BaseStream $Token 512)|ConvertFrom-Json -AsHashtable -Depth 3
        Assert-ImmuData ($held.Count -eq 4 -and $held.stage -ceq 'held' -and $held.pid -eq $gate.Id -and
            $held.responseSha256 -cmatch '^[a-f0-9]{64}\z' -and $held.nativeDaemonStreamExited -eq $true -and
            -not $native.HasExited -and (Get-HistoricalNativeBirth $native).token -ceq $birth.token -and
            $output.Length -eq 0 -and -not $stdout.IsCompleted -and -not $stdout.IsFaulted -and -not $stderr.IsFaulted) 'inflight-native-client-held'
        Write-HistoricalWitnessFrame $OutputStream $Token @{stage='inflight';nonce=$Request.nonce;pid=$PID;
            nativePid=$native.Id;nativeBirthKind=$birth.kind;nativeBirthToken=$birth.token;responseSha256=$held.responseSha256;nativeStdoutBytes=0}
        $released=$false
        try{$released=(Read-IndependentFrame $InputStream $Token 96) -ceq ('release:'+$Request.nonce)}catch{}
        # Always drain this original invocation, even if its requester has gone away.
        $drain=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(15))
        Send-IndependentFrame $gate.StandardInput.BaseStream ([Text.Encoding]::ASCII.GetBytes(('release:'+$Request.session))) $drain.Token
        $gate.StandardInput.Close()
        $null=$native.WaitForExitAsync($drain.Token).GetAwaiter().GetResult()
        $null=$gate.WaitForExitAsync($drain.Token).GetAwaiter().GetResult()
        foreach($task in $copies){$null=$task.WaitAsync($drain.Token).GetAwaiter().GetResult()}
        Assert-ImmuData ($native.ExitCode -eq 0 -and $errorOutput.Length -eq 0 -and $gate.ExitCode -eq 0 -and
            $gateError.Length -eq 0 -and $gate.StandardOutput.BaseStream.ReadByte() -eq -1) 'inflight-original-native-reply'
        return @{ExitCode=$native.ExitCode;StdoutBytes=$output.ToArray();StderrBytes=$errorOutput.ToArray();RequesterReleased=$released}
    }catch{
        $category='inflight-'+$phase
        if($null -ne $gate -and $gate.HasExited){
            try{$null=$gateErrors.Wait(2000)}catch{}
            $captured=[Text.Encoding]::UTF8.GetString($gateError.ToArray())
            $causes=[regex]::Matches($captured,'(?m)^GateRefusal: Historical create gate refused: ([a-z-]{1,32})\.\r?$')
            if($causes.Count -gt 0){$category+='-'+$causes[$causes.Count-1].Groups[1].Value}
            else{
                $types=[regex]::Matches($captured,'(?m)^([A-Za-z0-9]+Error):')
                if($types.Count -gt 0){$category+='-'+$types[$types.Count-1].Groups[1].Value.ToLowerInvariant()}
            }
        }
        Assert-ImmuData $false $category
    }finally{
        foreach($process in @($native,$gate)){
            if($null -ne $process){
                if(-not $process.HasExited){try{$process.Kill($true);$null=$process.WaitForExit(2000)}catch{}}
                $process.Dispose()
            }
        }
        foreach($task in $copies){if(-not $task.IsCompleted){try{$null=$task.Wait(2000)}catch{}}}
        $output.Dispose();$errorOutput.Dispose();$gateError.Dispose();if($null -ne $drain){$drain.Dispose()}
        if($null -ne $configuration -and (Test-Path -LiteralPath $configuration)){[IO.File]::Delete($configuration)}
        if($null -ne $directory -and (Test-Path -LiteralPath $directory)){[IO.Directory]::Delete($directory,$false)}
    }
}

function Assert-HistoricalInFlightClient($Peer){
    Assert-ImmuData ($null -ne $Peer.inFlight -and $null -ne $Peer.nativeObserver -and
        -not $Peer.nativeObserver.HasExited) 'inflight-native-live'
    Assert-ImmuData ($Peer.nativeObserver.Id -eq $Peer.inFlight.nativePid) 'inflight-native-pid'
    $birth=Get-HistoricalNativeBirth $Peer.nativeObserver
    Assert-ImmuData ($birth.kind -ceq $Peer.inFlight.nativeBirthKind -and
        $birth.token -ceq $Peer.inFlight.nativeBirthToken) 'inflight-native-birth'
}

function Complete-HistoricalInFlightWitness($Peer,$Request){
    Assert-HistoricalInFlightClient $Peer
    Send-IndependentFrame $Peer.input ([Text.Encoding]::ASCII.GetBytes(('release:'+$Request.nonce))) $Peer.cancel.Token
    $ack=(Read-IndependentFrame $Peer.output $Peer.cancel.Token 512)|ConvertFrom-Json -AsHashtable -Depth 3
    Assert-ImmuData ($ack.Count -eq 5 -and $ack.stage -ceq 'created' -and $ack.nonce -ceq $Request.nonce -and
        $ack.pid -eq $Peer.process.Id -and $ack.replySha256 -cmatch '^[a-f0-9]{64}\z' -and $null -eq $ack.prefix -and
        $Peer.nativeObserver.HasExited) 'inflight-native-reply-after-release'
    $Peer.ack=$ack
    return Complete-HistoricalCreateWitness $Peer $Request
}
