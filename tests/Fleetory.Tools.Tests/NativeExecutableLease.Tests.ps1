#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
trap {
    $failure=$_.Exception.GetBaseException()
    $stage=$failure.Data['NativeExecutableLeaseStage']
    if($stage -cin @('start','image-query','image-path-match','image-file-identity','live-handle')){
        [Console]::Error.WriteLine(('NATIVE EXECUTABLE LEASE FAILURE STAGE: '+$stage))
    }
    throw
}

. (Join-Path $PSScriptRoot '../../eng/pilot/PilotNativeExecutableLease.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/PilotNativeProcess.ps1')
$executable=if($IsWindows){[Environment]::ProcessPath}else{'/usr/bin/cat'}
$hash=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
function Refuse([scriptblock]$Operation){
    $rejected=$false
    try{& $Operation}catch{
        if($_.Exception.GetBaseException().Message -cne 'Native executable lease refused.'){throw}
        $rejected=$true
    }
    if(-not $rejected){throw ('Unsafe executable binding accepted at test line '+$MyInvocation.ScriptLineNumber)}
}
Refuse { $null=[Fleetory.Pilot.NativeExecutableLease]::new('relative-program',$hash) }
Refuse { $null=[Fleetory.Pilot.NativeExecutableLease]::new($executable,('0'*64)) }
$lease=[Fleetory.Pilot.NativeExecutableLease]::new($executable,$hash)
$description=$lease.Describe()
if($description.Item1 -cne $executable -or $description.Item2 -cne $hash -or $description.Item3 -ne (Get-Item -LiteralPath $executable).Length){throw 'Held executable byte description changed.'}
$process=[Diagnostics.Process]::new()
$started=$false
try{
    $start=[Diagnostics.ProcessStartInfo]::new($lease.GetLaunchPath())
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.Environment.Clear()
    if($IsWindows){
        $start.Environment['SystemRoot']=[Environment]::GetEnvironmentVariable('SystemRoot')
        foreach($word in @('-NoLogo','-NoProfile','-NonInteractive','-Command','[Console]::Out.Write([Console]::In.ReadToEnd())')){$start.ArgumentList.Add($word)}
    }
    $process.StartInfo=$start
    $lease.Start($process)
    $started=$true
    [Fleetory.Pilot.NativeExecutableLease]::AssertStarted($process)
    $copy=[Diagnostics.Process]::GetProcessById($process.Id)
    try{Refuse {[Fleetory.Pilot.NativeExecutableLease]::AssertStarted($copy)}}finally{$copy.Dispose()}
    Refuse {[Fleetory.Pilot.NativeExecutableLease]::AssertStarted([Diagnostics.Process]::GetCurrentProcess())}
    $process.StandardInput.Write('generated-native-lease');$process.StandardInput.Close()
    if(-not $process.WaitForExit(5000) -or $process.ExitCode -ne 0 -or $process.StandardOutput.ReadToEnd() -cne 'generated-native-lease' -or $process.StandardError.ReadToEnd() -cne ''){throw 'Actual leased child failed.'}
    Refuse {[Fleetory.Pilot.NativeExecutableLease]::AssertStarted($process)}
}finally{
    if($started -and -not $process.HasExited){$process.Kill($true);$null=$process.WaitForExit(2000)}
    $process.Dispose();$lease.Dispose()
}
Refuse {$lease.Check()}
Refuse {$null=$lease.GetLaunchPath()}
Refuse {$null=$lease.Describe()}
$lease=[Fleetory.Pilot.NativeExecutableLease]::new($executable,$hash)
try{
    $arguments=if($IsWindows){@('-NoLogo','-NoProfile','-NonInteractive','-Command','[Console]::Out.Write([Console]::In.ReadToEnd())')}else{@()}
    Refuse {$null=Invoke-NativeBytes 'relative-must-not-launch' $arguments -DockerClientEnvironment -ExecutableLease $lease}
    $reply=Invoke-NativeBytes $executable $arguments ([Text.Encoding]::ASCII.GetBytes('generated-pipeline')) 5 -DockerClientEnvironment -ExecutableLease $lease
    if($reply.ExitCode -ne 0 -or $reply.Stdout -cne 'generated-pipeline' -or $reply.Stderr -cne ''){throw 'Actual native pipeline did not use the lease before stdin.'}
    $refused=$false
    try{$null=Invoke-NativeBytes $executable $arguments -ExecutableLease $lease}catch{
        if($_.Exception.GetBaseException().Message -cne 'Native executable lease profile refused.'){throw}
        $refused=$true
    }
    if(-not $refused){throw 'Leased process inherited a default environment.'}
    $classicArguments=if($IsWindows){@('-NoLogo','-NoProfile','-NonInteractive','-Command','if([Environment]::GetEnvironmentVariable("DOCKER_BUILDKIT") -cne "0"){exit 7};[Console]::Out.Write([Console]::In.ReadToEnd())')}else{@('-c','test "$DOCKER_BUILDKIT" = 0 && /usr/bin/cat')}
    $classicExecutable=if($IsWindows){$executable}else{'/usr/bin/dash'}
    $classicHash=(Get-FileHash -LiteralPath $classicExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    $classicLease=[Fleetory.Pilot.NativeExecutableLease]::new($classicExecutable,$classicHash)
    try{
        $reply=Invoke-NativeBytes $classicExecutable $classicArguments ([Text.Encoding]::ASCII.GetBytes('generated-classic-pipeline')) 5 -ClassicDockerEnvironment -ExecutableLease $classicLease
        if($reply.ExitCode -ne 0 -or $reply.Stdout -cne 'generated-classic-pipeline' -or $reply.Stderr -cne ''){throw 'Actual classic build pipeline did not use its lease.'}
    }finally{$classicLease.Dispose()}
}finally{$lease.Dispose()}
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('fleetory-native-lease-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($temporary)
$selected=Join-Path $temporary ([IO.Path]::GetFileName($executable))
$lease=$null
try{
    [IO.File]::Copy($executable,$selected)
    $lease=[Fleetory.Pilot.NativeExecutableLease]::new($selected,$hash)
    if($IsLinux){
        [IO.File]::Move($selected,$selected+'.old')
        [IO.File]::Copy($selected+'.old',$selected)
        Refuse {$lease.Check()}
    }else{
        $denied=$false
        try{[IO.File]::Move($selected,$selected+'.old')}catch [IO.IOException]{$denied=$true}
        if(-not $denied){throw 'Held Windows executable was renamed.'}
        $lease.Check()
    }
}finally{
    if($null -ne $lease){$lease.Dispose()}
    # This test created and still holds the exact absolute namespace; never delete caller paths.
    $resolved=[IO.Path]::GetFullPath($temporary)
    if(-not $resolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::Ordinal) -or (Split-Path $resolved -Leaf) -cnotmatch '^fleetory-native-lease-[a-f0-9]{32}$'){throw 'Temporary lease namespace changed.'}
    [IO.Directory]::Delete($resolved,$true)
}
Write-Output 'NATIVE EXECUTABLE LEASE PASS: actual held-file launch, original-process identity, copied process/relative/hash/exited/closed refusals and pathname replacement checks; no release provenance or resource authority.'
$global:LASTEXITCODE=0
