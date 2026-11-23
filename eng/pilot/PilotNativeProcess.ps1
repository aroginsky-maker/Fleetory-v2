#requires -Version 7.3
# Bounded binary stdin/stdout; callers must keep credentials out of Arguments.
. (Join-Path $PSScriptRoot 'PilotCaptureStream.ps1')
function Invoke-NativeBytes([string] $Executable, [string[]] $Arguments, [byte[]] $InputBytes = $null, [int] $TimeoutSeconds = 90, [scriptblock] $ObserveProcess = $null, [switch] $ClassicDockerEnvironment, [switch] $DockerClientEnvironment, [object] $ExecutableLease = $null) {
    if ($ClassicDockerEnvironment -and $DockerClientEnvironment) { throw 'Native Docker environment modes are mutually exclusive.' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    if ($null -ne $ExecutableLease) {
        if (-not $DockerClientEnvironment -or $ExecutableLease -isnot [Fleetory.Pilot.NativeExecutableLease]) { throw 'Native executable lease profile refused.' }
        $ExecutableLease.ValidateRequest($Executable)
        $start.FileName = $ExecutableLease.GetLaunchPath()
    } else { $start.FileName = $Executable }
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $true
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 120) { throw 'Native process timeout is outside bounds.' }
    if ($null -ne $InputBytes -and $InputBytes.Length -gt 67108864) { throw 'Native process input is outside bounds.' }
    if ($ClassicDockerEnvironment -or $DockerClientEnvironment) {
        $start.Environment.Clear()
        if ($IsWindows) { $start.Environment['SystemRoot'] = [Environment]::GetEnvironmentVariable('SystemRoot') }
        if ($ClassicDockerEnvironment) { $start.Environment['DOCKER_BUILDKIT'] = '0' }
    }
    foreach ($name in @('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH')) {
        $null = $start.Environment.Remove($name)
    }
    foreach ($argument in $Arguments) { $null = $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = [Fleetory.Tests.PilotCaptureStream]::new(67108864)
    $stderr = [Fleetory.Tests.PilotCaptureStream]::new(1048576)
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $observationCancel = if ($null -ne $ObserveProcess) { [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds)) } else { $null }
    $processStarted = $false
    $stdoutTask = $null
    $stderrTask = $null
    $writeTask = $null
    try {
        if ($null -ne $ExecutableLease) { $ExecutableLease.Start($process) }
        elseif (-not $process.Start()) { throw 'Native process did not start.' }
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
        [double]$nextObservation=1
        while ($true) {
            if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Native process deadline exceeded.' }
            if ($stdoutTask.IsFaulted -or $stderrTask.IsFaulted -or $writeTask.IsFaulted) { throw 'Bounded native process I/O failed.' }
            if ($writeTask.IsCompleted -and -not $inputClosed) {
                $null = $writeTask.GetAwaiter().GetResult()
                $process.StandardInput.Close()
                $inputClosed = $true
            }
            if ($null -ne $ObserveProcess -and $stopwatch.Elapsed.TotalSeconds -ge $nextObservation) {
                # Only this exact launched Process is supplied; observer output cannot enter the binary reply.
                $null = & $ObserveProcess $process $observationCancel.Token
                $observationCancel.Token.ThrowIfCancellationRequested()
                $nextObservation = $stopwatch.Elapsed.TotalSeconds + 1
            }
            if ($process.HasExited -and $stdoutTask.IsCompleted -and $stderrTask.IsCompleted -and $writeTask.IsCompleted) {
                if ($null -ne $ObserveProcess) { $null = & $ObserveProcess $process $observationCancel.Token; $observationCancel.Token.ThrowIfCancellationRequested() }
                break
            }
            Start-Sleep -Milliseconds 20
        }
        $null = $stdoutTask.GetAwaiter().GetResult()
        $null = $stderrTask.GetAwaiter().GetResult()
        $null = $writeTask.GetAwaiter().GetResult()
        if ($null -ne $ExecutableLease) { $ExecutableLease.Check() }
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
        if ($null -ne $observationCancel) { $observationCancel.Dispose() }
        $stopwatch.Stop()
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
}
