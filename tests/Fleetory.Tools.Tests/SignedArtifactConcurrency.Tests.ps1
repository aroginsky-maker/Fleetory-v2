#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$verifier = Join-Path $repoRoot 'eng/verify-signed-artifact.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source (
    Join-Path $PSScriptRoot 'SignedArtifactVerification.Tests.ps1') -Names @('Get-TestSha256', 'Write-ManifestSignature', 'Write-SignedArtifact')
$work = Join-Path $repoRoot ('artifacts/artifact-concurrency-' + [Guid]::NewGuid().ToString('N'))
$anchorPath = Join-Path $work 'release.anchor.json'
$lockPath = $anchorPath + '.lock'
$key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
$runs = [Collections.Generic.List[object]]::new()
$held = $null

function New-ReleaseFixture([int] $Version) {
    $directory = Join-Path $work ("release-$Version")
    [void](New-Item -ItemType Directory -Path $directory -Force)
    $artifactPath = Join-Path $directory 'artifact.zip'
    $manifestPath = Join-Path $directory 'manifest.json'
    $signaturePath = Join-Path $directory 'manifest.sig'
    $publicKeyPath = Join-Path $directory 'public.pem'
    Write-SignedArtifact $Version "release-$Version"
    return [pscustomobject]@{
        Version = $Version; Artifact = $artifactPath; Manifest = $manifestPath
        Signature = $signaturePath; PublicKey = $publicKeyPath
    }
}

function Start-TestProcess([string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    $run = [pscustomobject]@{
        Process = $process; Output = $process.StandardOutput.ReadToEndAsync()
        Error = $process.StandardError.ReadToEndAsync(); Completed = $false
    }
    $runs.Add($run)
    return $run
}

function Start-Verification($Fixture) {
    return Start-TestProcess @('-NoProfile', '-NonInteractive', '-File', $verifier,
        '-ArtifactPath', $Fixture.Artifact, '-ManifestPath', $Fixture.Manifest,
        '-SignaturePath', $Fixture.Signature, '-PublicKeyPath', $Fixture.PublicKey,
        '-AnchorPath', $anchorPath, '-ExpectedArtifactId', 'fleetory.server')
}

function Wait-TestProcess($Run) {
    try {
        if (-not $Run.Process.WaitForExit(15000) -or
            -not $Run.Output.Wait(5000) -or -not $Run.Error.Wait(5000)) {
            throw 'Owned artifact test process exceeded its deadline.'
        }
        return [pscustomobject]@{
            ExitCode = $Run.Process.ExitCode
            Output = $Run.Output.GetAwaiter().GetResult()
            Error = $Run.Error.GetAwaiter().GetResult()
        }
    }
    finally {
        if (-not $Run.Process.HasExited) { $Run.Process.Kill($true); $Run.Process.WaitForExit() }
        $Run.Process.Dispose()
        $Run.Completed = $true
    }
}

try {
    [void](New-Item -ItemType Directory -Path $work -Force)
    $one = New-ReleaseFixture 1
    $two = New-ReleaseFixture 2
    $initial = Wait-TestProcess (Start-Verification $one)
    if ($initial.ExitCode -ne 0) { throw 'Initial fixture acceptance failed.' }
    $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($anchorPath))

    $held = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $elapsed = [Diagnostics.Stopwatch]::StartNew()
        $denied = Wait-TestProcess (Start-Verification $two)
        if ($denied.ExitCode -eq 0) { throw 'Another verifier advanced the anchor while its writer lock was held.' }
        if ($denied.Error -notlike '*anchor lock*' -or $elapsed.Elapsed.TotalSeconds -lt 4 -or $elapsed.Elapsed.TotalSeconds -gt 15) {
            throw 'Contended anchor locking did not fail within its bounded acquisition window.'
        }
        if ($before -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($anchorPath))) {
            throw 'Lock contention changed anchor bytes.'
        }
    }
    finally { $held.Dispose(); $held = $null }

    $three = New-ReleaseFixture 3
    $initialBytes = [Convert]::FromBase64String($before)
    foreach ($order in @(@($two, $three), @($three, $two))) {
        [IO.File]::WriteAllBytes($anchorPath, $initialBytes)
        $held = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $first = Start-Verification $order[0]
            $secondRun = Start-Verification $order[1]
            Start-Sleep -Milliseconds 500
        }
        finally { $held.Dispose(); $held = $null }
        $results = @((Wait-TestProcess $first), (Wait-TestProcess $secondRun))
        for ($index = 0; $index -lt 2; $index++) {
            $result = $results[$index]
            if ($result.ExitCode -eq 0) {
                $accepted = $result.Output | ConvertFrom-Json
                if ($accepted.status -ne 'accepted' -or $accepted.version -ne $order[$index].Version) { throw 'Concurrent forward release was not accepted.' }
            }
            elseif ($order[$index].Version -ne 2 -or $result.Error -notlike '*older than the anti-rollback anchor*') {
                throw 'Concurrent release failed for an unexpected reason.'
            }
        }
        $finalAnchor = [IO.File]::ReadAllText($anchorPath) | ConvertFrom-Json
        if ($finalAnchor.version -ne 3) { throw 'A concurrent writer regressed the accepted version.' }
    }

    # A process exit releases the OS handle; marker-file presence is not a lease.
    $driverPath = Join-Path $work 'lock-holder.ps1'
    $readyPath = Join-Path $work 'holder-ready'
    $driver = @'
param([string] $LockPath, [string] $ReadyPath)
$ErrorActionPreference = 'Stop'
$held = [IO.File]::Open($LockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    [IO.File]::WriteAllText($ReadyPath, 'locked')
    Start-Sleep -Seconds 30
}
finally { $held.Dispose() }
'@
    [IO.File]::WriteAllText($driverPath, $driver, [Text.UTF8Encoding]::new($true))
    $holder = Start-TestProcess @('-NoProfile', '-NonInteractive', '-File', $driverPath,
        '-LockPath', $lockPath, '-ReadyPath', $readyPath)
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $readyPath)) {
        if ($holder.Process.HasExited -or $deadline.Elapsed.TotalSeconds -gt 10) {
            throw 'Owned lock-holder process did not become ready.'
        }
        Start-Sleep -Milliseconds 20
    }
    $holder.Process.Kill($true)
    [void](Wait-TestProcess $holder)
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { throw 'Persistent lock marker disappeared.' }
    $four = New-ReleaseFixture 4
    $afterExit = Wait-TestProcess (Start-Verification $four)
    if ($afterExit.ExitCode -ne 0 -or ($afterExit.Output | ConvertFrom-Json).version -ne 4) {
        throw 'A terminated writer left a stale lease or blocked forward acceptance.'
    }

    $preserved = [Convert]::ToBase64String([IO.File]::ReadAllBytes($anchorPath))
    Remove-Item -LiteralPath $lockPath -Force
    [void](New-Item -ItemType Directory -Path $lockPath)
    $unsafePath = Wait-TestProcess (Start-Verification $four)
    if ($unsafePath.ExitCode -eq 0 -or $unsafePath.Error -notlike '*regular file*') {
        throw 'A directory was accepted as the writer lock.'
    }
    [IO.Directory]::Delete($lockPath)
    if ($env:OS -ne 'Windows_NT') {
        $target = Join-Path $work 'lock-target'
        [IO.File]::WriteAllText($target, 'lock-target-sentinel')
        [void](New-Item -ItemType SymbolicLink -Path $lockPath -Target $target)
        $unsafeLink = Wait-TestProcess (Start-Verification $four)
        if ($unsafeLink.ExitCode -eq 0 -or $unsafeLink.Error -notlike '*regular file*' -or
            [IO.File]::ReadAllText($target) -cne 'lock-target-sentinel') {
            throw 'A linked lock path was followed or accepted.'
        }
    }
    if ($preserved -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($anchorPath))) {
        throw 'An unsafe lock path changed accepted anchor bytes.'
    }
    Write-Host 'ARTIFACT CONCURRENCY TESTS PASS: bounded contention, two concurrent launch orders, process-exit recovery, persistent marker and unsafe-path denial.'
}
finally {
    if ($null -ne $held) { $held.Dispose() }
    foreach ($run in $runs) {
        if (-not $run.Completed) {
            if (-not $run.Process.HasExited) { $run.Process.Kill($true); $run.Process.WaitForExit() }
            $run.Process.Dispose()
        }
    }
    $key.Dispose()
    Remove-FleetoryTestArtifacts $work $repoRoot
}
