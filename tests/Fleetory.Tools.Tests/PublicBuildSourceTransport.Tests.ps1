$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot '../../eng/pilot/public_build/SourceTransport.cs')
$expected=[System.Text.Encoding]::ASCII.GetBytes('generated-public-source-only')
$pin=[System.Security.Cryptography.SHA256]::HashData($expected)
$cases=0
foreach($mode in @('normal','oversize','magic','digest','truncated','stall','permit')) {
    $age=[System.Diagnostics.Stopwatch]::StartNew()
    $info=[System.Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
    $info.UseShellExecute=$false
    $info.RedirectStandardInput=$true
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    $arguments=@('-NoProfile','-File',(Join-Path $PSScriptRoot 'PublicBuildTransportFixture.ps1'),$mode)
    foreach($argument in $arguments) { $info.ArgumentList.Add($argument) }
    $process=[System.Diagnostics.Process]::Start($info)
    $transport=[Fleetory.Pilot.PublicBuildSourceTransport]::new($process,$age,2000)
    $failed=$false
    try {
        $raw=$transport.Take($pin)
        if([Convert]::ToHexString($raw) -cne [Convert]::ToHexString($expected)) { throw 'Unexpected bytes' }
        $transport.RequestBeforeSdk()
        if($mode -cne 'normal') { throw 'Negative accepted' }
        $replayRefused=$false
        try { $transport.RequestBeforeSdk() } catch { $replayRefused=$true }
        if(-not $replayRefused) { throw 'Replay accepted' }
        $takeRefused=$false
        try { $null=$transport.Take($pin) } catch { $takeRefused=$true }
        if(-not $takeRefused) { throw 'Frame replay accepted' }
    } catch {
        if($mode -ceq 'normal' -or $_.Exception.Message -eq 'Negative accepted') { throw }
        $failed=$true
        $latePermitRefused=$false
        try { $transport.RequestBeforeSdk() } catch { $latePermitRefused=$true }
        if(-not $latePermitRefused) { throw 'Permit accepted after failed frame/permit attempt' }
    } finally { $transport.Dispose() }
    if($mode -cne 'normal' -and -not $failed) { throw 'Missing refusal' }
    if($age.ElapsedMilliseconds -gt 8500) { throw 'Unbounded source child cleanup' }
    $cases++
}
Write-Output "PASS $cases actual source-child transport cases; no native resources or original inputs"
