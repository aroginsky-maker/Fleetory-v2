#Requires -Version 7.3
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'eng/readiness-response.ps1')
. (Join-Path $PSScriptRoot 'PilotNativeProcess.ps1')
$accepted = 0
foreach ($status in @(200, [long]200, [Net.HttpStatusCode]::OK)) {
    if (-not (Test-FleetoryReadinessResponse $status 'Healthy')) { throw 'Canonical healthy response refused.' }
    $accepted++
}
$refused = 0
$cases = @(
    @{Status=200;Body='Degraded'}, @{Status=200;Body='Unhealthy'}, @{Status=200;Body=''},
    @{Status=200;Body=$null}, @{Status=200;Body='healthy'}, @{Status=200;Body='HEALTHY'},
    @{Status=200;Body=' Healthy'}, @{Status=200;Body='Healthy '}, @{Status=200;Body="Healthy`n"},
    @{Status=200;Body=([string][char]0xfeff+'Healthy')}, @{Status=200;Body=('Healthy'+[char]0)},
    @{Status=200;Body='{"status":"Healthy"}'}, @{Status=200;Body=('x'*64)}, @{Status=200;Body=('x'*65)},
    @{Status=200;Body=('Healthy'+('x'*65536))}, @{Status=200;Body=[Text.Encoding]::UTF8.GetBytes('Healthy')},
    @{Status=200;Body=@('Healthy')}, @{Status=200;Body=[pscustomobject]@{value='Healthy'}},
    @{Status=503;Body='Healthy'}, @{Status=302;Body='Healthy'}, @{Status=204;Body='Healthy'},
    @{Status='200';Body='Healthy'}, @{Status=[double]200;Body='Healthy'},
    @{Status=$true;Body='Healthy'}, @{Status=$null;Body='Healthy'}
)
foreach ($case in $cases) {
    if (Test-FleetoryReadinessResponse $case.Status $case.Body) { throw 'Unsafe readiness response accepted.' }
    $refused++
}
$work = Join-Path $repo ('artifacts/readiness-response-'+[Guid]::NewGuid().ToString('N'))
$driver = @'
param([string] $Scenario)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$global:ReadinessFixtureScenario=$Scenario
$global:ReadinessFixtureCalls=0
$global:ReadinessFixtureStops=0
$global:ReadinessFixtureWaits=0
$global:ReadinessFixtureFileReads=0
$global:ReadinessFixtureStarts=0
$global:ReadinessFixtureRepo=Join-Path $PSScriptRoot 'repository'
$global:ReadinessFixtureLab=Join-Path $PSScriptRoot 'work/security-lab'
function global:Test-Path {
    param([string] $LiteralPath)
    $paths=@((Join-Path $global:ReadinessFixtureRepo 'src/Fleetory.Server/bin/Debug/net10.0/Fleetory.Server.dll'),
        (Join-Path $global:ReadinessFixtureLab 'openbao-token'))
    if($LiteralPath -cnotin $paths){throw 'Unexpected fixture path query.'}
    return $true
}
function global:Get-Content { $global:ReadinessFixtureFileReads++;throw 'Fixture forbids token/env file reads.' }
function global:Start-Sleep { param([int] $Seconds) if($Seconds -ne 1){throw 'Unexpected readiness poll interval.'} }
function global:Start-Process {
    param([string] $FilePath,[string[]] $ArgumentList,[string] $WindowStyle,[switch] $PassThru,
        [string] $RedirectStandardOutput,[string] $RedirectStandardError)
    $dll=Join-Path $global:ReadinessFixtureRepo 'src/Fleetory.Server/bin/Debug/net10.0/Fleetory.Server.dll'
    if($FilePath -cne 'dotnet' -or ($ArgumentList -join '|') -cne ('"'+$dll+'"|--environment=Development|--urls=http://127.0.0.1:5088') -or
        $WindowStyle -cne 'Hidden' -or -not $PassThru -or
        $RedirectStandardOutput -cne (Join-Path $global:ReadinessFixtureLab 'fleetory-server.stdout.log') -or
        $RedirectStandardError -cne (Join-Path $global:ReadinessFixtureLab 'fleetory-server.stderr.log')){throw 'Unexpected fixture launch.'}
    $global:ReadinessFixtureStarts++
    $fake=[pscustomobject]@{Id=4242;HasExited=($global:ReadinessFixtureScenario -ceq 'exited')}
    $fake|Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {$global:ReadinessFixtureWaits++}
    return $fake
}
function global:Stop-Process {
    param([int] $Id,[switch] $Force)
    if($Id -ne 4242 -or -not $Force){throw 'Unowned fixture process stop.'}
    $global:ReadinessFixtureStops++
}
function global:Invoke-WebRequest {
    param([string] $Uri,[int] $TimeoutSec,[int] $MaximumRedirection=-1)
    if($Uri -cne 'http://127.0.0.1:5088/health/ready' -or $TimeoutSec -ne 2 -or $MaximumRedirection -ne 0){throw 'Unexpected readiness request policy.'}
    $global:ReadinessFixtureCalls++
    if($global:ReadinessFixtureScenario -ceq 'transport'){throw 'Fixture transport failure.'}
    $body=if($global:ReadinessFixtureScenario -ceq 'degraded' -or
        ($global:ReadinessFixtureScenario -ceq 'recover' -and $global:ReadinessFixtureCalls -eq 1)){'Degraded'}else{'Healthy'}
    $code=if($global:ReadinessFixtureScenario -ceq 'redirect'){302}else{200}
    return [pscustomobject]@{StatusCode=$code;Content=$body}
}
$outcome='PASS'
try { & (Join-Path $global:ReadinessFixtureRepo 'eng/verify-security-lab.ps1') }
catch {
    if($_.Exception.Message -cne ('Fleetory did not become ready with OpenBao. See '+(Join-Path $global:ReadinessFixtureLab 'fleetory-server.stderr.log'))){throw}
    $outcome='NOT_READY'
}
[ordered]@{outcome=$outcome;calls=$global:ReadinessFixtureCalls;starts=$global:ReadinessFixtureStarts;
    stops=$global:ReadinessFixtureStops;waits=$global:ReadinessFixtureWaits;fileReads=$global:ReadinessFixtureFileReads}|ConvertTo-Json -Compress
'@
$utf8 = [Text.UTF8Encoding]::new($false)
$cliChecks = 0
try {
    $eng = Join-Path $work 'repository/eng'
    $null = New-Item -ItemType Directory -Path $eng
    foreach ($name in @('verify-security-lab.ps1','readiness-response.ps1')) {
        Copy-Item -LiteralPath (Join-Path $repo ('eng/'+$name)) -Destination (Join-Path $eng $name)
    }
    $driverPath=Join-Path $work 'driver.ps1'
    [IO.File]::WriteAllText($driverPath,$driver,$utf8)
    $executables=@((Join-Path $PSHOME $(if($IsWindows){'pwsh.exe'}else{'pwsh'})))
    if($IsWindows){$executables+=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'}
    foreach($executable in $executables){
        foreach($scenario in @('healthy','recover','degraded','redirect','transport','exited')){
            # Process-scoped execution of these copied repository fixtures; no machine policy change.
            $launch=@('-NoProfile','-NonInteractive')
            if($IsWindows){$launch+=@('-ExecutionPolicy','Bypass')}
            $result=Invoke-NativeBytes $executable ($launch+@('-File',$driverPath,'-Scenario',$scenario)) -TimeoutSeconds 30
            if($result.ExitCode -ne 0 -or $result.Stderr.Length -ne 0){
                [Console]::Error.WriteLine('Disposable readiness driver '+$scenario+': '+$result.Stderr.Substring(0,[Math]::Min(1600,$result.Stderr.Length)))
                throw 'Isolated readiness CLI fixture failed.'
            }
            $json=@($result.Stdout -split "`r?`n"|Where-Object {$_ -like '{"outcome":*'})
            if($json.Count -ne 1){throw 'Readiness fixture evidence missing.'}
            $record=$json[0]|ConvertFrom-Json
            $good=$scenario -cin @('healthy','recover')
            $expectedCalls=switch($scenario){'healthy'{1};'recover'{2};'exited'{0};default{30}}
            $expectedStops=if($scenario -ceq 'exited'){0}else{1}
            $expectedOutcome=if($good){'PASS'}else{'NOT_READY'}
            $marker=$result.Stdout.Contains('Fleetory /health/ready returned 200/Healthy with OpenBao-backed PostgreSQL configuration.',[StringComparison]::Ordinal)
            if($record.outcome -cne $expectedOutcome -or $record.calls -ne $expectedCalls -or $record.starts -ne 1 -or
                $record.stops -ne $expectedStops -or $record.waits -ne $expectedStops -or $record.fileReads -ne 0 -or $marker -ne $good){throw 'Readiness CLI falsely accepted or escaped its disposable scope.'}
            $cliChecks++
        }
    }
}
finally {
    $resolved=[IO.Path]::GetFullPath($work)
    $artifacts=[IO.Path]::GetFullPath((Join-Path $repo 'artifacts'))+[IO.Path]::DirectorySeparatorChar
    if(-not $resolved.StartsWith($artifacts,[StringComparison]::OrdinalIgnoreCase) -or
        (Get-Item -LiteralPath $resolved).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)){throw 'Readiness fixture cleanup containment failed.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Host ('READINESS RESPONSE PASS: {0} canonical responses, {1} refusals, {2} isolated CLI cases; no network, lab/token reads or Server launch.' -f $accepted,$refused,$cliChecks)
