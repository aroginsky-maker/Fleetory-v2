#Requires -Version 7.3
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$quality = Join-Path $repo 'eng/verify-quality.ps1'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $quality -Names @()
$work = Join-Path $repo ('artifacts/quality-orchestration-' + [Guid]::NewGuid().ToString('N'))
$utf8 = [Text.UTF8Encoding]::new($false)
$passed = 0

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

$driver = @'
param([string] $Mode, [string] $Entry)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$global:QualityFixtureMode = $Mode
$global:QualityFixtureTrace = Join-Path $PSScriptRoot 'trace.jsonl'
$global:QualityFixtureScannerStarted = $false
$env:FLEETORY_TEST_CONNECTION_STRING = $null
foreach ($name in @('SONAR_HOST_URL','SONAR_PROJECT_KEY','SONAR_TOKEN','SONAR_ORGANIZATION','SONAR_QUALITYGATE_TIMEOUT','SONAR_PROJECT_NAME')) {
    [Environment]::SetEnvironmentVariable($name, $null, 'Process')
}
if ($Mode -eq 'configured' -or $Mode.StartsWith('configured-') -or $Mode.StartsWith('scanner-') -or
    $Entry -eq 'verify-sonar.ps1' -or $Mode.StartsWith('partial-')) {
    $env:SONAR_HOST_URL = 'http://127.0.0.1:19000'
    $env:SONAR_PROJECT_KEY = 'quality-fixture'
    $env:SONAR_TOKEN = 'fixture-token'
}
switch ($Mode) {
    'partial-host' { $env:SONAR_HOST_URL = $null }
    'partial-project' { $env:SONAR_PROJECT_KEY = $null }
    'partial-token' { $env:SONAR_TOKEN = $null }
    'partial-whitespace' { $env:SONAR_TOKEN = ' ' }
}
function Write-FixtureTrace([string] $Kind, [string[]] $Arguments) {
    $line = @{ kind = $Kind; arguments = $Arguments } | ConvertTo-Json -Compress
    [IO.File]::AppendAllText($global:QualityFixtureTrace, $line + [Environment]::NewLine)
}
function global:docker {
    $arguments = @($args | ForEach-Object { [string] $_ })
    if (($arguments -join ' ') -ne 'info --format {{.ServerVersion}}') { throw 'Unexpected fixture Docker command.' }
    Write-FixtureTrace 'docker-info' $arguments
    $global:LASTEXITCODE = if ($global:QualityFixtureMode -eq 'docker-failure') { 7 } else { 0 }
}
function global:dotnet {
    $arguments = @($args | ForEach-Object { [string] $_ })
    $kind = ''
    if ($arguments[0] -eq 'restore') { $kind = 'audited-restore' }
    elseif ($arguments[0] -eq 'build') {
        $kind = if ($global:QualityFixtureScannerStarted) { 'scanner-build' } else { 'strict-build' }
    }
    elseif ($arguments[0] -eq 'clean') { $kind = 'scanner-clean' }
    elseif ($arguments[0] -eq 'test' -and $arguments[1] -eq 'Fleetory.sln') { $kind = 'solution-tests' }
    elseif ($arguments[0] -eq 'test' -and $arguments[1] -eq 'tests/Fleetory.Architecture.Tests/Fleetory.Architecture.Tests.csproj') {
        $kind = 'architecture-tests'
    }
    elseif ($arguments.Count -eq 2 -and $arguments[0] -eq 'tool' -and $arguments[1] -eq 'restore') { $kind = 'tool-restore' }
    elseif ($arguments.Count -gt 3 -and $arguments[0] -eq 'tool' -and $arguments[1] -eq 'run') {
        if ($arguments[2] -eq 'dotnet-coverage' -and $arguments -contains 'collect') { $kind = 'coverage-collect' }
        elseif ($arguments[2] -eq 'dotnet-sonarscanner' -and $arguments -contains 'begin') {
            $kind = 'scanner-begin'
            $global:QualityFixtureScannerStarted = $true
        }
        elseif ($arguments[2] -eq 'dotnet-sonarscanner' -and $arguments -contains 'end') { $kind = 'scanner-end' }
    }
    if (-not $kind) { throw 'Unexpected fixture dotnet command.' }
    Write-FixtureTrace $kind $arguments
    if ($kind -eq 'solution-tests' -and
        ($arguments -join ' ') -cne 'test Fleetory.sln -c Release --no-build --no-restore') {
        throw 'Strict gate did not request the unfiltered Release solution suite.'
    }
    $failures = @{
        'audit-failure' = 'audited-restore'
        'build-failure' = 'strict-build'
        'tool-failure' = 'tool-restore'
        'suite-failure' = 'coverage-collect'
        'architecture-failure' = 'architecture-tests'
        'configured-suite-failure' = 'solution-tests'
        'configured-architecture-failure' = 'architecture-tests'
        'configured-audit-failure' = 'audited-restore'
        'configured-build-failure' = 'strict-build'
        'scanner-begin-failure' = 'scanner-begin'
        'scanner-build-failure' = 'scanner-build'
        'scanner-end-failure' = 'scanner-end'
        'scanner-suite-failure' = 'coverage-collect'
    }
    if ($failures.ContainsKey($global:QualityFixtureMode) -and
        $kind -eq $failures[$global:QualityFixtureMode]) {
        $global:LASTEXITCODE = 17
        return
    }
    if ($kind -eq 'coverage-collect') {
        $collectIndex = [Array]::IndexOf($arguments, 'collect')
        if ($collectIndex + 1 -ge $arguments.Count -or
            $arguments[$collectIndex + 1] -cne 'dotnet test Fleetory.sln -c Release --no-build --no-restore') {
            throw 'Collector did not request the unfiltered full solution suite.'
        }
    }
    if ($kind -eq 'coverage-collect' -and $global:QualityFixtureMode -ne 'coverage-missing') {
        $index = [Array]::IndexOf($arguments, '-o')
        if ($index -lt 0 -or $index + 1 -ge $arguments.Count) { throw 'Missing coverage output path.' }
        $report = $arguments[$index + 1]
        $covered = if ($global:QualityFixtureMode -eq 'coverage-low') { 79 } elseif ($global:QualityFixtureMode -eq 'minimum') { 80 } else { 90 }
        $module = if ($global:QualityFixtureMode -eq 'coverage-tests-only') { 'Fleetory.Core.Tests.dll' } else { 'Fleetory.Core.dll' }
        $xml = '<results><modules><module name="' + $module + '" lines_covered="' + $covered +
            '" lines_partially_covered="0" lines_not_covered="' + (100 - $covered) + '" /></modules></results>'
        if ($global:QualityFixtureMode -eq 'coverage-empty') { $xml = '' }
        if ($global:QualityFixtureMode -eq 'coverage-malformed') { $xml = '<invalid' }
        [IO.File]::WriteAllText($report, $xml)
    }
    $global:LASTEXITCODE = 0
}
& (Join-Path $PSScriptRoot ('eng/' + $Entry))
exit $LASTEXITCODE
'@

function Invoke-QualityFixture([string] $Mode, [string] $Entry = 'verify-quality.ps1') {
    $caseRoot = Join-Path $work ($Mode + '-' + $Entry.Replace('.ps1',''))
    foreach ($directory in @('eng','tests/Fleetory.Persistence.Tests','artifacts/coverage','.sonarqube')) {
        [void](New-Item -ItemType Directory -Path (Join-Path $caseRoot $directory) -Force)
    }
    Copy-Item -LiteralPath $quality, (Join-Path $repo 'eng/verify-sonar.ps1') -Destination (Join-Path $caseRoot 'eng')
    [IO.File]::WriteAllText((Join-Path $caseRoot 'tests/Fleetory.Persistence.Tests/Fleetory.Persistence.Tests.csproj'), '<Project />', $utf8)
    $report = Join-Path $caseRoot 'artifacts/coverage/coverage.xml'
    [IO.File]::WriteAllText($report, '<results><modules><module name="Fleetory.Core.dll" lines_covered="100" lines_partially_covered="0" lines_not_covered="0" /></modules></results>', $utf8)
    [IO.File]::WriteAllText((Join-Path $caseRoot 'artifacts/coverage/retained.txt'), 'unrelated generated output', $utf8)
    if ($Mode -eq 'coverage-directory') {
        Remove-Item -LiteralPath $report
        [void](New-Item -ItemType Directory -Path $report)
        [IO.File]::WriteAllText((Join-Path $report 'retained.txt'), 'directory must not be deleted', $utf8)
    }
    $driverPath = Join-Path $caseRoot 'driver.ps1'
    [IO.File]::WriteAllText($driverPath, $driver, [Text.UTF8Encoding]::new($true))
    $output = & ([Environment]::ProcessPath) -NoProfile -File $driverPath $Mode $Entry 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine
    Assert-True (-not $text.Contains('fixture-token')) 'Orchestrator printed a scanner credential.'
    $tracePath = Join-Path $caseRoot 'trace.jsonl'
    $trace = @()
    if (Test-Path -LiteralPath $tracePath) {
        $trace = @(Get-Content -LiteralPath $tracePath | ForEach-Object { $_ | ConvertFrom-Json -AsHashtable })
    }
    return [pscustomobject]@{ Code=$exitCode; Text=$text; Trace=$trace; Root=$caseRoot }
}

try {
    # Verify the pinned real collector's exit behavior, not only a stubbed convention.
    [void](New-Item -ItemType Directory -Path $work -Force)
    $null = & dotnet tool restore 2>&1
    Assert-True ($LASTEXITCODE -eq 0) 'Pinned coverage tool restore failed.'
    $failureChild = Join-Path $work 'expected-failure.ps1'
    [IO.File]::WriteAllText($failureChild,
        '[IO.File]::WriteAllText((Join-Path $PSScriptRoot ''child-ran.txt''),''expected-failure''); exit 17',
        [Text.UTF8Encoding]::new($true))
    $childCommand = '"' + [Environment]::ProcessPath + '" -NoProfile -File "' + $failureChild + '"'
    $null = & dotnet tool run dotnet-coverage --allow-roll-forward -- collect $childCommand -f xml -o (Join-Path $work 'failure.xml') 2>&1
    $nativeExit = $LASTEXITCODE
    Assert-True ($nativeExit -eq 17 -and (Test-Path -LiteralPath (Join-Path $work 'child-ran.txt'))) 'Pinned collector did not propagate the failing child exit.'

    foreach ($mode in @('local','minimum','configured','standalone')) {
        $entry = if ($mode -eq 'standalone') { 'verify-sonar.ps1' } else { 'verify-quality.ps1' }
        $result = Invoke-QualityFixture $mode $entry
        $expectedCode = if ($mode -in @('local','minimum')) { 2 } else { 0 }
        Assert-True ($result.Code -eq $expectedCode) ("Unexpected success-path exit for " + $mode + ': ' + $result.Text)
        $suiteRequests = @($result.Trace | Where-Object { $_.kind -in @('solution-tests','coverage-collect') })
        $expectedSuites = if ($mode -eq 'configured') { 2 } else { 1 }
        Assert-True ($suiteRequests.Count -eq $expectedSuites) ("Wrong full-suite count for " + $mode + ': ' + $suiteRequests.Count)
        Assert-True (@($result.Trace | Where-Object { $_.kind -eq 'coverage-collect' }).Count -eq 1) 'Coverage collection count changed.'
        if ($mode -ne 'standalone') {
            Assert-True (@($result.Trace | Where-Object { $_.kind -eq 'architecture-tests' }).Count -eq 1) 'Independent architecture gate was lost.'
            $audit = @($result.Trace | Where-Object { $_.kind -eq 'audited-restore' })
            Assert-True ($audit.Count -eq 1) 'Audited strict restore count changed.'
            foreach ($argument in @('--force','-warnaserror','-p:FleetoryRequireDependencyAudit=true','-p:NuGetAudit=true','-p:NuGetAuditMode=all','-p:NuGetAuditLevel=low','-p:RestoreUseStaticGraphEvaluation=false')) {
                Assert-True ($audit[0].arguments -contains $argument) 'Strict dependency audit flag was lost.'
            }
            $strict = @($result.Trace | Where-Object { $_.kind -eq 'strict-build' })
            Assert-True ($strict.Count -eq 1 -and $strict[0].arguments -contains '--no-restore') 'Strict build gate changed.'
            $architecture = @($result.Trace | Where-Object { $_.kind -eq 'architecture-tests' })[0]
            Assert-True ($architecture.arguments -contains '--no-build' -and $architecture.arguments -contains '--no-restore' -and
                $architecture.arguments -notcontains '--filter') 'Architecture execution was filtered or rebuilt.'
        }
        if ($mode -in @('local','minimum')) {
            Assert-True ($suiteRequests[0].kind -eq 'coverage-collect') 'Unconfigured run tested the solution before coverage collection.'
            Assert-True ($result.Text -match 'TESTS\s+PASS' -and $result.Text -match 'ARCHITECTURE TESTS\s+PASS' -and $result.Text -match 'COVERAGE\s+\d+[.,]\d+% / PASS') 'Local summary lost a successful gate.'
            Assert-True ($result.Text -match 'SONAR QUALITY GATE\s+NOT VERIFIED') 'Unconfigured run claimed an external gate.'
            Assert-True (Test-Path -LiteralPath (Join-Path $result.Root 'artifacts/coverage/retained.txt')) 'Local run deleted unrelated coverage output.'
            $localKinds = @($result.Trace | ForEach-Object { $_.kind })
            Assert-True ([Array]::IndexOf($localKinds,'strict-build') -lt [Array]::IndexOf($localKinds,'coverage-collect') -and
                [Array]::IndexOf($localKinds,'coverage-collect') -lt [Array]::IndexOf($localKinds,'architecture-tests')) 'Local strict build/test/architecture order changed.'
        } else {
            $kinds = @($result.Trace | ForEach-Object { $_.kind })
            $begin = [Array]::IndexOf($kinds, 'scanner-begin')
            $build = [Array]::IndexOf($kinds, 'scanner-build')
            $collect = [Array]::IndexOf($kinds, 'coverage-collect')
            $end = [Array]::IndexOf($kinds, 'scanner-end')
            Assert-True ($begin -gt [Array]::IndexOf($kinds,'scanner-clean') -and $build -gt $begin -and $collect -gt $build -and $end -gt $collect) 'Standalone Sonar sequence changed.'
            if ($mode -eq 'configured') {
                Assert-True ([Array]::IndexOf($kinds,'strict-build') -lt [Array]::IndexOf($kinds,'solution-tests') -and
                    [Array]::IndexOf($kinds,'solution-tests') -lt [Array]::IndexOf($kinds,'architecture-tests') -and
                    [Array]::IndexOf($kinds,'architecture-tests') -lt [Array]::IndexOf($kinds,'scanner-clean')) 'Sonar ran before independent strict prerequisites.'
            }
            $beginCall = @($result.Trace | Where-Object { $_.kind -eq 'scanner-begin' })[0]
            Assert-True ($beginCall.arguments -contains '/d:sonar.qualitygate.wait=true') 'External gate wait was disabled.'
            $scanBuild = @($result.Trace | Where-Object { $_.kind -eq 'scanner-build' })[0]
            Assert-True ($scanBuild.arguments -contains '--no-incremental' -and $scanBuild.arguments -contains '--disable-build-servers') 'Sonar build lost required isolation flags.'
        }
        $script:passed++
    }

    foreach ($mode in @('partial-host','partial-project','partial-token','partial-whitespace',
        'docker-failure','audit-failure','build-failure','tool-failure','suite-failure','architecture-failure',
        'coverage-missing','coverage-empty','coverage-malformed','coverage-low','coverage-tests-only','coverage-directory',
        'scanner-begin-failure','scanner-build-failure','scanner-end-failure','scanner-suite-failure',
        'configured-suite-failure','configured-architecture-failure','configured-audit-failure','configured-build-failure')) {
        $result = Invoke-QualityFixture $mode
        Assert-True ($result.Code -eq 1) ("Failure case did not fail closed: " + $mode + ': ' + $result.Text)
        Assert-True ($result.Text -notmatch 'SONAR QUALITY GATE\s+PASS') 'Failed run claimed external gate success.'
        if ($mode.StartsWith('partial-')) {
            Assert-True ($result.Trace.Count -eq 0) 'Partial Sonar configuration ran expensive work before failing.'
        }
        if ($mode -in @('suite-failure','architecture-failure','audit-failure','build-failure') -or $mode.StartsWith('configured-')) {
            Assert-True (@($result.Trace | Where-Object { $_.kind -eq 'scanner-begin' }).Count -eq 0) 'Sonar ran after a failed strict prerequisite.'
        }
        if ($mode -eq 'coverage-directory') {
            Assert-True (Test-Path -LiteralPath (Join-Path $result.Root 'artifacts/coverage/coverage.xml/retained.txt')) 'Rejected coverage directory was modified.'
        }
        $script:passed++
    }
    Write-Host ("QUALITY ORCHESTRATION TESTS PASS: " + $passed + " CLI scenarios and native collector exit 17; one covered local suite, independent strict/Sonar builds, architecture, fresh coverage, fail-closed errors and unconfigured exit 2.")
}
finally { Remove-FleetoryTestArtifacts -Work $work -RepoRoot $repo }
$global:LASTEXITCODE = 0

