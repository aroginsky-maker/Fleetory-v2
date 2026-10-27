# Fleetory PowerShell scripts are stored as UTF-8 with BOM for Windows PowerShell 5.1 compatibility.
# Console and child-process text output are forced to UTF-8; dotnet CLI output is forced to English.
$Utf8Encoding = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $Utf8Encoding
[Console]::OutputEncoding = $Utf8Encoding
$OutputEncoding = $Utf8Encoding
$env:DOTNET_CLI_UI_LANGUAGE = 'en-US'

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CoveragePath = Join-Path $RepoRoot 'artifacts/coverage/coverage.xml'
$CoverageDirectory = Split-Path -Parent $CoveragePath
$Phase6PersistenceTestProject = Join-Path $RepoRoot 'tests/Fleetory.Persistence.Tests/Fleetory.Persistence.Tests.csproj'

$StrictBuildStatus = 'NOT RUN'
$TestsStatus = 'NOT RUN'
$ArchitectureTestsStatus = 'NOT RUN'
$CoverageStatus = 'NOT RUN'
$CoverageDisplay = 'NOT VERIFIED'
$SonarAnalysisStatus = 'NOT VERIFIED'
$SonarQualityGateStatus = 'NOT VERIFIED'

function Write-Summary {
    Write-Host ''
    Write-Host 'Fleetory quality verification summary'
    Write-Host '-------------------------------------'
    Write-Host ("STRICT BUILD        {0}" -f $StrictBuildStatus)
    Write-Host ("TESTS               {0}" -f $TestsStatus)
    Write-Host ("ARCHITECTURE TESTS  {0}" -f $ArchitectureTestsStatus)
    Write-Host ("COVERAGE            {0} / {1}" -f $CoverageDisplay, $CoverageStatus)
    Write-Host ("SONAR ANALYSIS      {0}" -f $SonarAnalysisStatus)
    Write-Host ("SONAR QUALITY GATE  {0}" -f $SonarQualityGateStatus)
}

function Invoke-DotnetStep([string[]] $Arguments) {
    & dotnet @Arguments | Out-Host
    return $LASTEXITCODE
}

function Get-ProductionLineCoverage([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Coverage report was not found at '$Path'."
    }

    [xml] $coverage = Get-Content -LiteralPath $Path -Raw
    $modules = @($coverage.results.modules.module) | Where-Object {
        $name = [string] $_.name
        $name -match '^Fleetory\.' -and $name -notmatch '\.Tests(?:\.dll)?$'
    }

    if ($modules.Count -eq 0) {
        throw 'Coverage report contains no Fleetory production modules.'
    }

    [long] $covered = 0
    [long] $partial = 0
    [long] $notCovered = 0

    foreach ($module in $modules) {
        $covered += [long] $module.lines_covered
        $partial += [long] $module.lines_partially_covered
        $notCovered += [long] $module.lines_not_covered
    }

    $total = $covered + $partial + $notCovered
    if ($total -le 0) {
        throw 'Coverage report contains no measurable production lines.'
    }

    return [math]::Round(($covered * 100.0) / $total, 2)
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    $StrictBuildStatus = 'FAIL (.NET SDK missing)'
    Write-Summary
    exit 1
}

if (Test-Path -LiteralPath $Phase6PersistenceTestProject -PathType Leaf) {
    $phase6ConnectionString = [Environment]::GetEnvironmentVariable('FLEETORY_TEST_CONNECTION_STRING')

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        $TestsStatus = 'FAIL (Docker unavailable for signer process isolation)'
        Write-Warning 'The full suite requires Docker for signer process isolation, including with an external PostgreSQL test database.'
        Write-Summary
        exit 1
    }

    & docker info --format '{{.ServerVersion}}' *> $null
    if ($LASTEXITCODE -ne 0) {
        $TestsStatus = 'FAIL (Docker unavailable for signer process isolation)'
        Write-Warning 'The full suite requires a running Docker engine for signer process isolation.'
        Write-Summary
        exit 1
    }

    if (-not [string]::IsNullOrWhiteSpace($phase6ConnectionString)) {
        $builder = [System.Data.Common.DbConnectionStringBuilder]::new()
        try {
            $builder.ConnectionString = $phase6ConnectionString
        }
        catch {
            $TestsStatus = 'FAIL (invalid PHASE 6 external test DB configuration)'
            Write-Warning 'FLEETORY_TEST_CONNECTION_STRING is not a valid connection string.'
            Write-Summary
            exit 1
        }

        if (-not $builder.ContainsKey('Database') -or
            ([string] $builder['Database']).IndexOf('test', [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            $TestsStatus = 'FAIL (unsafe PHASE 6 external test DB configuration)'
            Write-Warning "FLEETORY_TEST_CONNECTION_STRING must target a test database whose name contains 'test'."
            Write-Summary
            exit 1
        }
    }
}

Push-Location $RepoRoot
try {
    if ((Invoke-DotnetStep @('restore', 'Fleetory.sln')) -ne 0) {
        $StrictBuildStatus = 'FAIL (restore)'
        Write-Summary
        exit 1
    }

    if ((Invoke-DotnetStep @('build', 'Fleetory.sln', '-c', 'Release', '--no-restore')) -ne 0) {
        $StrictBuildStatus = 'FAIL'
        Write-Summary
        exit 1
    }

    $StrictBuildStatus = 'PASS'

    if ((Invoke-DotnetStep @('test', 'Fleetory.sln', '-c', 'Release', '--no-build', '--no-restore')) -ne 0) {
        $TestsStatus = 'FAIL'
    }
    else {
        $TestsStatus = 'PASS'
    }

    if ((Invoke-DotnetStep @(
        'test', 'tests/Fleetory.Architecture.Tests/Fleetory.Architecture.Tests.csproj',
        '-c', 'Release', '--no-build', '--no-restore'
    )) -ne 0) {
        $ArchitectureTestsStatus = 'FAIL'
    }
    else {
        $ArchitectureTestsStatus = 'PASS'
    }

    if ($TestsStatus -ne 'PASS' -or $ArchitectureTestsStatus -ne 'PASS') {
        Write-Summary
        exit 1
    }

    $SonarHostUrl = [Environment]::GetEnvironmentVariable('SONAR_HOST_URL')
    $SonarProjectKey = [Environment]::GetEnvironmentVariable('SONAR_PROJECT_KEY')
    $SonarToken = [Environment]::GetEnvironmentVariable('SONAR_TOKEN')
    $sonarValues = @($SonarHostUrl, $SonarProjectKey, $SonarToken)
    $setSonarValues = @($sonarValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count

    if ($setSonarValues -eq 3) {
        try {
            & (Join-Path $PSScriptRoot 'verify-sonar.ps1')
            $SonarAnalysisStatus = 'PASS'
            $SonarQualityGateStatus = 'PASS'
        }
        catch {
            $SonarAnalysisStatus = 'FAIL'
            $SonarQualityGateStatus = 'FAIL'
            Write-Warning $_.Exception.Message
        }
    }
    elseif ($setSonarValues -eq 0) {
        if ((Invoke-DotnetStep @('tool', 'restore')) -ne 0) {
            $CoverageStatus = 'FAIL (tool restore)'
            Write-Summary
            exit 1
        }

        Remove-Item -Recurse -Force $CoverageDirectory -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $CoverageDirectory -Force | Out-Null

        $testCommand = 'dotnet test Fleetory.sln -c Release --no-build --no-restore'
        if ((Invoke-DotnetStep @(
            'tool', 'run', 'dotnet-coverage', '--allow-roll-forward', '--',
            'collect', $testCommand,
            '-f', 'xml',
            '-o', $CoveragePath
        )) -ne 0) {
            $CoverageStatus = 'FAIL'
            Write-Summary
            exit 1
        }
    }
    else {
        $SonarAnalysisStatus = 'FAIL (incomplete environment)'
        $SonarQualityGateStatus = 'FAIL (incomplete environment)'
        Write-Summary
        exit 1
    }

    try {
        $coveragePercent = Get-ProductionLineCoverage $CoveragePath
        $CoverageDisplay = ('{0:N2}%' -f $coveragePercent)
        $CoverageStatus = if ($coveragePercent -ge 80.0) { 'PASS' } else { 'FAIL' }
    }
    catch {
        $CoverageStatus = 'FAIL'
        $CoverageDisplay = 'NOT AVAILABLE'
        Write-Warning $_.Exception.Message
    }

    Write-Summary

    if ($CoverageStatus -ne 'PASS') {
        exit 1
    }

    if ($setSonarValues -eq 0) {
        # Strict build and local coverage are verified, but the external Quality Gate is intentionally not claimed.
        exit 2
    }

    if ($SonarAnalysisStatus -ne 'PASS' -or $SonarQualityGateStatus -ne 'PASS') {
        exit 1
    }

    exit 0
}
finally {
    Pop-Location
}
