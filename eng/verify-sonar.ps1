$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CoverageRelativePath = 'artifacts/coverage/coverage.xml'
$CoveragePath = Join-Path $RepoRoot $CoverageRelativePath
$CoverageDirectory = Split-Path -Parent $CoveragePath
$SonarWorkingDirectory = Join-Path $RepoRoot '.sonarqube'

function Assert-DotnetAvailable {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw '.NET SDK was not found on PATH.'
    }
}

function Get-RequiredEnvironmentValue([string] $Name) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Required environment variable '$Name' is not set."
    }

    return $value
}

function Invoke-Dotnet([string[]] $Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet command failed with exit code $LASTEXITCODE."
    }
}

Assert-DotnetAvailable

$SonarHostUrl = Get-RequiredEnvironmentValue 'SONAR_HOST_URL'
$SonarProjectKey = Get-RequiredEnvironmentValue 'SONAR_PROJECT_KEY'
$SonarToken = Get-RequiredEnvironmentValue 'SONAR_TOKEN'
$SonarOrganization = [Environment]::GetEnvironmentVariable('SONAR_ORGANIZATION')
$SonarProjectName = [Environment]::GetEnvironmentVariable('SONAR_PROJECT_NAME')
$TimeoutRaw = [Environment]::GetEnvironmentVariable('SONAR_QUALITYGATE_TIMEOUT')
$SonarQualityGateTimeout = 300

$isSonarCloud = $SonarHostUrl -match '(^https?://)?([^/]+\.)?sonarcloud\.io(?:/|$)'
if ($isSonarCloud -and [string]::IsNullOrWhiteSpace($SonarOrganization)) {
    throw "SONAR_ORGANIZATION is required when SONAR_HOST_URL points to SonarQube Cloud."
}

if (-not [string]::IsNullOrWhiteSpace($TimeoutRaw)) {
    $parsedTimeout = 0
    if (-not [int]::TryParse($TimeoutRaw, [ref] $parsedTimeout) -or $parsedTimeout -le 0) {
        throw 'SONAR_QUALITYGATE_TIMEOUT must be a positive integer number of seconds.'
    }

    $SonarQualityGateTimeout = $parsedTimeout
}

Push-Location $RepoRoot
try {
    Invoke-Dotnet @('tool', 'restore')

    Remove-Item -Recurse -Force $CoverageDirectory -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $SonarWorkingDirectory -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $CoverageDirectory -Force | Out-Null

    Invoke-Dotnet @('clean', 'Fleetory.sln', '-c', 'Release', '--nologo')

    $beginArguments = @(
        'tool', 'run', 'dotnet-sonarscanner', '--allow-roll-forward', '--', 'begin',
        "/k:$SonarProjectKey",
        "/d:sonar.host.url=$SonarHostUrl",
        "/d:sonar.token=$SonarToken",
        "/d:sonar.cs.vscoveragexml.reportsPaths=$CoverageRelativePath",
        '/d:sonar.qualitygate.wait=true',
        "/d:sonar.qualitygate.timeout=$SonarQualityGateTimeout",
        '/d:sonar.exclusions=**/bin/**,**/obj/**,artifacts/**,.sonarqube/**'
    )

    if (-not [string]::IsNullOrWhiteSpace($SonarOrganization)) {
        $beginArguments += "/o:$SonarOrganization"
    }

    if (-not [string]::IsNullOrWhiteSpace($SonarProjectName)) {
        $beginArguments += "/n:$SonarProjectName"
    }

    Invoke-Dotnet $beginArguments

    Invoke-Dotnet @(
        'build', 'Fleetory.sln', '-c', 'Release',
        '--no-incremental', '--disable-build-servers'
    )

    $testCommand = 'dotnet test Fleetory.sln -c Release --no-build --no-restore'
    Invoke-Dotnet @(
        'tool', 'run', 'dotnet-coverage', '--allow-roll-forward', '--',
        'collect', $testCommand,
        '-f', 'xml',
        '-o', $CoveragePath
    )

    if (-not (Test-Path -LiteralPath $CoveragePath -PathType Leaf)) {
        throw "Coverage report was not created at '$CoveragePath'."
    }

    if ((Get-Item -LiteralPath $CoveragePath).Length -le 0) {
        throw "Coverage report '$CoveragePath' is empty."
    }

    Invoke-Dotnet @(
        'tool', 'run', 'dotnet-sonarscanner', '--allow-roll-forward', '--', 'end',
        "/d:sonar.token=$SonarToken"
    )

    Write-Host 'SONAR ANALYSIS      PASS'
    Write-Host 'SONAR QUALITY GATE  PASS'
}
finally {
    Pop-Location
}
