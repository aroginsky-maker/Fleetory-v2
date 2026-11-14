# Fleetory PowerShell scripts are stored as UTF-8 with BOM for Windows PowerShell 5.1 compatibility.
# Console and child-process output are forced to UTF-8; dotnet CLI output is forced to English.
$Utf8Encoding = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $Utf8Encoding
[Console]::OutputEncoding = $Utf8Encoding
$OutputEncoding = $Utf8Encoding
$env:DOTNET_CLI_UI_LANGUAGE = 'en-US'

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$PersistenceTestProject = 'tests/Fleetory.Persistence.Tests/Fleetory.Persistence.Tests.csproj'
$ArchitectureTestProject = 'tests/Fleetory.Architecture.Tests/Fleetory.Architecture.Tests.csproj'
$ArtifactRoot = Join-Path $RepoRoot 'artifacts/server'
$WindowsOutput = Join-Path $ArtifactRoot 'win-x64'
$LinuxOutput = Join-Path $ArtifactRoot 'linux-x64'
$WindowsArchive = Join-Path $ArtifactRoot 'Fleetory.Server-win-x64.zip'
$LinuxArchive = Join-Path $ArtifactRoot 'Fleetory.Server-linux-x64.tar.gz'
$RuntimeRequiredFiles = @(
    'Microsoft.EntityFrameworkCore.dll',
    'Microsoft.EntityFrameworkCore.Relational.dll',
    'Npgsql.dll',
    'Npgsql.EntityFrameworkCore.PostgreSQL.dll'
)

$StrictBuildStatus = 'NOT RUN'
$TestsStatus = 'NOT RUN'
$ArchitectureTestsStatus = 'NOT RUN'
$PostgreSqlContainerStatus = 'NOT RUN'
$PostgreSqlConnectivityStatus = 'NOT RUN'
$MigrationsStatus = 'NOT RUN'
$PersistenceTestsStatus = 'NOT RUN'
$HealthReadyStatus = 'NOT RUN'
$WindowsPublishStatus = 'NOT RUN'
$LinuxPublishStatus = 'NOT RUN'
$ServerPackageStatus = 'NOT RUN'
$CurrentHostRuntimeStatus = 'NOT RUN'

function Write-Summary {
    Write-Host ''
    Write-Host 'Fleetory PHASE 6 verification summary'
    Write-Host '------------------------------------'
    Write-Host ("STRICT BUILD             {0}" -f $StrictBuildStatus)
    Write-Host ("TESTS                    {0}" -f $TestsStatus)
    Write-Host ("ARCHITECTURE TESTS       {0}" -f $ArchitectureTestsStatus)
    Write-Host ("POSTGRESQL CONTAINER     {0}" -f $PostgreSqlContainerStatus)
    Write-Host ("POSTGRESQL CONNECTIVITY  {0}" -f $PostgreSqlConnectivityStatus)
    Write-Host ("MIGRATIONS               {0}" -f $MigrationsStatus)
    Write-Host ("PERSISTENCE TESTS        {0}" -f $PersistenceTestsStatus)
    Write-Host ("DATABASE READINESS       {0}" -f $HealthReadyStatus)
    Write-Host ("WINDOWS PUBLISH          {0}" -f $WindowsPublishStatus)
    Write-Host ("LINUX PUBLISH            {0}" -f $LinuxPublishStatus)
    Write-Host ("SERVER PACKAGE           {0}" -f $ServerPackageStatus)
    Write-Host ("CURRENT HOST RUNTIME     {0}" -f $CurrentHostRuntimeStatus)
}

function Invoke-DotnetStep([string[]] $Arguments) {
    & dotnet @Arguments | Out-Host
    return $LASTEXITCODE
}

function Test-DockerAvailable {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        return $false
    }

    & docker info --format '{{.ServerVersion}}' *> $null
    return $LASTEXITCODE -eq 0
}

function Assert-ExternalTestConnectionString([string] $ConnectionString) {
    $builder = [System.Data.Common.DbConnectionStringBuilder]::new()
    try {
        $builder.ConnectionString = $ConnectionString
    }
    catch {
        throw 'FLEETORY_TEST_CONNECTION_STRING is not a valid connection string.'
    }

    if (-not $builder.ContainsKey('Database')) {
        throw 'FLEETORY_TEST_CONNECTION_STRING must contain an explicit Database value.'
    }

    $databaseName = [string] $builder['Database']
    if ([string]::IsNullOrWhiteSpace($databaseName) -or
        $databaseName.IndexOf('test', [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
        $databaseName -in @('postgres', 'template0', 'template1')) {
        throw "FLEETORY_TEST_CONNECTION_STRING must target a test database whose name contains 'test'."
    }
}

. (Join-Path $PSScriptRoot 'server-package-helpers.ps1')

function Invoke-PublishedServerSmokeTest([string] $RuntimeDirectory) {
    $entry = Join-Path $RuntimeDirectory 'Fleetory.Server.dll'
    if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) {
        throw "Published server entry point was not found: '$entry'."
    }

    # The published-package smoke test verifies startup, liveness and CorrelationId.
    # Real ready/unready PostgreSQL behavior is verified in the Testcontainers integration suite.
    $smokeConnectionString = 'Host=127.0.0.1;Port=1;Database=fleetory_test_package_smoke;Timeout=1;Command Timeout=1;Pooling=false'
    $port = Get-FreeLoopbackPort
    $baseUrl = "http://127.0.0.1:$port"
    $stdout = Join-Path $ArtifactRoot 'phase6-smoke.stdout.log'
    $stderr = Join-Path $ArtifactRoot 'phase6-smoke.stderr.log'
    Remove-Item -Force $stdout, $stderr -ErrorAction SilentlyContinue

    $secretDirectory = Join-Path $ArtifactRoot 'phase6-smoke-secrets'
    New-Item -ItemType Directory -Path $secretDirectory -Force | Out-Null
    $secretFile = Join-Path $secretDirectory 'fleetory-postgresql'
    [System.IO.File]::WriteAllText($secretFile, $smokeConnectionString, $Utf8Encoding)
    if ($env:OS -ne 'Windows_NT') {
        & chmod 600 $secretFile
    }

    $previousEnvironment = $env:ASPNETCORE_ENVIRONMENT
    $previousConnectionString = $env:FLEETORY_ConnectionStrings__Fleetory
    $previousSecretDirectory = $env:FLEETORY_Fleetory__Secrets__Directory
    $env:ASPNETCORE_ENVIRONMENT = 'Production'
    Remove-Item Env:FLEETORY_ConnectionStrings__Fleetory -ErrorAction SilentlyContinue
    $env:FLEETORY_Fleetory__Secrets__Directory = $secretDirectory

    try {
        $startArguments = @{
            FilePath = 'dotnet'
            ArgumentList = @(("`"{0}`"" -f $entry), '--urls', $baseUrl)
            WorkingDirectory = $RuntimeDirectory
            RedirectStandardOutput = $stdout
            RedirectStandardError = $stderr
            PassThru = $true
        }
        if ($env:OS -eq 'Windows_NT') {
            $startArguments.WindowStyle = 'Hidden'
        }
        $process = Start-Process @startArguments
    }
    catch {
        Remove-Item -LiteralPath $secretFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $secretDirectory -ErrorAction SilentlyContinue
        throw
    }
    finally {
        if ($null -eq $previousEnvironment) {
            Remove-Item Env:ASPNETCORE_ENVIRONMENT -ErrorAction SilentlyContinue
        }
        else {
            $env:ASPNETCORE_ENVIRONMENT = $previousEnvironment
        }

        if ($null -eq $previousConnectionString) {
            Remove-Item Env:FLEETORY_ConnectionStrings__Fleetory -ErrorAction SilentlyContinue
        }
        else {
            $env:FLEETORY_ConnectionStrings__Fleetory = $previousConnectionString
        }

        if ($null -eq $previousSecretDirectory) {
            Remove-Item Env:FLEETORY_Fleetory__Secrets__Directory -ErrorAction SilentlyContinue
        }
        else {
            $env:FLEETORY_Fleetory__Secrets__Directory = $previousSecretDirectory
        }
    }

    try {
        $liveResponse = $null
        for ($attempt = 0; $attempt -lt 80; $attempt++) {
            if ($process.HasExited) {
                $errorText = if (Test-Path -LiteralPath $stderr) {
                    Get-Content -LiteralPath $stderr -Raw
                }
                else {
                    ''
                }
                throw "Published Fleetory.Server exited before becoming live. $errorText"
            }

            try {
                $liveResponse = Invoke-WebRequest -Uri "$baseUrl/health/live" -UseBasicParsing -TimeoutSec 2
                if ($liveResponse.StatusCode -eq 200) {
                    break
                }
            }
            catch {
                Start-Sleep -Milliseconds 250
            }
        }

        if ($null -eq $liveResponse -or $liveResponse.StatusCode -ne 200) {
            throw 'Published Fleetory.Server did not pass /health/live within the timeout.'
        }

        $correlationId = 'phase6-published-smoke'
        $correlationResponse = Invoke-WebRequest -Uri "$baseUrl/health/live" `
            -UseBasicParsing `
            -TimeoutSec 5 `
            -Headers @{ 'X-Correlation-ID' = $correlationId }
        $actualCorrelationId = [string] $correlationResponse.Headers['X-Correlation-ID']
        if ($actualCorrelationId -ne $correlationId) {
            throw "CorrelationId response mismatch. Expected '$correlationId', actual '$actualCorrelationId'."
        }
    }
    finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit()
        }
        Remove-Item -LiteralPath $secretFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $secretDirectory -ErrorAction SilentlyContinue
    }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    $StrictBuildStatus = 'FAIL (.NET SDK missing)'
    Write-Summary
    exit 1
}

$ExternalTestConnectionString = [Environment]::GetEnvironmentVariable('FLEETORY_TEST_CONNECTION_STRING')
$UsingExternalTestDatabase = -not [string]::IsNullOrWhiteSpace($ExternalTestConnectionString)

if ($UsingExternalTestDatabase) {
    try {
        Assert-ExternalTestConnectionString $ExternalTestConnectionString
        $PostgreSqlContainerStatus = 'NOT RUN (external override)'
    }
    catch {
        $PostgreSqlConnectivityStatus = 'FAIL (unsafe external test DB configuration)'
        Write-Warning $_.Exception.Message
        Write-Summary
        exit 1
    }
}
elseif (-not (Test-DockerAvailable)) {
    $PostgreSqlContainerStatus = 'FAIL (Docker unavailable)'
    Write-Warning 'PostgreSQL integration verification requires Docker or an explicit FLEETORY_TEST_CONNECTION_STRING.'
    Write-Summary
    exit 1
}
else {
    $PostgreSqlContainerStatus = 'READY (Docker available; Testcontainers will create PostgreSQL)'
}

Push-Location $RepoRoot
try {
    if ((Invoke-DotnetStep @('tool', 'restore')) -ne 0) {
        $MigrationsStatus = 'FAIL (tool restore)'
        Write-Summary
        exit 1
    }

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
        Write-Summary
        exit 1
    }
    $TestsStatus = 'PASS'

    if ((Invoke-DotnetStep @(
        'test', $ArchitectureTestProject,
        '-c', 'Release', '--no-build', '--no-restore'
    )) -ne 0) {
        $ArchitectureTestsStatus = 'FAIL'
        Write-Summary
        exit 1
    }
    $ArchitectureTestsStatus = 'PASS'

    if ((Invoke-DotnetStep @(
        'test', $PersistenceTestProject,
        '-c', 'Release', '--no-build', '--no-restore'
    )) -ne 0) {
        if (-not $UsingExternalTestDatabase) {
            $PostgreSqlContainerStatus = 'FAIL'
        }
        $PostgreSqlConnectivityStatus = 'FAIL'
        $MigrationsStatus = 'FAIL'
        $PersistenceTestsStatus = 'FAIL'
        $HealthReadyStatus = 'FAIL'
        Write-Summary
        exit 1
    }

    if (-not $UsingExternalTestDatabase) {
        $PostgreSqlContainerStatus = 'PASS'
    }
    $PostgreSqlConnectivityStatus = 'PASS'
    $MigrationsStatus = 'PASS'
    $PersistenceTestsStatus = 'PASS'
    $HealthReadyStatus = 'PASS'

    try {
        & (Join-Path $PSScriptRoot 'package-server.ps1') -SkipSolutionRestore
        $WindowsPublishStatus = 'PASS'
        $LinuxPublishStatus = 'PASS'

        Assert-PackageContents $WindowsOutput 'win-x64' $RuntimeRequiredFiles
        Assert-PackageContents $LinuxOutput 'linux-x64' $RuntimeRequiredFiles

        if (-not (Test-Path -LiteralPath $WindowsArchive -PathType Leaf) -or
            (Get-Item -LiteralPath $WindowsArchive).Length -le 0) {
            throw 'Windows ZIP package was not created or is empty.'
        }

        if (-not (Test-Path -LiteralPath $LinuxArchive -PathType Leaf) -or
            (Get-Item -LiteralPath $LinuxArchive).Length -le 0) {
            throw 'Linux tar.gz package was not created or is empty.'
        }

        $ServerPackageStatus = 'PASS'
    }
    catch {
        $WindowsPublishStatus = 'FAIL'
        $LinuxPublishStatus = 'FAIL'
        $ServerPackageStatus = 'FAIL'
        Write-Warning $_.Exception.Message
        Write-Summary
        exit 1
    }

    try {
        if ($env:OS -eq 'Windows_NT') {
            Invoke-PublishedServerSmokeTest $WindowsOutput
            $CurrentHostRuntimeStatus = 'PASS (Windows)'
        }
        else {
            Invoke-PublishedServerSmokeTest $LinuxOutput
            $CurrentHostRuntimeStatus = 'PASS (Linux)'
        }
    }
    catch {
        $CurrentHostRuntimeStatus = 'FAIL'
        Write-Warning $_.Exception.Message
        Write-Summary
        exit 1
    }

    Write-Summary

    if ($UsingExternalTestDatabase) {
        Write-Warning 'External PostgreSQL verification passed, but PHASE 6 completion still requires the default disposable Testcontainers PostgreSQL run.'
        exit 2
    }

    exit 0
}
finally {
    Pop-Location
}
