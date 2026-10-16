$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ArtifactRoot = Join-Path $RepoRoot 'artifacts/server'
$WindowsOutput = Join-Path $ArtifactRoot 'win-x64'
$LinuxOutput = Join-Path $ArtifactRoot 'linux-x64'
$WindowsArchive = Join-Path $ArtifactRoot 'Fleetory.Server-win-x64.zip'
$LinuxArchive = Join-Path $ArtifactRoot 'Fleetory.Server-linux-x64.tar.gz'

$StrictBuildStatus = 'NOT RUN'
$TestsStatus = 'NOT RUN'
$ArchitectureTestsStatus = 'NOT RUN'
$WindowsPublishStatus = 'NOT RUN'
$LinuxPublishStatus = 'NOT RUN'
$WindowsRuntimeStatus = 'NOT VERIFIED'
$LinuxRuntimeStatus = 'NOT VERIFIED'
$HealthStatus = 'NOT RUN'
$CorrelationStatus = 'NOT RUN'

function Write-Summary {
    Write-Host ''
    Write-Host 'Fleetory PHASE 5 verification summary'
    Write-Host '------------------------------------'
    Write-Host ("STRICT BUILD        {0}" -f $StrictBuildStatus)
    Write-Host ("TESTS               {0}" -f $TestsStatus)
    Write-Host ("ARCHITECTURE TESTS  {0}" -f $ArchitectureTestsStatus)
    Write-Host ("WINDOWS PUBLISH     {0}" -f $WindowsPublishStatus)
    Write-Host ("LINUX PUBLISH       {0}" -f $LinuxPublishStatus)
    Write-Host ("WINDOWS RUNTIME     {0}" -f $WindowsRuntimeStatus)
    Write-Host ("LINUX RUNTIME       {0}" -f $LinuxRuntimeStatus)
    Write-Host ("HEALTH TESTS        {0}" -f $HealthStatus)
    Write-Host ("CORRELATION ID      {0}" -f $CorrelationStatus)
}

function Invoke-DotnetStep([string[]] $Arguments) {
    & dotnet @Arguments | Out-Host
    return $LASTEXITCODE
}

function Assert-PackageContents([string] $PackageDirectory, [string] $Rid) {
    $requiredFiles = @(
        'Fleetory.Server.dll',
        'Fleetory.Server.deps.json',
        'Fleetory.Server.runtimeconfig.json',
        'appsettings.json',
        'appsettings.Production.json'
    )

    foreach ($requiredFile in $requiredFiles) {
        $path = Join-Path $PackageDirectory $requiredFile
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Package '$Rid' is missing required file '$requiredFile'."
        }
    }

    if (Test-Path -LiteralPath (Join-Path $PackageDirectory 'appsettings.Development.json')) {
        throw "Package '$Rid' must not contain appsettings.Development.json."
    }

    $files = @(Get-ChildItem -LiteralPath $PackageDirectory -Recurse -File)
    $forbidden = @($files | Where-Object {
        $_.Extension -in @('.cs', '.csproj', '.sln', '.user', '.suo') -or
        $_.Name -like '*.Tests.dll' -or
        $_.Name -like '*.Tests.pdb' -or
        $_.FullName -match '[\\/](?:obj|bin|TestResults|coverage|\.sonarqube)[\\/]'
    })

    if ($forbidden.Count -gt 0) {
        throw "Package '$Rid' contains forbidden development/test artifacts: $($forbidden.FullName -join ', ')."
    }

    $secretKeyPattern = '"(?i:password|secret|token|api[_-]?key|connectionstrings?)"\s*:'
    foreach ($jsonFile in $files | Where-Object { $_.Extension -eq '.json' }) {
        $json = Get-Content -LiteralPath $jsonFile.FullName -Raw
        if ($json -match $secretKeyPattern) {
            throw "Package '$Rid' configuration '$($jsonFile.Name)' contains a secret-like configuration key."
        }
    }
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Invoke-PublishedServerSmokeTest([string] $RuntimeDirectory) {
    $entry = Join-Path $RuntimeDirectory 'Fleetory.Server.dll'
    if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) {
        throw "Published server entry point was not found: '$entry'."
    }

    $port = Get-FreeLoopbackPort
    $baseUrl = "http://127.0.0.1:$port"
    $stdout = Join-Path $ArtifactRoot 'phase5-smoke.stdout.log'
    $stderr = Join-Path $ArtifactRoot 'phase5-smoke.stderr.log'
    Remove-Item -Force $stdout, $stderr -ErrorAction SilentlyContinue

    $previousEnvironment = $env:ASPNETCORE_ENVIRONMENT
    $env:ASPNETCORE_ENVIRONMENT = 'Production'
    try {
        $startProcessArguments = @{
            FilePath = 'dotnet'
            ArgumentList = @(("`"{0}`"" -f $entry), '--urls', $baseUrl)
            WorkingDirectory = $RuntimeDirectory
            RedirectStandardOutput = $stdout
            RedirectStandardError = $stderr
            PassThru = $true
        }
        $process = Start-Process @startProcessArguments
    }
    finally {
        if ($null -eq $previousEnvironment) {
            Remove-Item Env:ASPNETCORE_ENVIRONMENT -ErrorAction SilentlyContinue
        }
        else {
            $env:ASPNETCORE_ENVIRONMENT = $previousEnvironment
        }
    }

    try {
        $liveResponse = $null
        for ($attempt = 0; $attempt -lt 80; $attempt++) {
            if ($process.HasExited) {
                $errorText = if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Raw } else { '' }
                throw "Published Fleetory.Server exited before becoming healthy. $errorText"
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

        $readyResponse = Invoke-WebRequest -Uri "$baseUrl/health/ready" -UseBasicParsing -TimeoutSec 5
        if ($readyResponse.StatusCode -ne 200) {
            throw "/health/ready returned HTTP $($readyResponse.StatusCode)."
        }
        $script:HealthStatus = 'PASS'

        $correlationId = 'phase5-published-smoke'
        $correlationResponse = Invoke-WebRequest -Uri "$baseUrl/health/live" `
            -UseBasicParsing `
            -TimeoutSec 5 `
            -Headers @{ 'X-Correlation-ID' = $correlationId }
        $actualCorrelationId = [string] $correlationResponse.Headers['X-Correlation-ID']
        if ($actualCorrelationId -ne $correlationId) {
            throw "CorrelationId response mismatch. Expected '$correlationId', actual '$actualCorrelationId'."
        }
        $script:CorrelationStatus = 'PASS'
    }
    finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit()
        }
    }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    $StrictBuildStatus = 'FAIL (.NET SDK missing)'
    Write-Summary
    exit 1
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
        Write-Summary
        exit 1
    }
    $TestsStatus = 'PASS'

    if ((Invoke-DotnetStep @(
        'test', 'tests/Fleetory.Architecture.Tests/Fleetory.Architecture.Tests.csproj',
        '-c', 'Release', '--no-build', '--no-restore'
    )) -ne 0) {
        $ArchitectureTestsStatus = 'FAIL'
        Write-Summary
        exit 1
    }
    $ArchitectureTestsStatus = 'PASS'

    try {
        & (Join-Path $PSScriptRoot 'package-server.ps1') -SkipSolutionRestore
        $WindowsPublishStatus = 'PASS'
        $LinuxPublishStatus = 'PASS'
    }
    catch {
        $WindowsPublishStatus = 'FAIL'
        $LinuxPublishStatus = 'FAIL'
        Write-Warning $_.Exception.Message
        Write-Summary
        exit 1
    }

    try {
        Assert-PackageContents $WindowsOutput 'win-x64'
        Assert-PackageContents $LinuxOutput 'linux-x64'
        if (-not (Test-Path -LiteralPath $WindowsArchive -PathType Leaf) -or (Get-Item $WindowsArchive).Length -le 0) {
            throw 'Windows ZIP package was not created or is empty.'
        }
        if (-not (Test-Path -LiteralPath $LinuxArchive -PathType Leaf) -or (Get-Item $LinuxArchive).Length -le 0) {
            throw 'Linux tar.gz package was not created or is empty.'
        }
    }
    catch {
        Write-Warning $_.Exception.Message
        $WindowsPublishStatus = 'FAIL (package validation)'
        $LinuxPublishStatus = 'FAIL (package validation)'
        Write-Summary
        exit 1
    }

    try {
        if ($env:OS -eq 'Windows_NT') {
            Invoke-PublishedServerSmokeTest $WindowsOutput
            $WindowsRuntimeStatus = 'PASS'
            $LinuxRuntimeStatus = 'NOT VERIFIED (cross-publish only)'
        }
        else {
            Invoke-PublishedServerSmokeTest $LinuxOutput
            $LinuxRuntimeStatus = 'PASS'
            $WindowsRuntimeStatus = 'NOT VERIFIED (cross-publish only)'
        }
    }
    catch {
        if ($env:OS -eq 'Windows_NT') {
            $WindowsRuntimeStatus = 'FAIL'
        }
        else {
            $LinuxRuntimeStatus = 'FAIL'
        }
        Write-Warning $_.Exception.Message
        Write-Summary
        exit 1
    }

    Write-Summary
    exit 0
}
finally {
    Pop-Location
}
