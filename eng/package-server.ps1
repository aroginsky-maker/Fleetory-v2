[CmdletBinding()]
param(
    [switch] $SkipSolutionRestore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ServerProject = Join-Path $RepoRoot 'src/Fleetory.Server/Fleetory.Server.csproj'
$ArtifactRoot = Join-Path $RepoRoot 'artifacts/server'
$WindowsOutput = Join-Path $ArtifactRoot 'win-x64'
$LinuxOutput = Join-Path $ArtifactRoot 'linux-x64'
$WindowsArchive = Join-Path $ArtifactRoot 'Fleetory.Server-win-x64.zip'
$LinuxArchive = Join-Path $ArtifactRoot 'Fleetory.Server-linux-x64.tar.gz'

function Invoke-Dotnet([string[]] $Arguments) {
    & dotnet @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw '.NET SDK was not found on PATH.'
}

Push-Location $RepoRoot
try {
    if (Test-Path -LiteralPath $ArtifactRoot) {
        Remove-Item -LiteralPath $ArtifactRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Path $WindowsOutput -Force | Out-Null
    New-Item -ItemType Directory -Path $LinuxOutput -Force | Out-Null

    if (-not $SkipSolutionRestore) {
        Invoke-Dotnet @('restore', 'Fleetory.sln')
    }

    # RID-specific restores are deliberately performed immediately before each publish.
    Invoke-Dotnet @('restore', $ServerProject, '-r', 'win-x64')
    Invoke-Dotnet @(
        'publish', $ServerProject,
        '-c', 'Release',
        '-r', 'win-x64',
        '--self-contained', 'false',
        '-p:UseAppHost=false',
        '--no-restore',
        '-o', $WindowsOutput
    )

    Invoke-Dotnet @('restore', $ServerProject, '-r', 'linux-x64')
    Invoke-Dotnet @(
        'publish', $ServerProject,
        '-c', 'Release',
        '-r', 'linux-x64',
        '--self-contained', 'false',
        '-p:UseAppHost=false',
        '--no-restore',
        '-o', $LinuxOutput
    )

    if (Test-Path -LiteralPath $WindowsArchive) {
        Remove-Item -LiteralPath $WindowsArchive -Force
    }
    Compress-Archive -Path (Join-Path $WindowsOutput '*') -DestinationPath $WindowsArchive -CompressionLevel Optimal

    if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
        throw "The 'tar' command is required to create the Linux .tar.gz package."
    }
    if (Test-Path -LiteralPath $LinuxArchive) {
        Remove-Item -LiteralPath $LinuxArchive -Force
    }
    & tar -czf $LinuxArchive -C $LinuxOutput .
    if ($LASTEXITCODE -ne 0) {
        throw "tar failed with exit code $LASTEXITCODE."
    }

    Write-Host ''
    Write-Host 'Fleetory Server packaging summary'
    Write-Host '---------------------------------'
    Write-Host ("WINDOWS PUBLISH  PASS  {0}" -f $WindowsOutput)
    Write-Host ("LINUX PUBLISH    PASS  {0}" -f $LinuxOutput)
    Write-Host ("WINDOWS PACKAGE  PASS  {0}" -f $WindowsArchive)
    Write-Host ("LINUX PACKAGE    PASS  {0}" -f $LinuxArchive)
    Write-Host 'DEPLOYMENT MODEL framework-dependent (.NET 10 runtime required)'
}
finally {
    Pop-Location
}
