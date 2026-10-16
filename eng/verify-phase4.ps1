$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot
try {
    dotnet restore Fleetory.sln
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    dotnet build Fleetory.sln -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    dotnet test Fleetory.sln -c Release --no-build --no-restore
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
