$ErrorActionPreference = 'Stop'
$engine = ([Diagnostics.Process]::GetCurrentProcess()).MainModule.FileName
& $engine -NoLogo -NoProfile -ExecutionPolicy (Get-ExecutionPolicy) -File (Join-Path (Split-Path -Parent $PSScriptRoot) 'Fleetory.Tooling.Tests/Phase7Readiness.Tests.ps1') @args
exit $LASTEXITCODE
