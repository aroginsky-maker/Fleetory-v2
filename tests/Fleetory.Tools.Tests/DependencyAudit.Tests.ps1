$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:DOTNET_CLI_UI_LANGUAGE = 'en-US'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$work = Join-Path $repo ('artifacts/dependency-audit-target-' + [Guid]::NewGuid().ToString('N'))
$harness = Join-Path $work 'audit.proj'
$targetPath = [Security.SecurityElement]::Escape((Join-Path $repo 'Directory.Solution.targets'))
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source (Join-Path $repo 'eng/verify-quality.ps1') -Names @('Get-ProductionLineCoverage')

function Invoke-DependencyAuditTarget([hashtable] $Overrides, [string] $Target = 'AssertFleetoryDependencyAudit') {
    $properties = @{
        FleetoryRequireDependencyAudit = 'true'
        NuGetAudit = 'true'
        NuGetAuditMode = 'all'
        NuGetAuditLevel = 'low'
        RestoreUseStaticGraphEvaluation = 'false'
        RestoreProjectCount = '2'
        RestoreProjectsAuditedCount = '2'
        RestoreSkippedCount = '0'
    }
    foreach ($key in $Overrides.Keys) { $properties[$key] = $Overrides[$key] }
    $arguments = @('msbuild', $harness, '-nologo', '-verbosity:minimal', "-target:$Target", '-warnaserror')
    foreach ($key in $properties.Keys) { $arguments += "-property:${key}=$($properties[$key])" }
    $output = & dotnet @arguments 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join "`n") }
}

try {
    [void](New-Item -ItemType Directory -Path $work)
    $xml = @'
<Project>
  <Import Project="{0}" />
  <Target Name="EmitAuditWarning">
    <Warning Code="$(AuditWarningCode)" Text="Synthetic audit warning for fail-closed gate verification." />
  </Target>
</Project>
'@ -f $targetPath
    [IO.File]::WriteAllText($harness, $xml, [Text.UTF8Encoding]::new($false))
    $valid = Invoke-DependencyAuditTarget @{}
    if ($valid.ExitCode -ne 0 -or $valid.Output -notlike '*DEPENDENCY AUDIT COVERAGE: 2/2*') {
        throw 'A fully covered NuGet audit was not accepted.'
    }
    $invalid = @(
        @{ NuGetAudit = 'false' },
        @{ NuGetAuditMode = 'direct' },
        @{ NuGetAuditLevel = 'high' },
        @{ RestoreUseStaticGraphEvaluation = 'true' },
        @{ RestoreProjectCount = '' },
        @{ RestoreProjectCount = '0'; RestoreProjectsAuditedCount = '0' },
        @{ RestoreProjectCount = '-1'; RestoreProjectsAuditedCount = '-1' },
        @{ RestoreProjectCount = 'not-a-count'; RestoreProjectsAuditedCount = 'not-a-count' },
        @{ RestoreProjectsAuditedCount = '' },
        @{ RestoreProjectsAuditedCount = '1' },
        @{ RestoreProjectsAuditedCount = '3' },
        @{ RestoreSkippedCount = '' },
        @{ RestoreSkippedCount = '1' }
    )
    foreach ($properties in $invalid) {
        $failed = Invoke-DependencyAuditTarget $properties
        if ($failed.ExitCode -eq 0 -or $failed.Output -like '*DEPENDENCY AUDIT COVERAGE:*') {
            throw 'Incomplete or weakened dependency audit was accepted.'
        }
    }
    foreach ($code in @('NU1900', 'NU1901', 'NU1902', 'NU1903', 'NU1904', 'NU1905')) {
        $failed = Invoke-DependencyAuditTarget @{ AuditWarningCode = $code } 'EmitAuditWarning'
        if ($failed.ExitCode -eq 0 -or $failed.Output -notlike "*error ${code}:*") {
            throw "Audit warning $code did not fail the actual MSBuild command."
        }
    }
    Write-Host 'DEPENDENCY AUDIT GATE PASS: complete graph accepted; 13 incomplete/weakened configurations and all six NuGet audit warning codes rejected.'
    $global:LASTEXITCODE = 0
}
finally { Remove-FleetoryTestArtifacts $work $repo }
