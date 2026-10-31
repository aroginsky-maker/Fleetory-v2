param(
    [ValidatePattern('^[a-z0-9-]{1,64}$')]
    [string] $Name = ([Guid]::NewGuid().ToString('N'))
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent $PSScriptRoot
$contextRoot = Join-Path $repoRoot 'artifacts/command-signer-container'
$contextPath = Join-Path $contextRoot $Name
$rawPublish = Join-Path (Join-Path $repoRoot 'artifacts/command-signer-publish') $Name
if (Test-Path -LiteralPath $contextPath) { throw 'Signer package output already exists.' }
if (Test-Path -LiteralPath $rawPublish) { throw 'Signer publish output already exists.' }
[void](New-Item -ItemType Directory -Path $contextPath)
$publish = Join-Path $contextPath 'publish'
$project = Join-Path $repoRoot 'src/Fleetory.CommandSigner.Host/Fleetory.CommandSigner.Host.csproj'
& dotnet publish $project -c Release --no-build --no-restore -p:UseAppHost=false -o $rawPublish --nologo
if ($LASTEXITCODE -ne 0) { throw 'Signer publish failed; run a Release build first.' }
$allowedAssemblies = @(
    'Fleetory.CommandSigner.Host', 'Fleetory.CommandSigning', 'Fleetory.Core.Contracts',
    'Fleetory.ModuleAbstractions', 'Fleetory.Security.Infrastructure',
    'Fleetory.Platform.Contracts', 'Fleetory.SharedKernel'
)
$files = @(Get-ChildItem -LiteralPath $rawPublish -File)
foreach ($file in $files) {
    if ($file.Extension -eq '.dll' -and $file.BaseName.StartsWith('Fleetory.', [StringComparison]::Ordinal) -and
        $allowedAssemblies -cnotcontains $file.BaseName) {
        throw 'Signer publish contains an unexpected Fleetory assembly.'
    }
}
[void](New-Item -ItemType Directory -Path $publish)
foreach ($file in $files) {
    if ($file.Extension -eq '.dll' -or $file.Name -in @(
        'Fleetory.CommandSigner.Host.deps.json', 'Fleetory.CommandSigner.Host.runtimeconfig.json')) {
        Copy-Item -LiteralPath $file.FullName -Destination $publish
    }
}
foreach ($required in @('Fleetory.CommandSigner.Host.dll',
    'Fleetory.CommandSigner.Host.deps.json', 'Fleetory.CommandSigner.Host.runtimeconfig.json')) {
    if (-not (Test-Path -LiteralPath (Join-Path $publish $required) -PathType Leaf)) {
        throw 'Signer publish is incomplete.'
    }
}
$profile = Join-Path $repoRoot 'infra/command-signer'
foreach ($fileName in @('Dockerfile', 'entrypoint.sh', '.dockerignore')) {
    Copy-Item -LiteralPath (Join-Path $profile $fileName) -Destination $contextPath
}
Write-Host ("Signer build context: {0}" -f $contextPath)
