param(
    [Parameter(Mandatory)][string] $Source,
    [Parameter(Mandatory)][string[]] $Names
)

$syntaxErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $Source, [ref] $null, [ref] $syntaxErrors)
if ($syntaxErrors.Count -ne 0) {
    throw "Provisioner has a syntax error: $Source"
}
foreach ($name in $Names) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing provisioner function $name." }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Remove-FleetoryTestArtifacts([string] $Work, [string] $RepoRoot) {
    $target = [IO.Path]::GetFullPath($Work)
    $artifactsRoot = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot 'artifacts')).TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    $comparison = if ($env:OS -eq 'Windows_NT') {
        [StringComparison]::OrdinalIgnoreCase
    }
    else { [StringComparison]::Ordinal }
    if (-not $target.StartsWith($artifactsRoot, $comparison)) {
        throw 'Test cleanup path escaped the Fleetory artifacts directory.'
    }
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}
