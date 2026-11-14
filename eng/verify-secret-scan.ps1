#Requires -Version 7.2
[CmdletBinding()]
param(
    [string] $RepositoryPath = (Split-Path -Parent $PSScriptRoot),
    [string] $OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/secret-scan')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false
$image = 'ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'
$policy = Join-Path $PSScriptRoot 'gitleaks.toml'
$output = [IO.Path]::GetFullPath($OutputDirectory)
$report = Join-Path $output 'findings.json'
$log = Join-Path $output 'scanner.log'
$summary = Join-Path $output 'summary.json'
[void](New-Item -ItemType Directory -Path $output -Force)
# Never reuse evidence from an earlier successful scan after a failing invocation.
foreach ($path in @($report, $log, $summary)) {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}
$source = (Resolve-Path -LiteralPath $RepositoryPath).Path

# This gate scans a self-contained checkout, never an external object database.
if (-not (Test-Path -LiteralPath (Join-Path $source '.git') -PathType Container)) {
    throw 'Secret scanning requires a normal Git checkout with its own .git directory.'
}
foreach ($relative in @('.git/objects/info/alternates', '.git/info/grafts')) {
    if (Test-Path -LiteralPath (Join-Path $source $relative)) {
        throw 'Secret scanning refuses alternate object stores and grafted history.'
    }
}
$shallow = & git --no-replace-objects -C $source rev-parse --is-shallow-repository 2>$null
if ($LASTEXITCODE -ne 0 -or $shallow -cne 'false') {
    throw 'Secret scanning requires complete Git history; shallow checkouts are refused.'
}
$head = & git --no-replace-objects -C $source rev-parse --verify HEAD 2>$null
if ($LASTEXITCODE -ne 0 -or $head -cnotmatch '\A[0-9a-f]{40}\z') {
    throw 'Secret scanning requires a committed HEAD.'
}
$commits = & git --no-replace-objects -C $source rev-list --count $head 2>$null
if ($LASTEXITCODE -ne 0 -or $commits -notmatch '\A[1-9][0-9]*\z') {
    throw 'Secret scanning could not establish the committed history scope.'
}
$arguments = @(
    'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true', '--pids-limit', '64', '--memory', '512m',
    '--user', '65532:65532',
    '--env', 'GIT_CONFIG_COUNT=1', '--env', 'GIT_CONFIG_KEY_0=safe.directory',
    '--env', 'GIT_CONFIG_VALUE_0=/scan', '--env', 'GIT_NO_REPLACE_OBJECTS=1',
    '--mount', "type=bind,source=$source/.git,target=/scan/.git,readonly",
    '--mount', "type=bind,source=$policy,target=/policy.toml,readonly",
    $image, 'git', '/scan',
    "--log-opts=--full-history --diff-merges=separate --no-ext-diff --no-textconv $head",
    '--config=/policy.toml',
    '--gitleaks-ignore-path=/dev/null', '--ignore-gitleaks-allow', '--redact=100',
    '--no-banner', '--no-color', '--report-format=json', '--report-path=-',
    '--exit-code=2', '--timeout=120'
)
& docker @arguments 1> $report 2> $log
$scannerExit = $LASTEXITCODE
if ($scannerExit -ne 0) {
    # Deliberately do not echo scanner output, matches, paths or commit messages.
    throw "Secret scan failed (scanner exit $scannerExit). Inspect the redacted artifacts in the output directory."
}
try {
    $findings = [Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($report))
    try {
        if ($findings.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Array -or
            $findings.RootElement.GetArrayLength() -ne 0) {
            throw 'The scanner report is not an empty findings array.'
        }
    }
    finally { $findings.Dispose() }
}
catch { throw 'Secret scanner did not produce a valid, empty JSON findings report.' }
[ordered]@{
    schema = 'fleetory.secret-scan.v1'
    image = $image
    policySha256 = (Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash
    head = $head
    reachableCommits = [long] $commits
    scope = 'committed HEAD and all ancestors; uncommitted files and other refs excluded'
    findings = 0
} | ConvertTo-Json | Set-Content -LiteralPath $summary -Encoding utf8
Write-Host "SECRET SCAN PASS: Gitleaks 8.30.1; $commits reachable commits at $head; 0 findings."
$global:LASTEXITCODE = 0
