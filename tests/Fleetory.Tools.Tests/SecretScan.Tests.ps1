#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scan = Join-Path $repo 'eng/verify-secret-scan.ps1'
$work = Join-Path $repo ('artifacts/secret-scan-test-' + [Guid]::NewGuid().ToString('N'))
$clean = Join-Path $work 'clean repo'
$leaky = Join-Path $work 'leaky repo'
$output = Join-Path $work 'scan output'
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source $scan -Names @()

function Invoke-FixtureGit([string] $Path, [string[]] $Arguments) {
    & git -C $Path -c user.name=FleetorySecretScanTest -c user.email=secret-scan@example.invalid @Arguments *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture Git operation failed.' }
}

function New-FixtureRepository([string] $Path) {
    [void](New-Item -ItemType Directory -Path $Path -Force)
    Invoke-FixtureGit $Path @('init', '--initial-branch=main')
    [IO.File]::WriteAllText((Join-Path $Path 'README.txt'), 'Generated fixture; no production credentials.')
    Invoke-FixtureGit $Path @('add', '.')
    Invoke-FixtureGit $Path @('commit', '-m', 'Initial clean fixture')
}

function Invoke-TestScan([string] $Path) {
    try {
        & $scan -RepositoryPath $Path -OutputDirectory $output 6>$null
        return $true
    }
    catch { return $false }
}

function Assert-Rejected([string] $Path, [string] $Case) {
    if (Invoke-TestScan $Path) { throw "Secret scan incorrectly accepted $Case." }
    if (Test-Path -LiteralPath (Join-Path $output 'summary.json')) {
        throw "A stale success summary survived $Case."
    }
}

try {
    New-FixtureRepository $clean
    if (-not (Invoke-TestScan $clean)) { throw 'The real scanner rejected the clean Git fixture.' }
    $summary = Get-Content -LiteralPath (Join-Path $output 'summary.json') -Raw | ConvertFrom-Json
    if ($summary.reachableCommits -ne 1 -or $summary.findings -ne 0) {
        throw 'The clean scan did not record its actual scope.'
    }

    # This randomly generated token has never existed on GitHub and is never sent there.
    $synthetic = 'ghp_' + [Guid]::NewGuid().ToString('N') + 'A1b2'
    New-FixtureRepository $leaky
    $fixture = Join-Path $leaky 'credential.txt'
    [IO.File]::WriteAllText($fixture, "token = '$synthetic' # gitleaks:allow")
    Invoke-FixtureGit $leaky @('add', '.')
    Invoke-FixtureGit $leaky @('commit', '-m', 'Generated inactive scanner fixture')
    Assert-Rejected $leaky 'a committed token with an inline suppression'
    foreach ($name in @('findings.json', 'scanner.log')) {
        $text = [IO.File]::ReadAllText((Join-Path $output $name))
        if ($text.Contains($synthetic)) { throw 'Scanner output disclosed the generated token.' }
    }
    $findings = @(Get-Content -LiteralPath (Join-Path $output 'findings.json') -Raw | ConvertFrom-Json)
    if ($findings.Count -eq 0 -or $findings[0].RuleID -cne 'github-pat') {
        throw 'The real upstream token rule was not exercised.'
    }
    # Neither repository config nor a matching fingerprint may bypass the gate.
    [IO.File]::WriteAllText((Join-Path $leaky '.gitleaks.toml'), "title = 'empty repository policy'`n")
    [IO.File]::WriteAllText((Join-Path $leaky '.gitleaksignore'), $findings[0].Fingerprint)
    Assert-Rejected $leaky 'repository policy and fingerprint suppressions'
    Remove-Item -LiteralPath $fixture
    Invoke-FixtureGit $leaky @('add', '-A')
    Invoke-FixtureGit $leaky @('commit', '-m', 'Remove generated token from tip')
    Assert-Rejected $leaky 'a credential removed from the current tree but retained in history'

    # The token exists only in the merge result, not in either parent commit.
    $merge = Join-Path $work 'merge repo'
    New-FixtureRepository $merge
    Invoke-FixtureGit $merge @('checkout', '-b', 'feature')
    [IO.File]::WriteAllText((Join-Path $merge 'feature.txt'), 'feature branch')
    Invoke-FixtureGit $merge @('add', '.')
    Invoke-FixtureGit $merge @('commit', '-m', 'Feature fixture')
    Invoke-FixtureGit $merge @('checkout', 'main')
    [IO.File]::WriteAllText((Join-Path $merge 'main.txt'), 'main branch')
    Invoke-FixtureGit $merge @('add', '.')
    Invoke-FixtureGit $merge @('commit', '-m', 'Main fixture')
    Invoke-FixtureGit $merge @('merge', '--no-ff', '--no-commit', 'feature')
    [IO.File]::WriteAllText((Join-Path $merge 'merge-only.txt'), "token = '$synthetic'")
    Invoke-FixtureGit $merge @('add', '.')
    Invoke-FixtureGit $merge @('commit', '-m', 'Merge-only inactive token fixture')
    Assert-Rejected $merge 'a token introduced only by a merge resolution'
    $mergeHead = & git -C $merge rev-parse HEAD
    $mergeFindings = @(Get-Content -LiteralPath (Join-Path $output 'findings.json') -Raw | ConvertFrom-Json)
    if (@($mergeFindings | Where-Object { $_.Commit -ceq $mergeHead }).Count -eq 0) {
        throw 'The scanner did not inspect the merge commit diff.'
    }

    if (-not (Invoke-TestScan $clean)) { throw 'The clean rescan failed.' }
    $savedHost = $env:DOCKER_HOST
    $savedContext = $env:DOCKER_CONTEXT
    try {
        $env:DOCKER_CONTEXT = ''
        $env:DOCKER_HOST = 'tcp://127.0.0.1:1'
        Assert-Rejected $clean 'an unavailable scanner engine'
    }
    finally {
        $env:DOCKER_HOST = $savedHost
        $env:DOCKER_CONTEXT = $savedContext
    }

    $shallow = Join-Path $work 'shallow'
    Invoke-FixtureGit $work @('clone', '--depth', '1', '--no-local', $clean, $shallow)
    Assert-Rejected $shallow 'shallow history'
    $unborn = Join-Path $work 'unborn'
    [void](New-Item -ItemType Directory -Path $unborn)
    Invoke-FixtureGit $unborn @('init')
    Assert-Rejected $unborn 'a repository without a committed HEAD'
    Assert-Rejected $work 'a directory without its own Git database'
    foreach ($relative in @('.git/objects/info/alternates', '.git/info/grafts')) {
        $path = Join-Path $clean $relative
        [IO.File]::WriteAllText($path, '')
        Assert-Rejected $clean $relative
        Remove-Item -LiteralPath $path
    }
    Write-Host 'SECRET SCAN TESTS PASS: clean history accepted; 10 failure/bypass cases rejected; token absent from redacted report and log.'
    $global:LASTEXITCODE = 0
}
finally { Remove-FleetoryTestArtifacts $work $repo }
