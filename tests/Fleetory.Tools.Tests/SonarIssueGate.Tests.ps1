#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repo 'eng/sonar-check-policy.ps1')
$sha = 'a' * 40
$project = 'fleetory-test'
$before = [DateTimeOffset]::Parse('2026-01-01T00:00:00Z')
$rejected = 0

function New-Check {
    param([string] $Scope = 'pullRequest=2')
    $base = 'https://sonarcloud.io'
    return [pscustomobject]@{
        id = 1; name = 'SonarCloud Code Analysis'; head_sha = $sha
        app = [pscustomobject]@{ id = 12526; slug = 'sonarqubecloud' }
        status = 'completed'; conclusion = 'success'; completed_at = '2026-01-01T00:00:01Z'
        details_url = "$base/dashboard?id=$project&$Scope"
        output = [pscustomobject]@{ summary = (
            "[0 New issues]($base/project/issues?id=$project&$Scope)" +
            " [0 Accepted issues]($base/project/issues?id=$project&$Scope)") }
    }
}
function Assert-Rejected([scriptblock] $Action) {
    $failed = $false
    try { & $Action } catch { $failed = $true }
    if (-not $failed) { throw 'Unsafe or incomplete Sonar evidence was accepted.' }
    $script:rejected++
}
function Assert-Clean($Check) {
    Assert-FleetorySonarCheckClean $Check $project '2' '' $before
}
$valid = New-Check
Assert-Clean $valid
Assert-FleetorySonarCheckClean (New-Check 'branch=main') $project '' 'main' $before
foreach ($instant in @([DateTimeOffset]::Parse('2026-01-01T00:00:01Z'), [DateTime]::Parse('2026-01-01T00:00:01Z').ToUniversalTime())) {
    $typed = New-Check
    $typed.completed_at = $instant
    Assert-Clean $typed
}
$response = [pscustomobject]@{ total_count = [long]1; check_runs = @($valid) }
if ($null -eq (Get-FleetorySonarCheck $response $sha $before)) { throw 'Valid official check was not selected.' }
$stale = New-Check
$stale.completed_at = '2025-12-31T23:59:59Z'
$oldResponse = [pscustomobject]@{ total_count = 1; check_runs = @($stale) }
if ($null -ne (Get-FleetorySonarCheck $oldResponse $sha $before)) { throw 'Old check selected for current submission.' }
foreach ($change in @(
    { param($c) $c.output.summary = $c.output.summary.Replace('[0 New issues]', '[2 New issues]') },
    { param($c) $c.output.summary = $c.output.summary.Replace('[0 New issues]', '[1 New issue]') },
    { param($c) $c.output.summary = $c.output.summary.Replace('[0 Accepted issues]', '[1 Accepted issue]') },
    { param($c) $c.output.summary = '' },
    { param($c) $c.output.summary += ' ' + $c.output.summary },
    { param($c) $c.output.summary = $c.output.summary.Replace('[0 New issues]', '[NaN New issues]') },
    { param($c) $c.output.summary = $c.output.summary.Replace('[0 New issues]', '[-1 New issues]') },
    { param($c) $c.output.summary = $c.output.summary.Replace('[0 New issues]', '[01 New issues]') },
    { param($c) $c.output.summary = $c.output.summary.Replace('[0 New issues]', '[2147483648 New issues]') },
    { param($c) $c.output.summary = $c.output.summary.Replace('id=fleetory-test', 'id=foreign') },
    { param($c) $c.output.summary = $c.output.summary.Replace('pullRequest=2', 'pullRequest=3') },
    { param($c) $c.output.summary = $c.output.summary.Replace('https://', 'http://') },
    { param($c) $c.output.summary = $c.output.summary.Replace('sonarcloud.io/', 'sonarcloud.io.evil/') },
    { param($c) $c.output.summary = $c.output.summary.Replace('id=fleetory-test', 'id=fleetory-test&id=foreign') },
    { param($c) $c.details_url = $c.details_url.Replace('pullRequest=2', 'branch=main') },
    { param($c) $c.details_url = $c.details_url.Replace('id=fleetory-test', 'id=foreign') },
    { param($c) $c.completed_at = '2025-12-31T23:59:59Z' },
    { param($c) $c.completed_at = 'not-a-time' },
    { param($c) $c.conclusion = 'failure' }
)) {
    $candidate = New-Check
    & $change $candidate
    Assert-Rejected { Assert-Clean $candidate }
}
foreach ($change in @(
    { param($c) $c.app.slug = 'other' },
    { param($c) $c.app.id = 1 },
    { param($c) $c.head_sha = 'b' * 40 },
    { param($c) $c.status = 'in_progress' }
)) {
    $candidate = New-Check
    & $change $candidate
    $inputResponse = [pscustomobject]@{ total_count = 1; check_runs = @($candidate) }
    if ($null -ne (Get-FleetorySonarCheck $inputResponse $sha)) { throw 'Wrong publisher/revision or pending check was selected.' }
}
Assert-Rejected { Get-FleetorySonarCheck ([pscustomobject]@{ total_count = 2; check_runs = @($valid, $valid) }) $sha }
Assert-Rejected { Get-FleetorySonarCheck ([pscustomobject]@{ total_count = 101; check_runs = @($valid) }) $sha }
Assert-Rejected { Get-FleetorySonarCheck ([pscustomobject]@{ total_count = '1'; check_runs = @($valid) }) $sha }
Assert-Rejected { Get-FleetorySonarCheck ([pscustomobject]@{ check_runs = @() }) $sha }
if ($null -ne (Get-FleetorySonarCheck ([pscustomobject]@{ total_count = 0; check_runs = @() }) $sha)) {
    throw 'Missing check was interpreted as clean.'
}
Write-Host "SONAR ISSUE POLICY TESTS PASS: PR/main acceptance; $rejected invalid evidence cases; wrong publisher/revision and pending/missing checks remain unverified."

. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') -Source (Join-Path $repo 'eng/sonar-check-policy.ps1') -Names @()
$work = Join-Path $repo ('artifacts/sonar-issue-cli-' + [Guid]::NewGuid().ToString('N'))
try {
    [void](New-Item -ItemType Directory -Path (Join-Path $work 'eng') -Force)
    $reportDirectory = Join-Path $work '.sonarqube/out/.sonar'
    [void](New-Item -ItemType Directory -Path $reportDirectory -Force)
    Copy-Item -LiteralPath (Join-Path $repo 'eng/sonar-check-policy.ps1'),
        (Join-Path $repo 'eng/verify-sonar-issues.ps1') -Destination (Join-Path $work 'eng')
    $driver = @'
param([string] $Mode)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:GITHUB_REPOSITORY = 'owner/repository'
$env:SONAR_PROJECT_KEY = 'fleetory-test'
$env:GITHUB_EVENT_NAME = 'pull_request'
$env:GITHUB_EVENT_PATH = Join-Path $PSScriptRoot 'event.json'
$env:GITHUB_SHA = 'b' * 40
$env:GITHUB_REF_NAME = '2/merge'
$env:GITHUB_TOKEN = 'fixture-token'
if ($Mode -eq 'feature-branch') {
    $env:GITHUB_EVENT_NAME = 'push'
    $env:GITHUB_SHA = 'a' * 40
    $env:GITHUB_REF_NAME = 'feature/issue-gate'
}
$global:FixtureCalls = 0
if ($Mode -eq 'missing-repository') { $env:GITHUB_REPOSITORY = '' }
$global:FixtureResponse = Get-Content (Join-Path $PSScriptRoot 'response.json') -Raw | ConvertFrom-Json
function Invoke-RestMethod {
    param($Uri, $Headers, $TimeoutSec, $MaximumRedirection)
    if ($Uri -notlike 'https://api.github.com/repos/owner/repository/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/check-runs?*' -or
        $MaximumRedirection -ne 0 -or $TimeoutSec -ne 15 -or
        $Headers.Authorization -ne 'Bearer fixture-token') { throw 'Transport contract mismatch.' }
    if ($Mode -eq 'api-failure') { throw 'fixture-token must not appear in a transport error.' }
    $global:FixtureCalls++
    if ($Mode -eq 'stale-refresh' -and $global:FixtureCalls -gt 1) {
        $global:FixtureResponse.check_runs[0].completed_at = '2026-01-01T00:00:01Z'
    }
    return $global:FixtureResponse
}
function Start-Sleep {
    if ($Mode -ne 'stale-refresh') { throw 'Pending fixture remains unverified.' }
}
& (Join-Path $PSScriptRoot 'eng/verify-sonar-issues.ps1')
'@
    [IO.File]::WriteAllText((Join-Path $work 'driver.ps1'), $driver, [Text.UTF8Encoding]::new($true))
    $cases = @('clean', 'feature-branch', 'stale-refresh', 'dirty', 'accepted', 'api-failure', 'pending', 'wrong-sha',
        'wrong-app', 'incomplete', 'wrong-project', 'stale', 'missing-task',
        'wrong-task-project', 'invalid-task-id', 'missing-repository', 'invalid-event')
    foreach ($case in $cases) {
        $candidate = New-Check
        if ($case -eq 'feature-branch') { $candidate = New-Check 'branch=feature%2Fissue-gate' }
        switch ($case) {
            'dirty' { $candidate.output.summary = $candidate.output.summary.Replace('[0 New issues]', '[2 New issues]') }
            'accepted' { $candidate.output.summary = $candidate.output.summary.Replace('[0 Accepted issues]', '[1 Accepted issue]') }
            'pending' { $candidate.status = 'in_progress' }
            'wrong-sha' { $candidate.head_sha = 'c' * 40 }
            'wrong-app' { $candidate.app.id = 1 }
            'wrong-project' { $candidate.details_url = $candidate.details_url.Replace('fleetory-test', 'other') }
            { $_ -in @('stale', 'stale-refresh') } { $candidate.completed_at = '2025-12-31T23:59:59Z' }
        }
        $reply = [pscustomobject]@{ total_count = 1; check_runs = @($candidate) }
        if ($case -eq 'incomplete') { $reply.total_count = 2 }
        [IO.File]::WriteAllText((Join-Path $work 'response.json'),
            ($reply | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        $pullRequestEvent = '{"number":2,"pull_request":{"head":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}'
        if ($case -eq 'invalid-event') { $pullRequestEvent = '{"number":2}' }
        [IO.File]::WriteAllText((Join-Path $work 'event.json'), $pullRequestEvent, [Text.UTF8Encoding]::new($false))
        $taskPath = Join-Path $reportDirectory 'report-task.txt'
        $task = @('projectKey=fleetory-test', 'ceTaskId=test-task')
        if ($case -eq 'wrong-task-project') { $task[0] = 'projectKey=foreign' }
        if ($case -eq 'invalid-task-id') { $task[1] = 'ceTaskId=https://foreign.example/' }
        [IO.File]::WriteAllLines($taskPath, $task, [Text.UTF8Encoding]::new($false))
        [IO.File]::SetLastWriteTimeUtc($taskPath, $before.UtcDateTime)
        if ($case -eq 'missing-task') { Remove-Item -LiteralPath $taskPath }
        $output = & pwsh -NoProfile -File (Join-Path $work 'driver.ps1') $case 2>&1
        $exitCode = $LASTEXITCODE
        $text = $output -join [Environment]::NewLine
        if ($text.Contains('fixture-token')) { throw 'Gate disclosed a transport credential.' }
        if ($case -in @('clean', 'feature-branch', 'stale-refresh')) {
            if ($exitCode -ne 0 -or $text -notlike '*SONAR ISSUE GATE PASS:*') {
                throw ('Clean end-to-end gate failed: ' + $text)
            }
        }
        elseif ($exitCode -eq 0 -or $text -like '*SONAR ISSUE GATE PASS:*') {
            throw "Unsafe CLI gate case was accepted: $case"
        }
    }
    Write-Host 'SONAR ISSUE CLI TESTS PASS: exact PR head/feature branch and stale-to-fresh retry accepted; 14 bad/unknown/transport/submission cases fail without a success marker or credential disclosure.'
}
finally { Remove-FleetoryTestArtifacts -Work $work -RepoRoot $repo }
# All child exit codes have been asserted; do not propagate an expected denial to the CI shell.
$global:LASTEXITCODE = 0
