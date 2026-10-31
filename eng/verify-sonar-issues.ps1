#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'sonar-check-policy.ps1')

$repository = [Environment]::GetEnvironmentVariable('GITHUB_REPOSITORY')
$project = [Environment]::GetEnvironmentVariable('SONAR_PROJECT_KEY')
$eventName = [Environment]::GetEnvironmentVariable('GITHUB_EVENT_NAME')
$eventPath = [Environment]::GetEnvironmentVariable('GITHUB_EVENT_PATH')
$token = [Environment]::GetEnvironmentVariable('GITHUB_TOKEN')
if ($repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
    [string]::IsNullOrWhiteSpace($project) -or $project.Length -gt 400) {
    throw 'GitHub repository and Sonar project are required.'
}
$revision = [Environment]::GetEnvironmentVariable('GITHUB_SHA')
$branch = [Environment]::GetEnvironmentVariable('GITHUB_REF_NAME')
$pullRequest = ''
if ($eventName -eq 'pull_request') {
    if (-not (Test-Path -LiteralPath $eventPath -PathType Leaf) -or
        (Get-Item -LiteralPath $eventPath).Length -gt 1048576) {
        throw 'GitHub PR event is unavailable.'
    }
    $pullRequestEvent = Get-Content -LiteralPath $eventPath -Raw | ConvertFrom-Json
    $revision = [string] $pullRequestEvent.pull_request.head.sha
    $pullRequest = [string] $pullRequestEvent.number
    if ($pullRequest -cnotmatch '^[1-9][0-9]*$') { throw 'GitHub PR identity is invalid.' }
}
elseif ($eventName -notin @('push', 'workflow_dispatch')) {
    throw 'Unsupported GitHub event for the Sonar issue gate.'
}
if ($revision -cnotmatch '^[0-9a-f]{40}$' -or
    (-not $pullRequest -and [string]::IsNullOrWhiteSpace($branch))) {
    throw 'Exact GitHub analysis revision/scope is required.'
}

$reportPath = Join-Path (Split-Path -Parent $PSScriptRoot) '.sonarqube/out/.sonar/report-task.txt'
if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf) -or
    ((Get-Item -LiteralPath $reportPath).Length -lt 1 -or (Get-Item -LiteralPath $reportPath).Length -gt 16384)) {
    throw 'This run has no bounded Sonar submission artifact.'
}
$submission = @{}
foreach ($line in Get-Content -LiteralPath $reportPath) {
    $pair = $line.Split('=', 2)
    if ($pair.Count -ne 2 -or $submission.ContainsKey($pair[0])) {
        throw 'Sonar submission artifact is malformed.'
    }
    $submission[$pair[0]] = $pair[1]
}
if ($submission['projectKey'] -cne $project -or
    $submission['ceTaskId'] -cnotmatch '^[A-Za-z0-9_-]{1,128}$') {
    throw 'Sonar submission project/task does not match this run.'
}
$notBefore = [DateTimeOffset] (Get-Item -LiteralPath $reportPath).LastWriteTimeUtc
$headers = @{ Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
if ($token) { $headers.Authorization = 'Bearer ' + $token }
$address = "https://api.github.com/repos/$repository/commits/$revision/check-runs?check_name=SonarCloud%20Code%20Analysis&filter=latest&per_page=100"
$deadline = [Diagnostics.Stopwatch]::StartNew()
try {
    do {
        try {
            $response = Invoke-RestMethod -Uri $address -Headers $headers -TimeoutSec 15 -MaximumRedirection 0
        }
        catch { throw 'GitHub Sonar check could not be read; zero issues are not verified.' }
        $check = Get-FleetorySonarCheck $response $revision $notBefore
        if ($null -ne $check) {
            Assert-FleetorySonarCheckClean $check $project $pullRequest $branch $notBefore
            Write-Host "SONAR ISSUE GATE PASS: revision $revision; check $($check.id); 0 new issues; 0 accepted issues."
            exit 0
        }
        if ($deadline.Elapsed.TotalSeconds -ge 90) { throw 'Current official Sonar check is unavailable.' }
        Start-Sleep -Seconds 3
    } while ($true)
}
finally { $headers.Clear(); $token = $null }
