#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'sonar-check-policy.ps1')

$reportPath = Join-Path (Split-Path -Parent $PSScriptRoot) '.sonarqube/out/.sonar/report-task.txt'
$receiptPath = Join-Path (Split-Path -Parent $reportPath) 'fleetory-verified-submission.json'
# A failed invocation must not leave a previous generated success cache usable.
if (Test-Path -LiteralPath $receiptPath) { Remove-Item -LiteralPath $receiptPath -Force }
$runId = [Environment]::GetEnvironmentVariable('GITHUB_RUN_ID')
$runAttempt = [Environment]::GetEnvironmentVariable('GITHUB_RUN_ATTEMPT')
if ($runId -cnotmatch '^[1-9][0-9]{0,19}$' -or $runAttempt -cnotmatch '^[1-9][0-9]{0,19}$') { throw 'Exact GitHub run/attempt is required.' }

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

$submission = Get-FleetorySonarSubmission $reportPath $project
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
            $verified = [ordered]@{
                schema='fleetory.sonar-verified-submission.v1'; projectKey=$project; revision=$revision
                pullRequest=$pullRequest; branch=$(if ($pullRequest) { '' } else { $branch })
                ceTaskId=$submission['ceTaskId']; checkId=$check.id
                completedAt=(Get-FleetorySonarCompletionTime $check).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
                submissionSha256=(Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
                runId=$runId; runAttempt=$runAttempt
            }
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($verified | ConvertTo-Json -Compress) + "`n")
            $stream = [IO.File]::Open($receiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
            Write-Host "SONAR ISSUE GATE PASS: revision $revision; check $($check.id); 0 new issues; 0 accepted issues."
            exit 0
        }
        if ($deadline.Elapsed.TotalSeconds -ge 90) { throw 'Current official Sonar check is unavailable.' }
        Start-Sleep -Seconds 3
    } while ($true)
}
finally { $headers.Clear(); $token = $null }
