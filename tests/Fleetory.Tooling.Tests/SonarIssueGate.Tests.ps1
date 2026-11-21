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

. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Fleetory.Tools.Tests/TestProvisionerHelpers.ps1') -Source (Join-Path $repo 'eng/sonar-check-policy.ps1') -Names @()
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
$env:GITHUB_RUN_ID = '12345'
$env:GITHUB_RUN_ATTEMPT = '1'
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
        $receiptPath = Join-Path $reportDirectory 'fleetory-verified-submission.json'
        [IO.File]::WriteAllText($receiptPath, 'previous generated success cache')
        $output = & pwsh -NoProfile -File (Join-Path $work 'driver.ps1') $case 2>&1
        $exitCode = $LASTEXITCODE
        $text = $output -join [Environment]::NewLine
        if ($text.Contains('fixture-token')) { throw 'Gate disclosed a transport credential.' }
        if ($case -in @('clean', 'feature-branch', 'stale-refresh')) {
            if ($exitCode -ne 0 -or $text -notlike '*SONAR ISSUE GATE PASS:*') {
                throw ('Clean end-to-end gate failed: ' + $text)
            }
            $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
            $expectedBranch = if ($case -eq 'feature-branch') { 'feature/issue-gate' } else { '' }
            $expectedPr = if ($case -eq 'feature-branch') { '' } else { '2' }
            if ($receipt.revision -cne $sha -or $receipt.branch -cne $expectedBranch -or
                $receipt.pullRequest -cne $expectedPr -or $receipt.ceTaskId -cne 'test-task' -or
                $receipt.runId -cne '12345' -or $receipt.runAttempt -cne '1') {
                throw "Clean gate did not replace the prior cache with current evidence: $case"
            }
        }
        else {
            if ($exitCode -eq 0 -or $text -like '*SONAR ISSUE GATE PASS:*') {
                throw "Unsafe CLI gate case was accepted: $case"
            }
            if (Test-Path -LiteralPath $receiptPath) { throw "Failed gate retained a success cache: $case" }
        }
    }
    Write-Host 'SONAR ISSUE CLI TESTS PASS: exact PR head/feature branch and stale-to-fresh retry accepted; 14 bad/unknown/transport/submission cases fail without a success marker or credential disclosure.'
}
finally { Remove-FleetoryTestArtifacts -Work $work -RepoRoot $repo }
# All child exit codes have been asserted; do not propagate an expected denial to the CI shell.
$global:LASTEXITCODE = 0

# The informational report must never turn an old analysis into current percentages.
$metricsWork = Join-Path $repo ('artifacts/sonar-metrics-cli-' + [Guid]::NewGuid().ToString('N'))
try {
    [void](New-Item -ItemType Directory -Path (Join-Path $metricsWork 'eng') -Force)
    Copy-Item -LiteralPath (Join-Path $repo 'eng/sonar-check-policy.ps1'),
        (Join-Path $repo 'eng/verify-sonar-issues.ps1'), (Join-Path $repo 'eng/report-sonar-metrics.ps1') -Destination (Join-Path $metricsWork 'eng')
    $metricsDriver = @'
param([string] $Mode)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$env:GITHUB_REPOSITORY='owner/repository'; $env:GITHUB_EVENT_NAME='pull_request'
$env:GITHUB_SHA='b'*40; $env:GITHUB_REF_NAME='2/merge'; $env:GITHUB_TOKEN='fixture-token'
$env:GITHUB_RUN_ID='12345';$env:GITHUB_RUN_ATTEMPT='1'
$env:SONAR_HOST_URL='https://sonarcloud.io'; $env:SONAR_PROJECT_KEY='fleetory-test'
$env:SONAR_TOKEN='fixture-token'; $env:SONAR_PULL_REQUEST='2'
$env:GITHUB_EVENT_PATH=Join-Path $PSScriptRoot 'event.json'
[IO.File]::WriteAllText($env:GITHUB_EVENT_PATH,'{"number":2,"pull_request":{"head":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}')
$scope='pullRequest=2'
if ($Mode -in @('main','feature')) {
    $env:GITHUB_EVENT_NAME='push';$env:GITHUB_SHA='a'*40;$env:SONAR_PULL_REQUEST=''
    $env:GITHUB_REF_NAME=if ($Mode -eq 'main') {'main'} else {'feature/metrics'}
    $scope='branch='+[Uri]::EscapeDataString($env:GITHUB_REF_NAME)
}
$directory=Join-Path $PSScriptRoot '.sonarqube/out/.sonar'
[void](New-Item -ItemType Directory -Path $directory -Force)
$report=Join-Path $directory 'report-task.txt';$receipt=Join-Path $directory 'fleetory-verified-submission.json'
[IO.File]::WriteAllLines($report,@('projectKey=fleetory-test','ceTaskId=test-task'))
[IO.File]::SetLastWriteTimeUtc($report,[DateTime]::Parse('2026-01-01T00:00:00Z').ToUniversalTime())
$global:MetricsTaskCalls=0;$global:MetricsLatestCalls=0;$global:MetricsReadCalls=0
$global:MetricsUris=[Collections.Generic.List[string]]::new()
function Invoke-RestMethod {
    param($Uri,$Method,$Headers,$TimeoutSec,$MaximumRedirection)
    if ($Headers.Authorization -cne 'Bearer fixture-token' -or $TimeoutSec -ne 15 -or $MaximumRedirection -ne 0) { throw 'Invalid transport settings.' }
    if ($Uri -like 'https://api.github.com/*') {
        return [pscustomobject]@{total_count=1;check_runs=@([pscustomobject]@{
            id=1;name='SonarCloud Code Analysis';head_sha=('a'*40);app=[pscustomobject]@{id=12526;slug='sonarqubecloud'}
            status='completed';conclusion='success';completed_at='2026-01-01T00:00:01Z'
            details_url="https://sonarcloud.io/dashboard?id=fleetory-test&$scope"
            output=[pscustomobject]@{summary="[0 New issues](https://sonarcloud.io/project/issues?id=fleetory-test&$scope) [0 Accepted issues](https://sonarcloud.io/project/issues?id=fleetory-test&$scope)"}
        })}
    }
    $global:MetricsUris.Add([string]$Uri)
    if ($Method -cne 'Get' -or $Uri -notlike 'https://sonarcloud.io/api/*') { throw 'Unexpected service destination.' }
    if ($Mode -eq 'api-failure') { throw 'fixture-token must not appear in a transport error.' }
    $task=[pscustomobject]@{id='test-task';componentKey='fleetory-test';type='REPORT';status='SUCCESS';analysisId='test-analysis'}
    if ($Uri -ceq 'https://sonarcloud.io/api/ce/task?id=test-task') {
        $global:MetricsTaskCalls++
        switch ($Mode) {
            'failed' {$task.status='FAILED'}
            'pending' {$task.status='PENDING'}
            'in-progress' {$task.status='IN_PROGRESS'}
            'cancelled' {$task.status='CANCELED'}
            'task-id' {$task.id='foreign'}
            'task-project' {$task.componentKey='foreign'}
            'task-type' {$task.type='foreign'}
            'task-analysis' {$task.analysisId='https://foreign.example/'}
            'race-task' {if ($global:MetricsTaskCalls -gt 1) {$task.status='FAILED'}}
        }
        return [pscustomobject]@{task=$task}
    }
    if ($Uri -ceq 'https://sonarcloud.io/api/ce/component?component=fleetory-test') {
        $global:MetricsLatestCalls++;$queue=@()
        if ($Mode -eq 'competing') {$queue=@($task)}
        if ($Mode -eq 'latest-other' -or ($Mode -eq 'race-latest' -and $global:MetricsLatestCalls -gt 1)) {$task.id='other-task'}
        return [pscustomobject]@{current=$task;queue=$queue}
    }
    if ($Uri -notlike "*&$scope*") {throw 'Metrics scope differs from the verified submission.'}
    $global:MetricsReadCalls++
    if ($Uri -like 'https://sonarcloud.io/api/measures/component?*') {
        $measures=@(
            [pscustomobject]@{metric='coverage';value='91.9'},[pscustomobject]@{metric='new_coverage';value='92.2180607573866'},
            [pscustomobject]@{metric='duplicated_lines_density';value='0.0'},[pscustomobject]@{metric='new_duplicated_lines_density';value='0.0'})
        $key='fleetory-test'
        switch ($Mode) {
            'metric-project' {$key='foreign'}
            'metric-value' {$measures[0].value='NaN'}
            'duplicate-metric' {$measures+= $measures[0]}
            'single-period' {$measures[1]=[pscustomobject]@{metric='new_coverage';period=[pscustomobject]@{value='92.2180607573866'}}}
            'periods' {$measures[1]=[pscustomobject]@{metric='new_coverage';periods=@([pscustomobject]@{value='92.2180607573866'})}}
            'ambiguous-periods' {$measures[1]=[pscustomobject]@{metric='new_coverage';periods=@([pscustomobject]@{value='1'},[pscustomobject]@{value='99'})}}
        }
        return [pscustomobject]@{component=[pscustomobject]@{key=$key;measures=$measures}}
    }
    if ($Uri -like 'https://sonarcloud.io/api/measures/component_tree?*') {
        if ($Mode -eq 'file-failure') {throw 'fixture-token cannot leak through file diagnostics.'}
        return [pscustomobject]@{components=@()}
    }
    throw 'Unexpected metrics endpoint.'
}
& (Join-Path $PSScriptRoot 'eng/verify-sonar-issues.ps1') 6>$null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $receipt)) {throw 'Generated clean gate did not write its receipt.'}
$value=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
switch ($Mode) {
    'missing-receipt' {Remove-Item -LiteralPath $receipt}
    'missing-report' {Remove-Item -LiteralPath $report}
    'report-project' {[IO.File]::WriteAllLines($report,@('projectKey=foreign','ceTaskId=test-task'))}
    'report-id' {[IO.File]::WriteAllLines($report,@('projectKey=fleetory-test','ceTaskId=https://foreign.example/'))}
    'duplicate-report' {[IO.File]::AppendAllText($report,"ceTaskId=test-task`n")}
    'oversize-report' {[IO.File]::WriteAllText($report,('x'*16385))}
    'receipt-project' {$value.projectKey='foreign'}
    'receipt-revision' {$value.revision='c'*40}
    'receipt-pr' {$value.pullRequest='3'}
    'receipt-branch' {$value.branch='main'}
    'receipt-task' {$value.ceTaskId='old-task'}
    'receipt-hash' {$value.submissionSha256='f'*64}
    'receipt-check' {$value.checkId=0}
    'receipt-old' {$value.completedAt='2025-01-01T00:00:00.0000000Z'}
    'receipt-run' {$value.runId='12344'}
    'receipt-attempt' {$value.runAttempt='2'}
    'missing-run' {$env:GITHUB_RUN_ID=''}
    'missing-attempt' {$env:GITHUB_RUN_ATTEMPT=''}
    'wrong-event' {$env:GITHUB_EVENT_NAME='schedule'}
    'wrong-head' {[IO.File]::WriteAllText($env:GITHUB_EVENT_PATH,'{"number":2,"pull_request":{"head":{"sha":"cccccccccccccccccccccccccccccccccccccccc"}}}')}
    'invalid-event' {[IO.File]::WriteAllText($env:GITHUB_EVENT_PATH,'{}')}
    'wrong-scope' {$env:SONAR_PULL_REQUEST='3'}
    'bad-host' {$env:SONAR_HOST_URL='https://sonarcloud.io.evil.example'}
    'incomplete-env' {$env:SONAR_TOKEN=''}
}
if ($Mode.StartsWith('receipt-')) {
    # Keep the production canonical key order while changing one verified fact.
    $ordered=[ordered]@{}
    foreach ($key in @('schema','projectKey','revision','pullRequest','branch','ceTaskId','checkId','completedAt','submissionSha256','runId','runAttempt')) {
        $ordered[$key]=$value.$key
    }
    if ($ordered.completedAt -is [DateTime]) {$ordered.completedAt=$ordered.completedAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")}
    [IO.File]::WriteAllText($receipt,($ordered|ConvertTo-Json -Compress)+"`n")
}
if ($Mode -eq 'duplicate-receipt') {[IO.File]::AppendAllText($receipt,'{}')}
if ($Mode -eq 'oversize-receipt') {[IO.File]::WriteAllText($receipt,('x'*4097))}
& (Join-Path $PSScriptRoot 'eng/report-sonar-metrics.ps1')
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'trace.json'),(@{requests=@($global:MetricsUris);reads=$global:MetricsReadCalls}|ConvertTo-Json -Depth 4))
'@
    [IO.File]::WriteAllText((Join-Path $metricsWork 'driver.ps1'),$metricsDriver,[Text.UTF8Encoding]::new($true))
    $metricCases=@('clean','main','feature','single-period','periods','file-failure','missing-receipt','missing-report','report-project','report-id',
        'duplicate-report','oversize-report','receipt-project','receipt-revision','receipt-pr','receipt-branch','receipt-task','receipt-hash',
        'receipt-check','receipt-old','duplicate-receipt','oversize-receipt','wrong-head','invalid-event','wrong-scope','bad-host','incomplete-env',
        'failed','pending','in-progress','cancelled','task-id','task-project','task-type','task-analysis','api-failure','competing','latest-other',
        'race-task','race-latest','metric-project','metric-value','duplicate-metric','ambiguous-periods','receipt-run','receipt-attempt',
        'missing-run','missing-attempt','wrong-event')
    foreach ($case in $metricCases) {
        $output=& pwsh -NoProfile -File (Join-Path $metricsWork 'driver.ps1') $case 2>&1
        $exitCode=$LASTEXITCODE;$text=$output -join [Environment]::NewLine
        if ($exitCode -ne 0 -or $text.Contains('fixture-token')) {throw "Metrics fixture failed or disclosed credentials ($case): $text"}
        $trace=Get-Content -LiteralPath (Join-Path $metricsWork 'trace.json') -Raw | ConvertFrom-Json
        if ($case -in @('clean','main','feature','single-period','periods','file-failure')) {
            if ($text -notmatch 'SONAR VERIFIED REVISION a{40}; check 1; task test-task; analysis test-analysis' -or
                $text -notmatch 'SONAR COVERAGE\s+91\.9%' -or $text -notmatch 'SONAR NEW COVERAGE\s+92\.2180607573866%' -or
                $trace.reads -lt 1) {throw "Verified metrics not emitted ($case): $text"}
            if ($case -eq 'file-failure' -and $text -notmatch 'SONAR PER-FILE METRICS NOT AVAILABLE') {throw 'Missing optional file diagnostics were not disclosed.'}
        }
        elseif ($text -match 'SONAR (?:NEW )?(?:COVERAGE|DUPLICATION)\s+\S+%' -or $text -match 'SONAR VERIFIED REVISION' -or
            $text -notmatch 'SONAR METRICS\s+NOT AVAILABLE') {throw "Stale/unverified metrics were emitted ($case): $text"}
        if ($case -in @('failed','pending','in-progress','cancelled','competing','latest-other') -and $trace.reads -ne 0) {
            throw "Old metrics were requested after noncurrent/failed processing ($case)."
        }
    }
    Write-Host "SONAR METRICS CLI TESTS PASS: $($metricCases.Count) cases; current task/revision/scope and post-read stability required; failures never emit historical percentages or credentials."
}
finally {Remove-FleetoryTestArtifacts -Work $metricsWork -RepoRoot $repo}
$global:LASTEXITCODE=0
