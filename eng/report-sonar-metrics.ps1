#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'sonar-check-policy.ps1')

$hostUrl = [Environment]::GetEnvironmentVariable('SONAR_HOST_URL')
$projectKey = [Environment]::GetEnvironmentVariable('SONAR_PROJECT_KEY')
$token = [Environment]::GetEnvironmentVariable('SONAR_TOKEN')
$pullRequest = [Environment]::GetEnvironmentVariable('SONAR_PULL_REQUEST')

if ([string]::IsNullOrWhiteSpace($hostUrl) -or
    [string]::IsNullOrWhiteSpace($projectKey) -or
    [string]::IsNullOrWhiteSpace($token)) {
    Write-Host 'SONAR METRICS       NOT AVAILABLE (connection is incomplete)'
    exit 0
}

$reportTask = Join-Path (Split-Path -Parent $PSScriptRoot) '.sonarqube/out/.sonar/report-task.txt'
if (-not (Test-Path -LiteralPath $reportTask -PathType Leaf)) {
    Write-Host 'SONAR METRICS       NOT AVAILABLE (this run did not submit an analysis)'
    exit 0
}

$metricKeys = @(
    'coverage',
    'new_coverage',
    'duplicated_lines_density',
    'new_duplicated_lines_density'
)
$query = 'component={0}&metricKeys={1}' -f `
    [Uri]::EscapeDataString($projectKey),
    [Uri]::EscapeDataString(($metricKeys -join ','))

$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }

function Read-SonarMetrics([string] $Address) {
    return Invoke-RestMethod -Uri $Address -Method Get -Headers $headers -TimeoutSec 15 -MaximumRedirection 0
}

function Assert-CurrentSonarMetricsTask($Task, [string] $TaskId, [string] $AnalysisId) {
    if ($Task.id -cne $TaskId -or $Task.componentKey -cne $projectKey -or $Task.type -cne 'REPORT' -or
        $Task.status -cne 'SUCCESS' -or $Task.analysisId -cne $AnalysisId) { throw 'Current Sonar task is not successfully processed.' }
}

function Assert-LatestSonarMetricsTask($Response, [string] $TaskId, [string] $AnalysisId) {
    if ($Response.queue -isnot [array] -or $Response.queue.Count -ne 0) { throw 'Competing Sonar processing prevents a stable metrics snapshot.' }
    Assert-CurrentSonarMetricsTask $Response.current $TaskId $AnalysisId
}

function Get-SonarMetricValue($Measure) {
    if ($Measure.PSObject.Properties['value']) { return [string]$Measure.value }
    if ($Measure.PSObject.Properties['period']) { return [string]$Measure.period.value }
    if ($Measure.PSObject.Properties['periods'] -and $Measure.periods -is [array] -and $Measure.periods.Count -eq 1) {
        return [string]$Measure.periods[0].value
    }
    throw 'A Sonar metric has no unambiguous value.'
}

try {
    if ($hostUrl.TrimEnd('/') -cne 'https://sonarcloud.io') { throw 'Metrics host is outside the approved official service.' }
    $hostUrl = $hostUrl.TrimEnd('/')
    $revision = [Environment]::GetEnvironmentVariable('GITHUB_SHA')
    $branch = [Environment]::GetEnvironmentVariable('GITHUB_REF_NAME')
    if ([Environment]::GetEnvironmentVariable('GITHUB_EVENT_NAME') -ceq 'pull_request') {
        $eventPath = [Environment]::GetEnvironmentVariable('GITHUB_EVENT_PATH')
        if (-not (Test-Path -LiteralPath $eventPath -PathType Leaf) -or (Get-Item -LiteralPath $eventPath).Length -gt 1048576) { throw 'Current GitHub event is unavailable.' }
        $event = Get-Content -LiteralPath $eventPath -Raw | ConvertFrom-Json
        if ($pullRequest -cnotmatch '^[1-9][0-9]*$' -or [string]$event.number -cne $pullRequest) { throw 'Current PR scope is unavailable.' }
        $revision = [string]$event.pull_request.head.sha
        $branch = ''
    }
    elseif ([Environment]::GetEnvironmentVariable('GITHUB_EVENT_NAME') -cnotin @('push','workflow_dispatch') -or
        $pullRequest -or [string]::IsNullOrWhiteSpace($branch)) { throw 'Current branch scope is unavailable.' }
    if ($pullRequest) { $query += '&pullRequest=' + [Uri]::EscapeDataString($pullRequest) }
    else { $query += '&branch=' + [Uri]::EscapeDataString($branch) }
    $uri = $hostUrl + '/api/measures/component?' + $query
    $receiptPath = Join-Path (Split-Path -Parent $reportTask) 'fleetory-verified-submission.json'
    $verified = Get-FleetoryVerifiedSonarSubmission $reportTask $receiptPath $projectKey $revision $pullRequest $branch
    $taskUri = $hostUrl + '/api/ce/task?id=' + [Uri]::EscapeDataString($verified.ceTaskId)
    $task = (Read-SonarMetrics $taskUri).task
    if ($task.id -cne $verified.ceTaskId -or $task.componentKey -cne $projectKey -or $task.type -cne 'REPORT') { throw 'Current task identity is unavailable.' }
    if ($task.status -cnotin @('PENDING','IN_PROGRESS','SUCCESS','FAILED','CANCELED')) { throw 'Unknown Sonar task state.' }
    if ($task.status -cne 'SUCCESS') {
        Write-Host ('SONAR METRICS       NOT AVAILABLE (current task {0})' -f $task.status)
        return
    }
    if ($task.analysisId -cnotmatch '^[A-Za-z0-9_-]{1,128}$') { throw 'Current analysis identifier is unavailable.' }
    Assert-CurrentSonarMetricsTask $task $verified.ceTaskId $task.analysisId
    $latestUri = $hostUrl + '/api/ce/component?component=' + [Uri]::EscapeDataString($projectKey)
    Assert-LatestSonarMetricsTask (Read-SonarMetrics $latestUri) $verified.ceTaskId $task.analysisId
    $lines = [Collections.Generic.List[string]]::new()
    $response = Read-SonarMetrics $uri
    if ($response.component.key -cne $projectKey) { throw 'Sonar metric component does not match this project.' }

    $measures = @{}
    foreach ($measure in $response.component.measures) {
        $value = Get-SonarMetricValue $measure
        if ($measure.metric -cnotin $metricKeys -or $measures.ContainsKey($measure.metric) -or
            $value -cnotmatch '^(100(?:\.0+)?|(?:[0-9]|[1-9][0-9])(?:\.[0-9]+)?)$') { throw 'Sonar percentages are malformed or ambiguous.' }
        $measures[$measure.metric] = $value
    }

    $labels = [ordered]@{
        'SONAR COVERAGE' = 'coverage'
        'SONAR NEW COVERAGE' = 'new_coverage'
        'SONAR DUPLICATION' = 'duplicated_lines_density'
        'SONAR NEW DUPLICATION' = 'new_duplicated_lines_density'
    }
    $scope = if ([string]::IsNullOrWhiteSpace($pullRequest)) {
        $branch
    }
    else {
        "PR #$pullRequest"
    }
    $lines.Add(('SONAR VERIFIED REVISION {0}; check {1}; task {2}; analysis {3}' -f $revision,$verified.checkId,$verified.ceTaskId,$task.analysisId))
    $lines.Add(('SONAR ANALYSIS SCOPE     {0}' -f $scope))
    foreach ($label in $labels.Keys) {
        $key = $labels[$label]
        $display = if ($measures.ContainsKey($key)) { $measures[$key] + '%' } else { 'NOT AVAILABLE' }
        $lines.Add(('{0,-24} {1}' -f $label, $display))
    }

    if (-not [string]::IsNullOrWhiteSpace($pullRequest)) {
        try {
            $fileMetrics = @(
                'new_lines_to_cover',
                'new_uncovered_lines',
                'new_duplicated_lines',
                'new_coverage',
                'new_duplicated_lines_density'
            )
            $fileQuery = 'component={0}&metricKeys={1}&pullRequest={2}&qualifiers=FIL&ps=500' -f `
                [Uri]::EscapeDataString($projectKey),
                [Uri]::EscapeDataString(($fileMetrics -join ',')),
                [Uri]::EscapeDataString($pullRequest)
            $fileUri = $hostUrl.TrimEnd('/') + '/api/measures/component_tree?' + $fileQuery
            $tree = Read-SonarMetrics $fileUri

            $files = foreach ($component in $tree.components) {
                $values = @{}
                foreach ($measure in $component.measures) {
                    $value = Get-SonarMetricValue $measure
                    if (-not [string]::IsNullOrWhiteSpace($value)) {
                        $values[$measure.metric] = $value
                    }
                }

                [pscustomobject]@{
                    Path = [string] $component.path
                    Uncovered = [int] $values['new_uncovered_lines']
                    LinesToCover = [int] $values['new_lines_to_cover']
                    Duplicated = [int] $values['new_duplicated_lines']
                    Coverage = [string] $values['new_coverage']
                    Duplication = [string] $values['new_duplicated_lines_density']
                }
            }

            $lines.Add('SONAR MOST UNCOVERED FILES')
            $files | Sort-Object Uncovered -Descending | Select-Object -First 12 | ForEach-Object {
                $lines.Add(('  {0}: {1}/{2} uncovered, coverage {3}%' -f `
                    $_.Path, $_.Uncovered, $_.LinesToCover, $_.Coverage))
            }
            $lines.Add('SONAR MOST DUPLICATED FILES')
            $files | Sort-Object Duplicated -Descending | Select-Object -First 12 | ForEach-Object {
                $lines.Add(('  {0}: {1} duplicated lines, duplication {2}%' -f `
                    $_.Path, $_.Duplicated, $_.Duplication))
            }
        }
        catch {
            $lines.Add('SONAR PER-FILE METRICS NOT AVAILABLE')
        }
    }
    Assert-CurrentSonarMetricsTask (Read-SonarMetrics $taskUri).task $verified.ceTaskId $task.analysisId
    Assert-LatestSonarMetricsTask (Read-SonarMetrics $latestUri) $verified.ceTaskId $task.analysisId
    [void](Get-FleetoryVerifiedSonarSubmission $reportTask $receiptPath $projectKey $revision $pullRequest $branch)
    foreach ($line in $lines) { Write-Host $line }
}
catch {
    Write-Warning 'Current Sonar metrics could not be verified; no historical percentages are displayed.'
    Write-Host 'SONAR METRICS       NOT AVAILABLE'
}
finally {
    $headers.Clear()
    $token = $null
}
