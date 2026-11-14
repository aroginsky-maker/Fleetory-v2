$ErrorActionPreference = 'Stop'

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

if (-not [string]::IsNullOrWhiteSpace($pullRequest)) {
    $query += '&pullRequest=' + [Uri]::EscapeDataString($pullRequest)
}
else {
    $query += '&branch=main'
}

$uri = $hostUrl.TrimEnd('/') + '/api/measures/component?' + $query

try {
    $response = Invoke-RestMethod -Uri $uri -Method Get -Headers @{
        Authorization = "Bearer $token"
        Accept = 'application/json'
    }

    $measures = @{}
    foreach ($measure in $response.component.measures) {
        $value = [string] $measure.value
        if ([string]::IsNullOrWhiteSpace($value) -and $measure.periods) {
            $value = [string] $measure.periods[-1].value
        }
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $measures[$measure.metric] = $value
        }
    }

    $labels = [ordered]@{
        'SONAR COVERAGE' = 'coverage'
        'SONAR NEW COVERAGE' = 'new_coverage'
        'SONAR DUPLICATION' = 'duplicated_lines_density'
        'SONAR NEW DUPLICATION' = 'new_duplicated_lines_density'
    }
    $scope = if ([string]::IsNullOrWhiteSpace($pullRequest)) {
        'main'
    }
    else {
        "PR #$pullRequest"
    }
    Write-Host ('SONAR ANALYSIS SCOPE     {0}' -f $scope)
    foreach ($label in $labels.Keys) {
        $key = $labels[$label]
        $display = if ($measures.ContainsKey($key)) { $measures[$key] + '%' } else { 'NOT AVAILABLE' }
        Write-Host ('{0,-24} {1}' -f $label, $display)
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
            $tree = Invoke-RestMethod -Uri $fileUri -Method Get -Headers @{
                Authorization = "Bearer $token"
                Accept = 'application/json'
            }

            $files = foreach ($component in $tree.components) {
                $values = @{}
                foreach ($measure in $component.measures) {
                    $value = [string] $measure.value
                    if ([string]::IsNullOrWhiteSpace($value) -and $measure.periods) {
                        $value = [string] $measure.periods[-1].value
                    }
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

            Write-Host 'SONAR MOST UNCOVERED FILES'
            $files | Sort-Object Uncovered -Descending | Select-Object -First 12 | ForEach-Object {
                Write-Host ('  {0}: {1}/{2} uncovered, coverage {3}%' -f `
                    $_.Path, $_.Uncovered, $_.LinesToCover, $_.Coverage)
            }
            Write-Host 'SONAR MOST DUPLICATED FILES'
            $files | Sort-Object Duplicated -Descending | Select-Object -First 12 | ForEach-Object {
                Write-Host ('  {0}: {1} duplicated lines, duplication {2}%' -f `
                    $_.Path, $_.Duplicated, $_.Duplication)
            }
        }
        catch {
            Write-Warning ('Sonar per-file metrics could not be read: ' + $_.Exception.Message)
        }
    }
}
catch {
    Write-Warning ('Sonar metrics could not be read: ' + $_.Exception.Message)
    Write-Host 'SONAR METRICS       NOT AVAILABLE'
}
finally {
    $token = $null
}
