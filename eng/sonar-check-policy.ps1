#Requires -Version 7.2
Set-StrictMode -Version Latest

function Assert-FleetorySonarScope {
    param([string] $Address, [string] $Path, [string] $ProjectKey,
          [string] $PullRequest, [string] $Branch)
    $uri = $null
    if (-not [Uri]::TryCreate($Address, [UriKind]::Absolute, [ref] $uri) -or
        $uri.Scheme -ne 'https' -or $uri.Host -ne 'sonarcloud.io' -or
        -not $uri.IsDefaultPort -or $uri.UserInfo -or $uri.Fragment -or
        $uri.AbsolutePath -cne $Path) { throw 'Sonar report URL is not in the approved scope.' }
    $query = @{}
    foreach ($part in $uri.Query.TrimStart('?').Split('&')) {
        $pair = $part.Split('=', 2)
        if ($pair.Count -ne 2) { throw 'Sonar report query is malformed.' }
        $key = [Uri]::UnescapeDataString($pair[0])
        if ($query.ContainsKey($key)) { throw 'Sonar report query is ambiguous.' }
        $query[$key] = [Uri]::UnescapeDataString($pair[1])
    }
    if ($query['id'] -cne $ProjectKey) { throw 'Sonar project does not match this analysis.' }
    if ($PullRequest) {
        if ($query['pullRequest'] -cne $PullRequest -or $query.ContainsKey('branch')) {
            throw 'Sonar PR does not match this analysis.'
        }
    }
    elseif ($query.ContainsKey('pullRequest') -or
            ($query.ContainsKey('branch') -and $query['branch'] -cne $Branch) -or
            (-not $query.ContainsKey('branch') -and $Branch -cne 'main')) {
        throw 'Sonar branch does not match this analysis.'
    }
}

function Get-FleetorySonarCompletionTime {
    param([object] $Check)
    $completed = [DateTimeOffset]::MinValue
    if ($Check.completed_at -is [DateTimeOffset]) { $completed = $Check.completed_at }
    elseif ($Check.completed_at -is [DateTime] -and $Check.completed_at.Kind -eq [DateTimeKind]::Utc) {
        $completed = [DateTimeOffset] $Check.completed_at
    }
    elseif ($Check.completed_at -isnot [string] -or
        -not [DateTimeOffset]::TryParseExact($Check.completed_at,
            [string[]]@("yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"),
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal),
            [ref] $completed)) { throw 'Official Sonar completion time is not UTC.' }
    return $completed
}

function Get-FleetorySonarCheck {
    param([object] $Response, [string] $Revision,
          [DateTimeOffset] $NotBefore = [DateTimeOffset]::MinValue)
    if ($null -eq $Response -or $null -eq $Response.PSObject.Properties['total_count'] -or
        $null -eq $Response.PSObject.Properties['check_runs'] -or
        ($Response.total_count -isnot [int] -and $Response.total_count -isnot [long]) -or $Response.total_count -lt 0 -or
        $Response.check_runs -isnot [array] -or
        $Response.total_count -ne $Response.check_runs.Count) {
        throw 'GitHub check response is incomplete.'
    }
    $officialChecks = @($Response.check_runs | Where-Object {
        $_.name -ceq 'SonarCloud Code Analysis' -and $_.head_sha -ceq $Revision -and
        $_.app.id -eq 12526 -and $_.app.slug -ceq 'sonarqubecloud'
    })
    if ($officialChecks.Count -gt 1) { throw 'Sonar check identity is ambiguous.' }
    if ($officialChecks.Count -eq 0 -or $officialChecks[0].status -ne 'completed') { return $null }
    if ((Get-FleetorySonarCompletionTime $officialChecks[0]).ToUnixTimeSeconds() -lt $NotBefore.ToUnixTimeSeconds()) { return $null }
    return $officialChecks[0]
}

function Assert-FleetorySonarCheckClean {
    param([object] $Check, [string] $ProjectKey, [string] $PullRequest,
          [string] $Branch, [DateTimeOffset] $NotBefore)
    if ($Check.conclusion -cne 'success') { throw 'Official Sonar check did not succeed.' }
    $completed = Get-FleetorySonarCompletionTime $Check
    if ($completed.ToUnixTimeSeconds() -lt $NotBefore.ToUnixTimeSeconds()) {
        throw 'Official Sonar check predates this analysis submission.'
    }
    Assert-FleetorySonarScope $Check.details_url '/dashboard' $ProjectKey $PullRequest $Branch
    foreach ($category in @('New', 'Accepted')) {
        $pattern = '\[(?<count>0|[1-9][0-9]*) ' + $category + ' issues?\]\((?<url>[^)\r\n]+)\)'
        $issueLinks = [regex]::Matches([string] $Check.output.summary, $pattern,
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if ($issueLinks.Count -ne 1) { throw 'Sonar issue count is absent, malformed or ambiguous.' }
        Assert-FleetorySonarScope $issueLinks[0].Groups['url'].Value '/project/issues' $ProjectKey $PullRequest $Branch
        $count = 0
        if (-not [int]::TryParse($issueLinks[0].Groups['count'].Value, [ref] $count) -or $count -ne 0) {
            throw "Fleetory requires zero $category Sonar issues."
        }
    }
}

function Get-FleetorySonarSubmission {
    param([string] $Path, [string] $ProjectKey)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or
        (Get-Item -LiteralPath $Path).Length -lt 1 -or (Get-Item -LiteralPath $Path).Length -gt 16384) {
        throw 'This run has no bounded Sonar submission artifact.'
    }
    $submission = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $pair = $line.Split('=', 2)
        if ($pair.Count -ne 2 -or $submission.ContainsKey($pair[0])) { throw 'Sonar submission artifact is malformed.' }
        $submission[$pair[0]] = $pair[1]
    }
    if ($submission['projectKey'] -cne $ProjectKey -or
        $submission['ceTaskId'] -cnotmatch '^[A-Za-z0-9_-]{1,128}$') {
        throw 'Sonar submission project/task does not match this run.'
    }
    return $submission
}

function Get-FleetoryVerifiedSonarSubmission {
    param([string] $ReportPath, [string] $ReceiptPath, [string] $ProjectKey,
          [string] $Revision, [string] $PullRequest, [string] $Branch)
    $submission = Get-FleetorySonarSubmission $ReportPath $ProjectKey
    if (-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf) -or
        (Get-Item -LiteralPath $ReceiptPath).Length -lt 1 -or (Get-Item -LiteralPath $ReceiptPath).Length -gt 4096) { throw 'Current official Sonar verification receipt is unavailable.' }
    $raw = [IO.File]::ReadAllText($ReceiptPath)
    $value = $raw | ConvertFrom-Json
    $runId = [Environment]::GetEnvironmentVariable('GITHUB_RUN_ID')
    $runAttempt = [Environment]::GetEnvironmentVariable('GITHUB_RUN_ATTEMPT')
    $keys = @('schema','projectKey','revision','pullRequest','branch','ceTaskId','checkId','completedAt','submissionSha256','runId','runAttempt')
    if (@($value.PSObject.Properties.Name).Count -ne $keys.Count -or
        @($value.PSObject.Properties.Name | Where-Object { $_ -notin $keys }).Count -ne 0 -or
        $value.schema -cne 'fleetory.sonar-verified-submission.v1' -or $Revision -cnotmatch '^[a-f0-9]{40}$' -or
        $value.revision -cne $Revision -or $value.projectKey -cne $ProjectKey -or
        $value.pullRequest -cne $PullRequest -or $value.branch -cne $Branch -or
        $value.ceTaskId -cne $submission['ceTaskId'] -or
        ($value.checkId -isnot [int] -and $value.checkId -isnot [long]) -or $value.checkId -le 0 -or
        $value.submissionSha256 -cne (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $runId -cnotmatch '^[1-9][0-9]{0,19}$' -or $runAttempt -cnotmatch '^[1-9][0-9]{0,19}$' -or
        $value.runId -isnot [string] -or $value.runId -cne $runId -or
        $value.runAttempt -isnot [string] -or $value.runAttempt -cne $runAttempt) {
        throw 'Official Sonar verification does not bind this submission/revision/scope.'
    }
    $completed = Get-FleetorySonarCompletionTime ([pscustomobject]@{completed_at=$value.completedAt})
    $value.completedAt = $completed.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
    $canonical = [ordered]@{}
    foreach ($key in $keys) { $canonical[$key] = $value.$key }
    if ($raw.TrimEnd("`r", "`n") -cne ($canonical | ConvertTo-Json -Compress)) { throw 'Sonar verification receipt is not canonical.' }
    $submitted = [DateTimeOffset](Get-Item -LiteralPath $ReportPath).LastWriteTimeUtc
    if ($completed.ToUnixTimeSeconds() -lt $submitted.ToUnixTimeSeconds()) { throw 'Sonar verification predates this submission.' }
    return $value
}
