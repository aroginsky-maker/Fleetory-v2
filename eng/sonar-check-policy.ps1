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
