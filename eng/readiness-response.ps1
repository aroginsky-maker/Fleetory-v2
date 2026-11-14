#Requires -Version 5.1
# ASP.NET's default health writer returns an exact text status, not JSON.
function Test-FleetoryReadinessResponse {
    [CmdletBinding()]
    param([object] $StatusCode, [object] $Content)

    if (($StatusCode -isnot [int] -and $StatusCode -isnot [long] -and
            $StatusCode -isnot [Net.HttpStatusCode]) -or $StatusCode -ne 200 -or
        $Content -isnot [string] -or $Content.Length -gt 64) {
        return $false
    }
    return [string]::Equals($Content, 'Healthy', [StringComparison]::Ordinal)
}
