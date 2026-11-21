#requires -Version 7.3
. (Join-Path $PSScriptRoot 'PublicBuildImageTransaction.ps1')
if(-not ('Fleetory.Pilot.PublicBuildSourceTransport' -as [type])){
    Add-Type -Path (Join-Path $PSScriptRoot 'public_build/SourceTransport.cs')
}

# Trusted surviving worker API only. A source process is not a recovery grant.
# The caller owns executable/code admission and supplies the actual live transport.
function Invoke-PublicBuildSourceTransaction(
    [Fleetory.Pilot.PublicBuildSourceTransport]$Source,[string]$ExpectedContextSha256,
    [scriptblock]$Native,[scriptblock]$ControllerAlive,[scriptblock]$UseImage){
    if($null -eq $Source){throw 'Public source transport required.'}
    try{
        if($ExpectedContextSha256 -cnotmatch '^[a-f0-9]{64}\z' -or $null -eq $Native -or
            $null -eq $ControllerAlive -or $null -eq $UseImage){throw 'Public source transaction input refused.'}
        $initial=@(& $ControllerAlive)
        if($initial.Count -ne 1 -or $initial[0] -isnot [bool] -or -not $initial[0]){throw 'Public build controller unavailable or expired.'}
        $bytes=$Source.Take([Convert]::FromHexString($ExpectedContextSha256))
        $alive={
            if(-not $Source.IsAlive()){return $false}
            $value=@(& $ControllerAlive)
            return ($value.Count -eq 1 -and $value[0] -is [bool] -and $value[0])
        }.GetNewClosure()
        $use={param($Context,$Client)
            $Source.RequestBeforeSdk()
            return & $UseImage $Context $Client $alive
        }.GetNewClosure()
        return Invoke-PublicBuildImageTransaction $bytes $ExpectedContextSha256 $Native $alive $use
    }finally{
        # Image cleanup has already unwound through its original CWT context.
        # Only the source-only child is stopped here; never its resource owner.
        $Source.Dispose()
    }
}
