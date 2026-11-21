#requires -Version 7.3
. (Join-Path $PSScriptRoot 'AuditDataResourceOwnership.ps1')
. (Join-Path $PSScriptRoot 'PublicBuildImagePolicy.ps1')

# Trusted live worker API only. There is no metadata import or native CLI entry.
# The worker must keep this stack alive across controller loss; a dead worker's
# claims cannot be recreated from the returned diagnostic metadata.
function Invoke-PublicBuildImageTransaction([byte[]]$Archive,[string]$ExpectedContextSha256,
    [scriptblock]$Native,[scriptblock]$ControllerAlive,[scriptblock]$UseImage){
    if($null -eq $Archive -or $Archive.Length -eq 0 -or $Archive.Length -gt 67108864 -or
        $ExpectedContextSha256 -cnotmatch '^[a-f0-9]{64}\z' -or $null -eq $Native -or
        $null -eq $ControllerAlive -or $null -eq $UseImage){throw 'Public build transaction input refused.'}
    $sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Archive)).ToLowerInvariant()
    if($sha -cne $ExpectedContextSha256){throw 'Public build transaction context refused.'}
    $fixture=[guid]::NewGuid().ToString('D')
    $context=@{Fixture=$fixture;Root='public-offline-build';ImageName=('fleetory-public-build-'+$fixture);
        SourceContextSha256=$sha;SdkImage='mcr.microsoft.com/dotnet/sdk@sha256:8dd1a57fe6b7b8b1b357635db67e272c2f9e9d76d1dd0a32711c4c33c57d7b43';
        ImageId=$null;ImageClaimed=$false}
    $client=$Native
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $image=$null
    $result=$null
    function Assert-Controller {
        $alive=@(& $ControllerAlive)
        if($alive.Count -ne 1 -or $alive[0] -isnot [bool] -or -not $alive[0] -or $clock.Elapsed.TotalSeconds -ge 420){throw 'Public build controller unavailable or expired.'}
    }
    function Invoke-Fixed([string[]]$Arguments,[byte[]]$InputBytes=$null){
        $frozen=[string[]]$Arguments.Clone()
        $reply=& $client $Arguments $InputBytes
        if(($Arguments -join "`0") -cne ($frozen -join "`0") -or $reply -isnot [Tuple[int,byte[],byte[]]]){throw 'Public build native reply or arguments refused.'}
        return $reply
    }
    try{
        Assert-Controller
        $arguments=Get-PublicBuildImageArguments $fixture
        $build=[Func[Tuple[int,byte[],byte[]]]]{Invoke-Fixed $arguments $Archive}
        $image=[Fleetory.Pilot.PublicBuildImageCustody]::Build($context,$client,$Archive,$build)
        Assert-Controller
        $result=& $UseImage $context $client
        Assert-Controller
    }finally{
        # No recovery by name or label when the original complete reply is unknown.
        if($null -ne $image){
            $owned=[Fleetory.Pilot.PublicBuildImageCustody]::Id($context,$client)
            $remove=[Func[Tuple[int,byte[],byte[]]]]{Invoke-Fixed @('image','rm','--no-prune',$owned)}
            [Fleetory.Pilot.PublicBuildImageCustody]::Remove($context,$client,$remove)
            $inspect=[Func[Tuple[int,byte[],byte[]]]]{Invoke-Fixed @('image','inspect',$owned)}
            [Fleetory.Pilot.PublicBuildImageCustody]::ConfirmRemoval($context,$client,$inspect)
            if(-not [Fleetory.Pilot.PublicBuildImageCustody]::Closed($context,$client)){throw 'Public build image closure refused.'}
        }
        $clock.Stop()
    }
    return @{schema='fleetory.public-build-image-transaction.v1';imageClosed=$true;result=$result;
        sourceContextSha256=$sha;nativeSdkLifecycleVerified=$false;controllerDeathVerified=$false;
        originalInputsRead=$false;phase7Complete=$false}
}
