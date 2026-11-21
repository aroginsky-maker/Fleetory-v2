#requires -Version 7.3
# Generated data through the same native target; no original gate/consent authority is inferred.
function Invoke-NativeRetainedServiceUseWorkflow([string]$InputRoot,[hashtable]$Metadata,[hashtable]$Expected,$AuditPoint){
    foreach($helper in @('HistoricalRecoveryInFlight.ps1','HistoricalRecoveryCoordinator.ps1','historical/RetainedConfiguration.ps1',
        'historical/RetainedServiceUseTransport.ps1','historical/RetainedDataStageHost.ps1')){. (Join-Path $repo ('eng/pilot/'+$helper))}
    $imageRoot=Join-Path $root 'retained-owned-public-build';$null=New-Item -ItemType Directory -Path $imageRoot
    Copy-Item -LiteralPath (Join-Path $root 'publish') -Destination (Join-Path $imageRoot 'publish') -Recurse
    $imageContext=@{Fixture=[Guid]::NewGuid().ToString('D');Root=$imageRoot;ImageName=('retained-service-'+[Guid]::NewGuid().ToString('N'));
        ProbeHash=$state.ProbeHash;ImageId=$null;ImageClaimed=$false}
    $result=$null
    $expiry=$Profile -ceq 'v2-retained-service-use-expiry'
    $loss=$Profile -cin @('v2-retained-service-use-loss','v2-retained-service-use-expiry')
    try{
        Build-AuditDataImage $imageContext 'codenotary/immuadmin:1.11.2@sha256:fd52f498485dcaf792677bf7d4b5b12c3bc77af80ab0718981aea9fd085ee8bd'
        $material=New-NativeRetainedMaterial 'service-use' $true
        $configuration=New-RetainedConfiguration $material $true $true
        $generated=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'native_retained_pg_inputs.py'),'generated-gates') -TimeoutSeconds 10
        Assert-Pair ($generated.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($generated.Stderr)) 'service-use-generated-gates'
        $gates=$generated.Stdout|ConvertFrom-Json -AsHashtable
        Assert-Pair ($gates.generatedFixtureOnly -and -not $gates.gateOriginAuthenticated) 'service-use-no-origin-authority'
        $raw=@{}
        foreach($name in @('selection','manifest','checkpoint')){$raw[$name]=[Convert]::FromBase64String($Metadata.body[$name])}
        foreach($name in @('ci','local')){$raw[$name]=[Convert]::FromBase64String($gates.body[$name])}
        $commitments=@{nonce=$fixture;revision=$gates.revision;imageId=$imageContext.ImageId;
            probeSha256=$imageContext.ProbeHash;configurationSha256=$configuration.Sha256}
        $script:stage='retained-service-open'
        $mode=if($expiry){'expire-after-restore'}elseif($loss){'exit-on-request'}else{'normal'}
        $afterCapture={
            foreach($relative in $Metadata.generatedPaths.Values){
                $path=Join-Path $InputRoot $relative
                $null=Get-ProviderOrdinaryItem $path
                [IO.File]::WriteAllText($path,'generated path replaced after private transfer')
            }
        }
        $result=Invoke-RetainedDataStageHost $repo $Python $InputRoot $raw $commitments $Expected $AuditPoint $imageContext $material -Mode $mode -GeneratedAfterCapture $afterCapture
        $result.schema='fleetory.native-retained-service-use-stage.v1'
        $result.allFourGeneratedPathsReplacedAfterCapture=$true
        $result.sourceOriginalFilesRead=$false
        return $result
    }finally{
        if($imageContext.ImageClaimed -and -not (Test-AuditDataImageClosed $imageContext)){Remove-AuditDataImage $imageContext}
    }
}
