#requires -Version 7.3
param([Parameter(Mandatory)][string]$Python,[Parameter(Mandatory)][string]$InputRoot,[switch]$ExitAfterRelease,[switch]$InjectCodeName)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
foreach($name in @('PilotNativeProcess.ps1','ProviderRecoveryTransport.ps1','ProviderRecoveryPolicy.ps1','ImmuDataRoundtripPolicy.ps1',
    'AuditDataResourceOwnership.ps1','HistoricalRecoveryInFlight.ps1','HistoricalRecoveryCoordinator.ps1','historical/RetainedServiceUseTransport.ps1')){
    . (Join-Path $repo ('eng/pilot/'+$name))
}
$request=Get-Content -Raw -LiteralPath (Join-Path $InputRoot 'generated-peer-metadata.json')|ConvertFrom-Json -AsHashtable -Depth 20
$metadata=@{}
foreach($name in @('selection','manifest','checkpoint','ci','local')){$metadata[$name]=[Convert]::FromBase64String($request.metadata[$name])}
$peer=$null;$canary=$null;$canaryOwned=$false
try{
    $mode=if($ExitAfterRelease){'exit-after-release'}else{'normal'}
    $peer=Open-RetainedServiceUsePeer $repo $Python $InputRoot $metadata $request.commitments -Mode $mode
    if($ExitAfterRelease){
        try{$null=Receive-RetainedServicePayload $peer}catch{
            if(-not $peer.holder.WaitForExit(3500) -or $peer.holder.ExitCode -ne 37){throw}
        }
        Assert-ImmuData ($peer.holder.WaitForExit(3500) -and $peer.holder.ExitCode -eq 37) 'prototype-actual-peer-death'
        try{Confirm-RetainedServiceUseLive $peer $peer.cancel.Token;throw 'prototype-dead-peer-accepted'}catch{
            if($_.Exception.Message -notmatch 'service-peer-actual-owner'){throw}
        }
        @{schema='fleetory.retained-service-parent-transport-prototype.v1';verified=$true;mode=$mode;
            actualPowerShellParentBound=$true;actualChildExitVerified=$true;childExitCode=37;deadPeerRejected=$true;
            nativeTargetInvoked=$false;originalInputsRead=$false;nativeResultAuthenticated=$false;
            originalExecutorReady=$false;phase7Complete=$false}|ConvertTo-Json -Compress
        return
    }
    $rejected=0
    foreach($operation in @('assert','close')){
        $copy=$peer.Clone()
        try{
            if($operation -eq 'assert'){Assert-RetainedServicePeer $copy}else{Close-RetainedServiceUsePeer $copy}
            throw 'prototype-copied-peer-accepted'
        }catch{
            if($_.Exception.Message -notmatch 'service-peer-unregistered'){throw}
            $rejected++
        }
    }
    $originalHolder=$peer.holder
    try{
        $peer.holder=[Diagnostics.Process]::GetCurrentProcess()
        try{Assert-RetainedServicePeer $peer;throw 'prototype-replaced-holder-accepted'}catch{
            if($_.Exception.Message -notmatch 'service-peer-replaced-handle'){throw}
            $rejected++
        }
    }finally{$peer.holder.Dispose();$peer.holder=$originalHolder}
    $payload=Receive-RetainedServicePayload $peer
    Assert-ImmuData ($payload.capture.verifiedArtifacts -eq 4 -and $payload.packets.Count -eq 4 -and $payload.executionAuthorized -eq $false) 'prototype-four-packets'
    if($InjectCodeName){
        $canary=Join-Path $repo ('eng/pilot/generated-code-canary-'+[Guid]::NewGuid().ToString('N')+'.py')
        $writer=[IO.FileStream]::new($canary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$canaryOwned=$true;$bytes=[Text.Encoding]::ASCII.GetBytes('# generated namespace canary');$writer.Write($bytes)}finally{$writer.Dispose()}
        $refused=Read-RetainedServiceMessage $peer
        Assert-ImmuData ($refused.Count -eq 3 -and $refused.kind -ceq 'code-refused' -and $refused.nonce -ceq $peer.nonce -and
            $refused.codePlanSha256 -ceq $peer.codePlanSha256 -and $peer.holder.WaitForExit(3500) -and $peer.holder.ExitCode -eq 1) 'prototype-code-namespace-refusal'
        @{schema='fleetory.retained-code-namespace-refusal.v1';verified=$true;packets=4;
            heldCodeFiles=$peer.codeFiles;typedCodeRefusalBeforeNativeTarget=$true;actualChildExitVerified=$true;
            nativeTargetInvoked=$false;originalInputsRead=$false;originalExecutorReady=$false;phase7Complete=$false}|ConvertTo-Json -Compress
        return
    }
    Confirm-RetainedServiceUseLive $peer $peer.cancel.Token
    Confirm-RetainedServiceUseLive $peer $peer.cancel.Token
    $receipt=Complete-RetainedServiceUse $peer ([Text.Encoding]::UTF8.GetBytes('generated-native-consumer-result'))
    Assert-ImmuData ($receipt.statusChecks -eq 2 -and $peer.closed -and $peer.holder.HasExited -and $peer.holder.ExitCode -eq 0) 'prototype-peer-complete'
    @{schema='fleetory.retained-service-parent-transport-prototype.v1';verified=$true;packets=4;statusChecks=2;
        actualPowerShellParentBound=$true;actualChildExitVerified=$true;copiedOrReplacedPeersRejected=$rejected;nativeTargetInvoked=$false;originalInputsRead=$false;
        nativeResultAuthenticated=$false;originalExecutorReady=$false;phase7Complete=$false}|ConvertTo-Json -Compress
}finally{
    try{Close-RetainedServiceUsePeer $peer}finally{
        if($canaryOwned){
            Assert-ImmuData ([IO.File]::ReadAllText($canary) -ceq '# generated namespace canary') 'prototype-owned-canary-content'
            [IO.File]::Delete($canary)
        }
    }
}
