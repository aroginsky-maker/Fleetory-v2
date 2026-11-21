#requires -Version 7.3
# Native owner remains this actual PowerShell process. No Docker/resource authority comes from these frames.
$script:RetainedServicePeers=[Runtime.CompilerServices.ConditionalWeakTable[object,object]]::new()
function Assert-RetainedServicePeerObject($Peer){
    $sealed=$null
    Assert-ImmuData ($null -ne $Peer -and $script:RetainedServicePeers.TryGetValue($Peer,[ref]$sealed)) 'service-peer-unregistered'
    foreach($name in @('owner','holder','cancel','errorStream')){
        Assert-ImmuData ([object]::ReferenceEquals($Peer[$name],$sealed[$name])) 'service-peer-replaced-handle'
    }
}
function Assert-RetainedServicePeer($Peer){
    Assert-RetainedServicePeerObject $Peer
    Assert-ImmuData ($Peer.owner.Id -eq $PID -and -not $Peer.owner.HasExited -and
        (Get-HistoricalNativeBirth $Peer.owner).token -ceq $Peer.ownerBirth.token -and
        $null -ne $Peer.holder -and -not $Peer.holder.HasExited -and
        (Get-HistoricalNativeBirth $Peer.holder).token -ceq $Peer.childBirth.token) 'service-peer-actual-owner'
    $Peer.cancel.Token.ThrowIfCancellationRequested()
}
function Send-RetainedServiceMessage($Peer,$Message){
    Send-IndependentFrame $Peer.input ([Text.Encoding]::UTF8.GetBytes(($Message|ConvertTo-Json -Depth 8 -Compress))) $Peer.cancel.Token
}
function Read-RetainedServiceMessage($Peer){
    return (Read-IndependentFrame $Peer.output $Peer.cancel.Token 32768)|ConvertFrom-Json -AsHashtable -Depth 12
}
function Open-RetainedServiceUsePeer([string]$Repository,[string]$Python,[string]$InputRoot,[hashtable]$Metadata,[hashtable]$Commitments,
    [ValidateSet('normal','exit-after-release','exit-on-request','expire-after-restore')][string]$Mode='normal'){
    $expected=Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Assert-ImmuData ($Repository -ceq $expected -and $Metadata.Count -eq 5) 'service-peer-repository'
    . (Join-Path $PSScriptRoot '../HistoricalAuditInputPins.ps1')
    $sourceSnapshot=Get-HistoricalAuditCodeSnapshot $Repository -IncludeSourcePins
    $codeBody=[Text.Encoding]::UTF8.GetBytes((@{snapshot=$sourceSnapshot;nonce=$Commitments.nonce}|ConvertTo-Json -Depth 10 -Compress))
    $codeReply=Invoke-NativeBytes $Python @('-I','-S','-B',(Join-Path $PSScriptRoot 'retained_source_bootstrap.py'),'catalog') $codeBody 20
    Assert-ImmuData ($codeReply.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($codeReply.Stderr)) 'service-peer-code-catalog'
    $code=$codeReply.Stdout|ConvertFrom-Json -AsHashtable
    $request=@{metadata=@{};nonce=$Commitments.nonce;revision=$Commitments.revision;imageId=$Commitments.imageId;
        probeSha256=$Commitments.probeSha256;configurationSha256=$Commitments.configurationSha256;mode=$Mode;codePlan=$code.plan;codePlanSha256=$code.sha256}
    foreach($name in @('selection','manifest','checkpoint','ci','local')){
        Assert-ImmuData ($Metadata.ContainsKey($name) -and $Metadata[$name] -is [byte[]]) 'service-peer-metadata'
        $request.metadata[$name]=[Convert]::ToBase64String($Metadata[$name])
    }
    $operator=Join-Path (Split-Path $InputRoot -Parent) 'operator'
    if(-not(Test-Path -LiteralPath $operator)){[Fleetory.Pilot.ExclusiveAuditDirectory]::Create($operator)}
    $oldDirectory=[Environment]::CurrentDirectory
    try{
        [Environment]::CurrentDirectory=$InputRoot
        $prepared=Invoke-NativeBytes $Python @('-I','-S','-B',(Join-Path $PSScriptRoot 'retained_source_bootstrap.py'),'peer','--prepare') ([Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Depth 8 -Compress))) 20
        $category='unclassified'
        foreach($stage in @('metadata','parent-runtime','parent-identity')){
            if($prepared.Stderr.TrimEnd() -ceq ('Retained service preparation refused at '+$stage+'; no input contents logged.')){$category=$stage}
        }
        Assert-ImmuData ($prepared.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($prepared.Stderr)) ('service-peer-header-'+$category)
        $header=$prepared.Stdout|ConvertFrom-Json -AsHashtable -Depth 8
    }finally{[Environment]::CurrentDirectory=$oldDirectory}
    $self=[Diagnostics.Process]::GetCurrentProcess();$null=$self.Handle
    $selfBirth=Get-HistoricalNativeBirth $self
    Assert-ImmuData ($header.parent.pid -eq $self.Id -and $header.parent.birthKind -ceq $selfBirth.kind -and
        $header.parent.birthToken -ceq $selfBirth.token -and $header.nonce -ceq $Commitments.nonce) 'service-peer-header-parent'
    $originalClock=[Diagnostics.Stopwatch]::StartNew()
    $peer=@{holder=$null;owner=$self;ownerBirth=$selfBirth;childBirth=$null;originalClock=$originalClock;cancel=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(108));
        input=$null;output=$null;nonce=$Commitments.nonce;headerSha256=$header.sha256;planSha256=$null;payloadSha256=$null;
        mode=$Mode;codePlanSha256=$code.sha256;codeFiles=$code.files;statusChecks=0;result=$false;closed=$false;errorStream=[Fleetory.Tests.PilotCaptureStream]::new(4096);errorDrain=$null}
    $sealed=@{owner=$peer.owner;holder=$null;cancel=$peer.cancel;errorStream=$peer.errorStream}
    $script:RetainedServicePeers.Add($peer,$sealed)
    try{
        $start=New-HistoricalChildStart $Python
        $start.WorkingDirectory=$InputRoot
        foreach($part in @('-I','-S','-B',(Join-Path $PSScriptRoot 'retained_source_bootstrap.py'),'peer','--header-sha256',$header.sha256)){$start.ArgumentList.Add($part)}
        $peer.holder=[Diagnostics.Process]::Start($start);$null=$peer.holder.Handle
        $sealed.holder=$peer.holder
        $peer.childBirth=Get-HistoricalNativeBirth $peer.holder
        $peer.input=$peer.holder.StandardInput.BaseStream;$peer.output=$peer.holder.StandardOutput.BaseStream
        $peer.errorDrain=$peer.holder.StandardError.BaseStream.CopyToAsync($peer.errorStream)
        Send-IndependentFrame $peer.input ([Convert]::FromBase64String($header.header)) $peer.cancel.Token
        $bound=Read-RetainedServiceMessage $peer
        Assert-ImmuData ($bound.Count -eq 8 -and $bound.codePlanSha256 -ceq $Peer.codePlanSha256 -and $bound.codeFiles -eq $Peer.codeFiles -and $bound.kind -ceq 'bound' -and $bound.nonce -ceq $peer.nonce -and
            $bound.headerSha256 -ceq $peer.headerSha256 -and $bound.owner.pid -eq $peer.holder.Id -and
            $bound.owner.birthKind -ceq $peer.childBirth.kind -and $bound.owner.birthToken -ceq $peer.childBirth.token -and
            $bound.consumer.pid -eq $PID -and $bound.consumer.birthToken -ceq $peer.ownerBirth.token) 'service-peer-bound'
        $peer.planSha256=$bound.planSha256
        Assert-RetainedServicePeer $peer
        return $peer
    }catch{Close-RetainedServiceUsePeer $peer;throw}
}
function Receive-RetainedServicePayload($Peer){
    Assert-RetainedServicePeer $Peer
    Assert-ImmuData ($null -eq $Peer.payloadSha256) 'service-peer-capture-replay'
    Send-RetainedServiceMessage $Peer @{kind='capture';nonce=$Peer.nonce}
    $envelope=Read-RetainedServiceMessage $Peer
    Assert-ImmuData ($envelope.Count -eq 6 -and $envelope.kind -ceq 'payload' -and $envelope.nonce -ceq $Peer.nonce -and
        $envelope.planSha256 -ceq $Peer.planSha256 -and $envelope.consumer.pid -eq $PID -and
        $envelope.consumer.birthToken -ceq $Peer.ownerBirth.token -and $envelope.payloadBytes -gt 0 -and
        $envelope.payloadBytes -le 25165824 -and $envelope.payloadSha256 -cmatch '^[a-f0-9]{64}\z') 'service-peer-payload'
    $raw=Read-IndependentFrame $Peer.output $Peer.cancel.Token 25165824
    $bytes=[Text.Encoding]::UTF8.GetBytes($raw)
    Assert-ImmuData ($bytes.Length -eq $envelope.payloadBytes -and (Get-ImmuDataHash $bytes) -ceq $envelope.payloadSha256) 'service-peer-payload-pin'
    $Peer.payloadSha256=$envelope.payloadSha256
    return $raw|ConvertFrom-Json -AsHashtable -Depth 20
}
function Confirm-RetainedServiceUseLive($Peer,[Threading.CancellationToken]$Token){
    Assert-RetainedServicePeer $Peer
    Assert-ImmuData ($null -ne $Peer.payloadSha256 -and -not $Peer.result -and $Peer.statusChecks -lt 256) 'service-peer-live-stage'
    $sequence=$Peer.statusChecks+1
    $value=@{kind='status';nonce=$Peer.nonce;sequence=$sequence;payloadSha256=$Peer.payloadSha256}
    Send-IndependentFrame $Peer.input ([Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Compress))) $Token
    $reply=(Read-IndependentFrame $Peer.output $Token 512)|ConvertFrom-Json -AsHashtable
    Assert-ImmuData ($reply.Count -eq 4 -and $reply.kind -ceq 'live' -and $reply.nonce -ceq $Peer.nonce -and
        $reply.sequence -eq $sequence -and $reply.payloadSha256 -ceq $Peer.payloadSha256) 'service-peer-live-reply'
    $Peer.statusChecks=$sequence
    Assert-RetainedServicePeer $Peer
}
function Complete-RetainedServiceUse($Peer,[byte[]]$Result){
    Assert-RetainedServicePeer $Peer
    Assert-ImmuData (-not $Peer.result -and $null -ne $Peer.payloadSha256 -and $Result.Length -gt 0 -and $Result.Length -le 184320) 'service-peer-result-stage'
    $Peer.result=$true
    $digest=Get-ImmuDataHash $Result
    Send-RetainedServiceMessage $Peer @{kind='result';nonce=$Peer.nonce;resultSha256=$digest}
    Send-IndependentFrame $Peer.input $Result $Peer.cancel.Token
    $receipt=Read-RetainedServiceMessage $Peer
    Assert-ImmuData ($receipt.Count -eq 11 -and $receipt.codePlanSha256 -ceq $Peer.codePlanSha256 -and $receipt.codeFiles -eq $Peer.codeFiles -and $receipt.kind -ceq 'receipt' -and $receipt.nonce -ceq $Peer.nonce -and
        $receipt.planSha256 -ceq $Peer.planSha256 -and $receipt.resultSha256 -ceq $digest -and
        $receipt.statusChecks -eq $Peer.statusChecks -and $receipt.actualParentIdentityBound -eq $true -and
        $receipt.nativeResultAuthenticated -eq $false -and $receipt.executionAuthorized -eq $false -and $receipt.phase7Complete -eq $false) 'service-peer-result-receipt'
    Send-RetainedServiceMessage $Peer @{kind='close';nonce=$Peer.nonce}
    $Peer.input.Dispose();$Peer.input=$null
    $closed=Read-RetainedServiceMessage $Peer
    Assert-ImmuData ($closed.Count -eq 3 -and $closed.kind -ceq 'closed' -and $closed.nonce -ceq $Peer.nonce -and $closed.phase7Complete -eq $false) 'service-peer-closed'
    Assert-ImmuData ($Peer.holder.WaitForExit(3500) -and $Peer.holder.ExitCode -eq 0) 'service-peer-exit'
    $Peer.closed=$true
    return $receipt
}
function Invoke-GeneratedRetainedServicePeerExit($Peer){
    Assert-RetainedServicePeer $Peer
    Assert-ImmuData ($Peer.mode -ceq 'exit-on-request' -and $null -ne $Peer.payloadSha256 -and -not $Peer.result) 'service-peer-generated-fault-mode'
    Send-RetainedServiceMessage $Peer @{kind='generated-fault-exit';nonce=$Peer.nonce;payloadSha256=$Peer.payloadSha256}
    Assert-ImmuData ($Peer.holder.WaitForExit(3500) -and $Peer.holder.ExitCode -eq 37) 'service-peer-generated-fault-exit'
}
function Wait-GeneratedRetainedServiceUseExpiry($Peer){
    Assert-RetainedServicePeer $Peer
    Assert-ImmuData ($Peer.mode -ceq 'expire-after-restore' -and $null -ne $Peer.payloadSha256 -and -not $Peer.result) 'service-peer-generated-expiry-mode'
    while(-not $Peer.cancel.IsCancellationRequested){
        Assert-ImmuData (-not $Peer.holder.HasExited) 'service-peer-exit-before-original-expiry'
        Start-Sleep -Milliseconds 50
    }
    Assert-ImmuData ($Peer.originalClock.ElapsedMilliseconds -ge 108000 -and
        $Peer.holder.WaitForExit(3500) -and $Peer.holder.ExitCode -ne 0) 'service-peer-original-expiry-exit'
    return $Peer.originalClock.ElapsedMilliseconds
}
function Close-RetainedServiceUsePeer($Peer){
    if($null -eq $Peer){return}
    Assert-RetainedServicePeerObject $Peer
    try{
        if($null -ne $Peer.input){$Peer.input.Dispose();$Peer.input=$null}
        if($null -ne $Peer.holder){
            Assert-ImmuData ($Peer.holder.HasExited -or $Peer.holder.WaitForExit(3500)) 'service-peer-exit-unverified'
            if($null -ne $Peer.errorDrain){$null=$Peer.errorDrain.WaitAsync([TimeSpan]::FromSeconds(3)).GetAwaiter().GetResult()}
        }
    }finally{
        if($null -ne $Peer.holder -and $Peer.holder.HasExited){$Peer.holder.Dispose()}
        $Peer.owner.Dispose();$Peer.cancel.Dispose();$Peer.errorStream.Dispose()
        $null=$script:RetainedServicePeers.Remove($Peer)
    }
}
