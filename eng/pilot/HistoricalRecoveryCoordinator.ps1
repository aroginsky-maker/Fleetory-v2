function Send-IndependentFrame([IO.Stream]$Stream,[byte[]]$Bytes,[Threading.CancellationToken]$Token){
    Assert-ImmuData ($Bytes.Length -gt 0 -and $Bytes.Length -le 184320) 'independent-input-bound'
    $header=[BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder([int]$Bytes.Length))
    foreach($part in @($header,$Bytes)){
        $null=$Stream.WriteAsync($part,0,$part.Length,$Token).WaitAsync($Token).GetAwaiter().GetResult()
    }
    $null=$Stream.FlushAsync($Token).WaitAsync($Token).GetAwaiter().GetResult()
}
function Read-IndependentFrame([IO.Stream]$Stream,[Threading.CancellationToken]$Token,[int]$Maximum=184320){
    $header=[byte[]]::new(4)
    $null=$Stream.ReadExactlyAsync([Memory[byte]]::new($header),$Token).AsTask().WaitAsync($Token).GetAwaiter().GetResult()
    $size=[Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($header,0))
    Assert-ImmuData ($size -gt 0 -and $size -le $Maximum) 'independent-output-bound'
    $bytes=[byte[]]::new($size)
    $null=$Stream.ReadExactlyAsync([Memory[byte]]::new($bytes),$Token).AsTask().WaitAsync($Token).GetAwaiter().GetResult()
    return [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
}
# The surviving historical owner keeps every Docker operation in its own process.
function Open-HistoricalRecoveryCoordinator([string]$Flow){
    $cancel=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(108))
    $peer=@{flow=$Flow;holder=$null;cancel=$cancel;input=$null;output=$null;projection=$null;
        lease=$null;allocationRequests=0;workRequests=0;workAdmitted=$false;expiredLiveCleanup=$false;allocationReplayRefused=$false;
        workStatusRequests=0;workStatusChecks=0}
    try{
        $peer.holder=[Diagnostics.Process]::Start((New-IndependentControllerStart $Flow '--recovery-owner'))
        Assert-ImmuData ($null -ne $peer.holder -and $peer.holder.Id -ne $PID) 'coordinator-supervisor'
        $peer.input=$peer.holder.StandardInput.BaseStream
        $peer.output=$peer.holder.StandardOutput.BaseStream
        Assert-ImmuData ((Read-IndependentFrame $peer.output $cancel.Token 96) -ceq ('ready:'+$plan.nonce)) 'coordinator-ready'
        return $peer
    }catch{
        Close-HistoricalRecoveryCoordinator $peer
        throw
    }
}
function Send-HistoricalCoordinatorFrame($Peer,[string]$Value){
    Send-IndependentFrame $Peer.input ([Text.Encoding]::ASCII.GetBytes($Value)) $Peer.cancel.Token
}
function Receive-HistoricalCoordinatorFrame($Peer,[string]$Expected){
    Assert-ImmuData ((Read-IndependentFrame $Peer.output $Peer.cancel.Token 96) -ceq $Expected) 'coordinator-frame'
}
function Enter-HistoricalCoordinatorAllocation($Peer){
    Assert-ImmuData ($Peer.allocationRequests -eq 0) 'coordinator-allocation-replay'
    Send-HistoricalCoordinatorFrame $Peer 'allocate'
    Receive-HistoricalCoordinatorFrame $Peer ('acquire:'+$plan.nonce)
    $Peer.allocationRequests++
}
function Set-HistoricalCoordinatorProjection($Peer){
    Read-AuditDataStore $context $store
    $client=${function:Invoke-Docker}
    $image=[Fleetory.Pilot.AuditImageCustody]::Id($context,$client)
    $id=[Fleetory.Pilot.AuditContainerCustody]::Id($context,$store,$client)
    Assert-ImmuData ($Peer.allocationRequests -eq 1 -and $null -eq $Peer.projection -and $context.PayloadClaimed -and
        -not $context.PayloadRemoved -and (Test-Path -LiteralPath $context.Root -PathType Container)) 'coordinator-custody'
    $Peer.lease=[Diagnostics.Stopwatch]::StartNew()
    $bytes=[Text.Encoding]::ASCII.GetBytes(($plan.nonce,$context.Fixture,$image,$id -join '|'))
    $Peer.projection=Get-ImmuDataHash $bytes
    Send-HistoricalCoordinatorFrame $Peer ('owned:'+$Peer.projection)
    Receive-HistoricalCoordinatorFrame $Peer ('received:'+$Peer.projection)
}
function Read-HistoricalCoordinatorWork($Peer){
    Assert-ImmuData ($Peer.workRequests -eq 0 -and $null -ne $Peer.projection) 'coordinator-work-replay'
    Send-HistoricalCoordinatorFrame $Peer 'work'
    Receive-HistoricalCoordinatorFrame $Peer ('run:'+$Peer.projection)
    $Peer.workRequests++
}
function Finish-HistoricalRecoveryCoordinator($Peer,[ValidateSet('terminate','completed','refused','allocation-refused')][string]$Outcome){
    Send-HistoricalCoordinatorFrame $Peer $Outcome
    $Peer.input.Dispose()
    return Receive-HistoricalCoordinatorCompletion $Peer $Outcome
}
function Receive-HistoricalCoordinatorCompletion($Peer,[ValidateSet('terminate','completed','refused','allocation-refused')][string]$Outcome,[string]$ResultFrame=''){
    $token=$Peer.cancel.Token
    if(-not $ResultFrame){$ResultFrame=Read-IndependentFrame $Peer.output $token 2048}
    $result=$ResultFrame|ConvertFrom-Json -AsHashtable -Depth 4
    $holder=$Peer.holder
    $null=$holder.WaitForExitAsync($token).GetAwaiter().GetResult()
    $fence=if($IsLinux){'linux-process-group'}else{'windows-job-object'}
    Assert-ImmuData ($holder.ExitCode -eq 0 -and $Peer.output.ReadByte() -eq -1 -and $holder.StandardError.BaseStream.ReadByte() -eq -1 -and
        $result.Count -eq 13 -and $result.schema -ceq 'fleetory.historical-recovery-coordinator.v1' -and
        $result.nonce -ceq $plan.nonce -and $result.flow -ceq $Peer.flow -and $result.projection -ceq $Peer.projection -and
        $result.supervisorPid -eq $holder.Id -and $result.coordinatorPid -is [long] -and $result.coordinatorPid -gt 0 -and
        $result.coordinatorPid -notin @($PID,$holder.Id) -and $result.identityVerified -eq $true -and
        $result.membersAbsent -eq $true -and $result.exitObservedHeld -eq $true -and $result.fence -ceq $fence -and
        ($result.coordinatorExitCode -ne 0) -eq ($Outcome -ceq 'terminate') -and
        $result.lateRequestRefused -eq ($Outcome -ceq 'refused') -and
        $result.allocationReplayRefused -eq $Peer.allocationReplayRefused -and
        $result.allocationReplayRefused -eq ($Outcome -ceq 'allocation-refused')) 'coordinator-evidence'
    $result.ownerPid=$PID
    $result.allocationRequests=$Peer.allocationRequests
    $result.workRequests=$Peer.workRequests
    $result.workAdmitted=$Peer.workAdmitted
    $result.expiredLiveCleanup=$Peer.expiredLiveCleanup
    $result.workStatusRequests=$Peer.workStatusRequests
    $result.workStatusChecks=$Peer.workStatusChecks
    return $result
}
function Complete-HistoricalCoordinatorCreateRefusal($Peer){
    Assert-ImmuData ($Peer.allocationRequests -eq 1 -and $null -eq $Peer.projection -and
        $Peer.workRequests -eq 0 -and -not $Peer.workAdmitted) 'coordinator-allocation-unavailable'
    Send-HistoricalCoordinatorFrame $Peer ('unavailable:'+$plan.nonce)
    Receive-HistoricalCoordinatorFrame $Peer ('retry:'+$plan.nonce)
    $blocked=$false
    try{Enter-HistoricalCoordinatorAllocation $Peer}catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: coordinator-allocation-replay'){throw}
        $blocked=$true
    }
    Assert-ImmuData ($blocked -and $Peer.allocationRequests -eq 1) 'coordinator-did-not-repeat-allocation'
    $Peer.allocationReplayRefused=$true
    return Finish-HistoricalRecoveryCoordinator $Peer 'allocation-refused'
}

function Close-HistoricalRecoveryCoordinator($Peer){
    if($null -eq $Peer){return}
    try{
        if($null -ne $Peer.holder){
            try{$Peer.holder.StandardInput.Close()}catch{}
            if(-not $Peer.holder.HasExited){$null=$Peer.holder.WaitForExit(3500)}
            $Peer.holder.Dispose()
        }
    }finally{$Peer.cancel.Dispose()}
}
function Remove-ExpiredHistoricalCoordinatorResources($Peer){
    while($Peer.lease.Elapsed.TotalSeconds -lt 5){
        $Peer.cancel.Token.ThrowIfCancellationRequested()
        Assert-ImmuData (-not $Peer.holder.HasExited) 'coordinator-lease-live'
        Start-Sleep -Milliseconds 50
    }
    Send-HistoricalCoordinatorFrame $Peer 'status'
    Receive-HistoricalCoordinatorFrame $Peer 'alive'
    Remove-OwnedHistoricalResources
    Assert-ImmuData $script:cleanup 'coordinator-expiry-cleanup'
    Read-HistoricalCoordinatorWork $Peer
    $Peer.expiredLiveCleanup=$true
    return Finish-HistoricalRecoveryCoordinator $Peer 'refused'
}
