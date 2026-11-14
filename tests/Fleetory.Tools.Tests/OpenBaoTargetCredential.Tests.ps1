#requires -Version 7.3
# Portable metadata contracts: no Docker, files containing secrets or provider calls.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert-True([bool]$Condition,[string]$Message) { if(-not $Condition){ throw $Message } }
function Assert-Owned { throw 'Portable credential contract must not call Docker.' }
. (Join-Path $PSScriptRoot 'OpenBaoTargetCredential.ps1')
$issued=[DateTimeOffset]::UtcNow.AddSeconds(-10)
$notBefore=$issued.AddSeconds(-1)
$lease=@{issue_time=$issued.ToString('O');expire_time=$issued.AddSeconds(300).ToString('O');
    creation_time=$issued.ToUnixTimeSeconds();orphan=$true;renewable=$false;explicit_max_ttl=300;
    creation_ttl=300;ttl=289;policies=@('fixture-recovered-signer')}
Assert-TargetCredentialLease $lease $notBefore
$shorter=$lease.Clone()
$shorter.expire_time=$issued.AddTicks(2999999953).ToString('O')
Assert-TargetCredentialLease $shorter $notBefore
$refused=0
foreach($change in @(
    @{expire_time=$issued.AddTicks(3000000001).ToString('O')},
    @{expire_time=$issued.ToString('O')},
    @{policies=@('fixture-recovered-signer','default')},
    @{renewable=$true},@{orphan=$false},@{explicit_max_ttl=301},@{creation_ttl=301}
)){
    $candidate=$lease.Clone()
    foreach($key in $change.Keys){$candidate[$key]=$change[$key]}
    try { Assert-TargetCredentialLease $candidate $notBefore }
    catch { $refused++; continue }
    throw 'Unsafe credential lease was accepted.'
}
$script:forceRestoreClaimed=$true
try { Assert-RecoveryCredentialTarget 'not-used' 'source' }
catch { if($_.Exception.Message -cne 'Credential recovery requires the already-restored fixture target.'){throw};$refused++ }
$script:forceRestoreClaimed=$false
try { Assert-RecoveryCredentialTarget 'not-used' 'restore' }
catch { if($_.Exception.Message -cne 'Credential recovery requires the already-restored fixture target.'){throw};$refused++ }
Assert-True ($refused -eq 9) 'Credential contract refusals did not all execute.'
Write-Host 'OPENBAO TARGET CREDENTIAL CONTRACT PASS: 2 valid leases / 9 refusals; one tick above 300 seconds denied; no Docker or original inputs.'

# Deterministic delayed-shutdown fixture: a replacement must not start merely
# because the old fixed 300ms sleep elapsed. Observe process absence first.
function Assert-Owned([string]$Id,[string]$Role) {
    Assert-True ($Id -ceq 'owned-fixture' -and $Role -ceq 'restore') 'Wrong restart target.'
}
function Get-Status { return @{cluster_id='fixture-cluster'} }
function Wait-Active { return @{cluster_id='fixture-cluster'} }
function Start-Bao {
    Assert-True $script:exitObserved 'Replacement started before old server exit.'
    $script:replacementStarts++
}
function Invoke-Unseal { $script:unsealCalls++ }
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=90,[switch]$AllowFailure) {
    Assert-True ($Arguments[0] -ceq 'exec' -and $Arguments[1] -ceq 'owned-fixture') 'Restart escaped its target.'
    if(($Arguments -join '|') -ceq 'exec|owned-fixture|/bin/busybox|killall|bao'){
        if($script:shutdownCase -ceq 'signal-failed'){throw 'Fixture stop signal refused.'}
        return @{ExitCode=0;Stdout='';Stderr=''}
    }
    Assert-True (($Arguments -join '|') -ceq 'exec|owned-fixture|/bin/busybox|pidof|bao' -and $AllowFailure) 'Unexpected restart probe.'
    $script:exitProbes++
    if($script:shutdownCase -ceq 'malformed'){return @{ExitCode=0;Stdout='not-a-pid';Stderr=''}}
    if($script:shutdownCase -ceq 'probe-error'){return @{ExitCode=1;Stdout='';Stderr='permission denied'}}
    if($script:shutdownCase -ceq 'empty-success'){return @{ExitCode=0;Stdout='';Stderr=''}}
    if($script:shutdownCase -ceq 'timeout' -or $script:exitProbes -le 4){return @{ExitCode=0;Stdout='42';Stderr=''}}
    $script:exitObserved=$true
    return @{ExitCode=1;Stdout='';Stderr=''}
}
function Reset-ShutdownFixture([string]$Case) {
    $script:shutdownCase=$Case;$script:exitProbes=0;$script:exitObserved=$false
    $script:replacementStarts=0;$script:unsealCalls=0;$script:forceRestoreClaimed=$true
}
Reset-ShutdownFixture 'delayed'
Restart-RecoveryCredentialTarget 'owned-fixture' 'fixture-cluster' 'fixture-placeholder'
Assert-True ($script:exitProbes -eq 5 -and $script:replacementStarts -eq 1 -and $script:unsealCalls -eq 1) 'Delayed shutdown was not observed before one replacement/unseal.'
$shutdownRefusals=0
foreach($case in @('malformed','probe-error','empty-success','signal-failed')){
    Reset-ShutdownFixture $case
    try{Restart-RecoveryCredentialTarget 'owned-fixture' 'fixture-cluster' 'fixture-placeholder'}
    catch{
        $expected=if($case -ceq 'signal-failed'){'Fixture stop signal refused.'}else{'OpenBao shutdown probe was invalid.'}
        Assert-True ($_.Exception.Message -ceq $expected) 'Unexpected shutdown refusal category.'
        $shutdownRefusals++;Assert-True ($script:replacementStarts -eq 0 -and $script:unsealCalls -eq 0) 'Failed shutdown crossed restart/unseal boundary.';continue
    }
    throw 'Unsafe shutdown result was accepted.'
}
Reset-ShutdownFixture 'timeout'
try{Wait-RecoveryBaoExit 'owned-fixture' -TimeoutMilliseconds 1}
catch{Assert-True ($_.Exception.Message -ceq 'OpenBao did not stop within its shutdown deadline.') 'Unexpected shutdown timeout category.';$shutdownRefusals++}
foreach($limit in @(0,30001)){
    try{Wait-RecoveryBaoExit 'owned-fixture' -TimeoutMilliseconds $limit}
    catch{Assert-True ($_.Exception.Message -ceq 'Invalid shutdown deadline.') 'Unexpected shutdown deadline category.';$shutdownRefusals++;continue}
    throw 'Invalid shutdown deadline accepted.'
}
Assert-True ($shutdownRefusals -eq 7) 'Shutdown refusal cases did not all execute.'
Write-Host 'OPENBAO SHUTDOWN CONTRACT PASS: delayed exit before replacement/unseal; 7 refusals; no Docker or original inputs.'
