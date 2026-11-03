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
