#requires -Version 7.3
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/AuditHistoryPolicy.ps1')
$refusals=0
foreach($wanted in @('AuditHistoryKeySetException','AuditHistoryRevisionException','AuditHistoryTransactionException')){
    Assert-AuditHistoryProbe @{ExitCode=1;Stderr=''} @{category='unexpected';errorType=$wanted} 'history-read' $wanted
    foreach($bad in @('InvalidOperationException','HttpRequestException','TaskCanceledException','JsonException','SocketException')){
        $seen=$false;try{Assert-AuditHistoryProbe @{ExitCode=1;Stderr=''} @{category='unexpected';errorType=$bad} 'history-read' $wanted}catch{$seen=$true}
        Assert-ImmuData $seen 'untyped-refusal-accepted';$refusals++
    }
    foreach($result in @(@{ExitCode=0;Stderr=''},@{ExitCode=1;Stderr='diagnostic'},@{ExitCode=2;Stderr=''})){
        $seen=$false;try{Assert-AuditHistoryProbe $result @{category='unexpected';errorType=$wanted} 'history-read' $wanted}catch{$seen=$true}
        Assert-ImmuData $seen 'wrong-process-refusal-accepted';$refusals++
    }
}
Assert-AuditHistoryProbe @{ExitCode=0;Stderr=''} @{category='history-read'} 'history-read'
Assert-ImmuData ($refusals -eq 24) 'history-refusal-count'
Write-Output 'AUDIT HISTORY POLICY PASS:24 process/configuration/transport refusals cannot count as data refusal.'
foreach($expected in @('immudb state public key does not match the pinned key.','The immudb state signature is invalid.',"Unexpected immudb database 'defaultdb'.")){
    Assert-AuditHistoryCryptoReason $expected $expected
    foreach($unrelated in @('File missing.','Access denied.','Malformed public key.','')){
        $seen=$false;try{Assert-AuditHistoryCryptoReason $unrelated $expected}catch{$seen=$true}
        if(-not $seen){throw 'Unrelated crypto failure accepted.'}
    }
}
Write-Output 'AUDIT HISTORY CRYPTO POLICY PASS:12 unrelated error refusals.'
