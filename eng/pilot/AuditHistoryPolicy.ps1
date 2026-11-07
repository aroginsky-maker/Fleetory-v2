#requires -Version 7.3
function Assert-AuditHistoryProbe($Result,$Body,[string]$Mode,[string]$ExpectedType=''){
    Assert-ImmuData ($Mode -cin @('audit-health','history-seed','history-seed-reversed','history-users','history-read','history-reader','history-extra','history-rewrite','history-wrong-password')) 'history-mode'
    Assert-ImmuData ([string]::IsNullOrWhiteSpace($Result.Stderr)) 'history-stderr'
    if($ExpectedType){
        Assert-ImmuData ($Mode -ceq 'history-read' -and $ExpectedType -cin @('AuditHistoryKeySetException','AuditHistoryRevisionException','AuditHistoryTransactionException') -and
            $Result.ExitCode -eq 1 -and $Body.category -ceq 'unexpected' -and $Body.errorType -ceq $ExpectedType) 'history-typed-data-refusal'
    }else{Assert-ImmuData ($Result.ExitCode -eq 0 -and $Body.category -ceq $Mode) 'history-probe'}
}
function Assert-AuditHistoryCryptoReason([string]$Actual,[string]$Expected){
    Assert-ImmuData ($Expected -cin @('immudb state public key does not match the pinned key.','The immudb state signature is invalid.',"Unexpected immudb database 'defaultdb'.") -and $Actual -ceq $Expected) 'history-crypto-reason'
}
