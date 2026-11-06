#requires -Version 7.3
function Assert-AuditObservationProbe($Result,$Body,[string]$Mode,[string]$ExpectedType=''){
    Assert-ImmuData ($Mode -cin @('observation-read','observation-history-read','observation-history-seed','observation-seed','observation-zset','observation-kv','observation-rewrite','observation-many','observation-reader-denial')) 'observation-mode'
    Assert-ImmuData ([string]::IsNullOrWhiteSpace($Result.Stderr)) 'observation-stderr'
    if($ExpectedType -ceq 'authentication'){
        Assert-ImmuData ($Mode -cin @('observation-read','observation-history-read') -and $Result.ExitCode -eq 1 -and $Body.category -ceq 'unexpected' -and $Body.errorType -ceq 'InvalidOperationException' -and $Body.authenticationDenied -eq $true -and $Body.controlStatus -eq 500) 'observation-authentication'
    }elseif($ExpectedType){
        Assert-ImmuData ($Mode -cin @('observation-read','observation-history-read') -and $ExpectedType -cin @('AuditObservationBindingException','AuditObservationPointException','AuditObservationBoundException','AuditObservationUnsupportedException') -and $Result.ExitCode -eq 1 -and $Body.category -ceq 'unexpected' -and $Body.errorType -ceq $ExpectedType) 'observation-typed-data-refusal'
    }else{Assert-ImmuData ($Result.ExitCode -eq 0 -and $Body.category -ceq $Mode) 'observation-probe'}
}
