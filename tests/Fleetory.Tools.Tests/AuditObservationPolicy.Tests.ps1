#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/AuditObservationPolicy.ps1')
$count=0
foreach($mode in @('observation-read','observation-history-read')){
foreach($wanted in @('AuditObservationBindingException','AuditObservationPointException','AuditObservationBoundException','AuditObservationUnsupportedException')){
    Assert-AuditObservationProbe @{ExitCode=1;Stderr=''} @{category='unexpected';errorType=$wanted} $mode $wanted
    foreach($bad in @('InvalidOperationException','HttpRequestException','TaskCanceledException','JsonException','SocketException')){
        $seen=$false;try{Assert-AuditObservationProbe @{ExitCode=1;Stderr=''} @{category='unexpected';errorType=$bad} $mode $wanted}catch{$seen=$true}
        Assert-ImmuData $seen 'observation-untyped-error';$count++
    }
    foreach($result in @(@{ExitCode=0;Stderr=''},@{ExitCode=1;Stderr='diagnostic'},@{ExitCode=2;Stderr=''})){
        $seen=$false;try{Assert-AuditObservationProbe $result @{category='unexpected';errorType=$wanted} $mode $wanted}catch{$seen=$true}
        Assert-ImmuData $seen 'observation-process-error';$count++
    }
}
Assert-AuditObservationProbe @{ExitCode=0;Stderr=''} @{category=$mode} $mode
$auth=@{category='unexpected';errorType='InvalidOperationException';authenticationDenied=$true;controlStatus=500}
Assert-AuditObservationProbe @{ExitCode=1;Stderr=''} $auth $mode 'authentication'
foreach($name in @('category','errorType','authenticationDenied','controlStatus')){
    $bad=$auth.Clone();$bad[$name]=if($name -ceq 'authenticationDenied'){$false}elseif($name -ceq 'controlStatus'){503}else{'wrong'}
    $seen=$false;try{Assert-AuditObservationProbe @{ExitCode=1;Stderr=''} $bad $mode 'authentication'}catch{$seen=$true}
    Assert-ImmuData $seen 'observation-authentication-not-data'
}
}
Assert-ImmuData ($count -eq 64) 'observation-refusal-count'
Write-Output 'AUDIT OBSERVATION POLICY PASS:64 unrelated data refusals and8 authentication mutations rejected across strict/historical modes.'
