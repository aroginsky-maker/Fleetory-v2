#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/AuditObservationPolicy.ps1')
$count=0
foreach($wanted in @('AuditObservationBindingException','AuditObservationPointException','AuditObservationBoundException','AuditObservationUnsupportedException')){
    Assert-AuditObservationProbe @{ExitCode=1;Stderr=''} @{category='unexpected';errorType=$wanted} 'observation-read' $wanted
    foreach($bad in @('InvalidOperationException','HttpRequestException','TaskCanceledException','JsonException','SocketException')){
        $seen=$false;try{Assert-AuditObservationProbe @{ExitCode=1;Stderr=''} @{category='unexpected';errorType=$bad} 'observation-read' $wanted}catch{$seen=$true}
        Assert-ImmuData $seen 'observation-untyped-error';$count++
    }
    foreach($result in @(@{ExitCode=0;Stderr=''},@{ExitCode=1;Stderr='diagnostic'},@{ExitCode=2;Stderr=''})){
        $seen=$false;try{Assert-AuditObservationProbe $result @{category='unexpected';errorType=$wanted} 'observation-read' $wanted}catch{$seen=$true}
        Assert-ImmuData $seen 'observation-process-error';$count++
    }
}
Assert-ImmuData ($count -eq 32) 'observation-refusal-count'
Assert-AuditObservationProbe @{ExitCode=0;Stderr=''} @{category='observation-read'} 'observation-read'
$auth=@{category='unexpected';errorType='InvalidOperationException';authenticationDenied=$true;controlStatus=500}
Assert-AuditObservationProbe @{ExitCode=1;Stderr=''} $auth 'observation-read' 'authentication'
foreach($name in @('category','errorType','authenticationDenied','controlStatus')){
    $bad=$auth.Clone();$bad[$name]=if($name -ceq 'authenticationDenied'){$false}elseif($name -ceq 'controlStatus'){503}else{'wrong'}
    $seen=$false;try{Assert-AuditObservationProbe @{ExitCode=1;Stderr=''} $bad 'observation-read' 'authentication'}catch{$seen=$true}
    Assert-ImmuData $seen 'observation-authentication-not-data'
}
Write-Output 'AUDIT OBSERVATION POLICY PASS:32 unrelated data refusals and4 authentication mutations rejected.'
