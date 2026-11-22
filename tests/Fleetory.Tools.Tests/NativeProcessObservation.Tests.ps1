#requires -Version 7.3
param([Parameter(Mandatory)][string]$Python)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'PilotNativeProcess.ps1')
# Synchronous observers keep the active caller scope; an isolated closure module loses its local assertions in CI.
function Require([bool]$Value,[string]$Name){if(-not$Value){throw ('Native observation test refused: '+$Name)}}
$normal=@{calls=0;pid=0;final=$false}
$observe={param([Diagnostics.Process]$Process)
    $normal.calls++
    if($normal.pid-eq0){$normal.pid=$Process.Id}else{Require ($normal.pid-eq$Process.Id) 'same-started-process'}
    if($Process.HasExited){$normal.final=$true}
    'observer-output-must-be-discarded'
}
$reply=Invoke-NativeBytes $Python @('-I','-S','-c',"import time; print('normal',flush=True); time.sleep(1.2)") -TimeoutSeconds 5 -ObserveProcess $observe
Require ($reply.ExitCode-eq0-and$reply.Stdout.Trim()-ceq'normal'-and$reply.StderrBytes.Length-eq0-and$normal.calls-ge2-and$normal.final) 'normal-and-final-admission'
$state=@{calls=0;process=$null;birth=$null;refused=$false}
$watch=[Diagnostics.Stopwatch]::StartNew()
$cancel={param([Diagnostics.Process]$Process)
    $state.calls++
    Require (-not$Process.HasExited) 'fault-during-live-operation'
    if($null-eq$state.process){
        $state.process=[Diagnostics.Process]::GetProcessById($Process.Id)
        $null=$state.process.Handle
        $state.birth=$Process.StartTime.ToUniversalTime().Ticks
        Require ($state.process.StartTime.ToUniversalTime().Ticks-eq$state.birth) 'held-observer-birth'
    }
    if($state.calls-ge2){throw [OperationCanceledException]::new('Generated observation refused.')}
}
try{
    $null=Invoke-NativeBytes $Python @('-I','-S','-c','import time; time.sleep(30)') -TimeoutSeconds 5 -ObserveProcess $cancel
}catch{
    if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw}
    $state.refused=$true
}
try{
    Require ($state.refused-and$state.calls-eq2-and$watch.Elapsed.TotalSeconds-lt5-and$null-ne$state.process) 'bounded-inflight-refusal'
    Require $state.process.HasExited 'exact-own-client-exited'
}finally{if($null-ne$state.process){$state.process.Dispose()}}
$late=@{finalRefused=$false}
$final={param([Diagnostics.Process]$Process)
    if($Process.HasExited){$late.finalRefused=$true;throw [OperationCanceledException]::new('Generated final admission refused.')}
}
$refused=$false
try{$null=Invoke-NativeBytes $Python @('-I','-S','-c',"print('unaccepted')") -TimeoutSeconds 5 -ObserveProcess $final}catch{
    if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw}
    $refused=$true
}
Require ($refused-and$late.finalRefused) 'final-native-result-not-admitted'
$plain=Invoke-NativeBytes $Python @('-I','-S','-c',"print('default')") -TimeoutSeconds 5
Require ($plain.ExitCode-eq0-and$plain.Stdout.Trim()-ceq'default'-and$plain.StderrBytes.Length-eq0) 'default-call-unchanged'
$start=[Diagnostics.ProcessStartInfo]::new($Python)
$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true
foreach($part in @('-I','-S','-c',"import time; print('control-ready',flush=True); time.sleep(30)")){$start.ArgumentList.Add($part)}
$control=$null
try{
    $control=[Diagnostics.Process]::Start($start)
    $null=$control.Handle
    $birth=$control.StartTime.ToUniversalTime().Ticks
    $ready=$control.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(5)).GetAwaiter().GetResult()
    Require ($ready-ceq'control-ready'-and-not$control.HasExited) 'unrelated-control-ready'
    $refused=$false
    try{
        $null=Invoke-NativeBytes $Python @('-I','-S','-c','import time; time.sleep(30)') -TimeoutSeconds 5 -ObserveProcess {
            param([Diagnostics.Process]$Process)
            if(-not$Process.HasExited){throw [OperationCanceledException]::new('Generated own target refusal.')}
        }
    }catch{
        if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw}
        $refused=$true
    }
    Require ($refused-and-not$control.HasExited-and$control.StartTime.ToUniversalTime().Ticks-eq$birth) 'unrelated-process-preserved'
}finally{
    if($null-ne$control){
        if(-not$control.HasExited){$control.Kill($true);Require ($control.WaitForExit(2000)) 'control-cleanup'}
        $control.Dispose()
    }
}
$budget=@{observed=$false;cancelled=$false;process=$null}
$watch=[Diagnostics.Stopwatch]::StartNew()
try{
    $null=Invoke-NativeBytes $Python @('-I','-S','-c','import time; time.sleep(30)') -TimeoutSeconds 2 -ObserveProcess {
        param([Diagnostics.Process]$Process,[Threading.CancellationToken]$Token)
        Require (-not$Process.HasExited-and$Token.CanBeCanceled) 'observation-live-and-budgeted'
        $budget.observed=$true
        $budget.process=[Diagnostics.Process]::GetProcessById($Process.Id)
        $null=$budget.process.Handle
        $null=$Token.WaitHandle.WaitOne()
        $Token.ThrowIfCancellationRequested()
    }
}catch{
    if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw}
    $budget.cancelled=$true
}
try{
    Require ($budget.observed-and$budget.cancelled-and$watch.Elapsed.TotalSeconds-lt5-and$budget.process.HasExited) 'observation-uses-original-native-deadline'
}finally{if($null-ne$budget.process){$budget.process.Dispose()}}
$ignored=@{observed=$false;refused=$false}
$watch=[Diagnostics.Stopwatch]::StartNew()
try{
    $null=Invoke-NativeBytes $Python @('-I','-S','-c','import time; time.sleep(30)') -TimeoutSeconds 2 -ObserveProcess {
        param([Diagnostics.Process]$Process,[Threading.CancellationToken]$Token)
        Require (-not$Process.HasExited) 'ignored-token-live-native'
        $ignored.observed=$true
        $null=$Token.WaitHandle.WaitOne()
        'expired-observer-must-not-authorize-result'
    }
}catch{
    if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw}
    $ignored.refused=$true
}
Require ($ignored.observed-and$ignored.refused-and$watch.Elapsed.TotalSeconds-lt5) 'expired-observer-return-refused'
. (Join-Path $PSScriptRoot 'ObservedCommandShape.Tests.ps1')
Write-Output 'NATIVE PROCESS OBSERVATION PASS:7 native cases and 8 exec-purpose refusals; own client cancelled; unrelated process preserved; final/expired result refused; no Docker/data/secret access.'

& (Join-Path $PSScriptRoot 'NativeProfileForwarding.Tests.ps1') -Python $Python
