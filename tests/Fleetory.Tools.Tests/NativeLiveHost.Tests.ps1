#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'NativeLiveHost.ps1')
$taskId='a'*64
foreach($operation in @('setup','start','commit','ready','exit','result','error')){
    $arguments=Get-NativeLiveControlArguments $taskId $operation
    if($arguments[0] -cne 'exec' -or @($arguments|Where-Object {$_ -ceq $taskId}).Count -ne 1){throw 'Live control argument contract drift.'}
}
function New-LiveResult([int]$Code,[byte[]]$Bytes,[string]$ErrorText=''){
    return @{ExitCode=$Code;StdoutBytes=$Bytes;Stderr=$ErrorText}
}
foreach($operation in @('ready','exit')){
    if($null -ne (Read-NativeLiveControlValue $operation (New-LiveResult 10 ([byte[]]@())))){throw 'Absent marker falsely accepted.'}
}
if((Read-NativeLiveControlValue 'ready' (New-LiveResult 0 ('admitted'|ForEach-Object {[Text.Encoding]::UTF8.GetBytes($_)}))) -cne 'admitted' -or
   (Read-NativeLiveControlValue 'exit' (New-LiveResult 0 ([byte[]]@(48)))) -cne '0'){throw 'Valid live markers rejected.'}
$taskRefusals=0
$taskCases=@(
    {Get-NativeLiveControlArguments ('a'*63) 'start'},
    {Get-NativeLiveControlArguments ('a'*63+';') 'commit'},
    {Get-NativeLiveControlArguments ('A'*64) 'start'},
    {Get-NativeLiveControlArguments $taskId '../result'},
    {Get-NativeLiveControlArguments $taskId 'START'},
    {Read-NativeLiveControlValue 'result' (New-LiveResult 10 ([byte[]]@()))},
    {Read-NativeLiveControlValue 'error' (New-LiveResult 10 ([byte[]]@()))},
    {Read-NativeLiveControlValue 'ready' (New-LiveResult 11 ([byte[]]@()))},
    {Read-NativeLiveControlValue 'ready' (New-LiveResult 10 ([byte[]]@(1)))},
    {Read-NativeLiveControlValue 'ready' (New-LiveResult 0 ([byte[]]@(1)))},
    {Read-NativeLiveControlValue 'ready' (New-LiveResult 0 ([byte[]]::new(9)))},
    {Read-NativeLiveControlValue 'result' (New-LiveResult 0 ([byte[]]::new(8193)))},
    {Read-NativeLiveControlValue 'error' (New-LiveResult 0 ([byte[]]::new(1025)))},
    {Read-NativeLiveControlValue 'result' (New-LiveResult 0 ([byte[]]@(255)))},
    {Read-NativeLiveControlValue 'exit' (New-LiveResult 0 ([Text.Encoding]::UTF8.GetBytes('256')))},
    {Read-NativeLiveControlValue 'exit' (New-LiveResult 0 ([Text.Encoding]::UTF8.GetBytes('-1')))},
    {Read-NativeLiveControlValue 'exit' (New-LiveResult 0 ([Text.Encoding]::UTF8.GetBytes('00')))},
    {Read-NativeLiveControlValue 'exit' (New-LiveResult 0 ([Text.Encoding]::UTF8.GetBytes('0 ')))},
    {Read-NativeLiveControlValue 'exit' (New-LiveResult 0 ([byte[]]@(48)) 'unexpected')},
    {Read-NativeLiveControlValue 'unknown' (New-LiveResult 0 ([byte[]]@()))}
)
foreach($case in $taskCases){
    try{$null=& $case}catch{$taskRefusals++;continue}
    throw 'Unsafe live control input accepted.'
}
Write-Output ('NATIVE LIVE CONTROL PASS: 7 fixed operations; 2 absent markers; 2 valid markers; '+$taskRefusals+' refusals; no Docker or original inputs.')
