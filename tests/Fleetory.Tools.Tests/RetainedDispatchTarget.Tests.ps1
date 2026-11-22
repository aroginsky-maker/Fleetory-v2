#requires -Version 7.3
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $repo 'eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $repo 'eng/pilot/historical/RetainedInFlightSql.ps1')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'eng/pilot/historical/RetainedPostgresTarget.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Source parse failed'}
$pgOwned='a'*64;$auditOwned='c'*64;$auditContext=$null;$auditStore=$null
function Confirm-RetainedLiveWork {}
function Read-RetainedPg {return $pgOwned}
function Read-RetainedAuditNamespace {return $auditOwned}
function Observe-RetainedNativeProcess {}
function Invoke-Docker {$script:dispatches++;return 'fake-native-result'}
$passed=0;$refused=0;$mutants=0
foreach($name in @('Invoke-RetainedPgNative','Invoke-RetainedAuditNative')){
    $matches=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    if($matches.Count -ne 1){throw 'Dispatcher definition not unique'}
    $owned=if($name -ceq 'Invoke-RetainedPgNative'){$pgOwned}else{$auditOwned}
    $foreign=if($name -ceq 'Invoke-RetainedPgNative'){$auditOwned}else{$pgOwned}
    $source=$matches[0].Extent.Text
    . ([scriptblock]::Create($source))
    foreach($argv in @(@('exec',$owned,'pg_isready','-q','-U','postgres'),@('exec','-i','-e','PGCLIENTENCODING=UTF8',$owned,'psql','-XqAt'))){
        $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
        $null=& $name $argv
        if($script:dispatches -ne 1 -or $meter.nativeDispatches -ne 1){throw 'Valid dispatch missing'}
        $passed++
    }
    foreach($argv in @(@('exec',$foreign,'psql','-v',$owned),@('exec','-i',$foreign,'psql',$owned))){
        $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
        try{$null=& $name $argv;throw 'Foreign target dispatched'}catch{
            if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: observed-client-owned-target'){throw}
        }
        if($script:dispatches -ne 0 -or $meter.nativeDispatches -ne 0){throw 'Refusal after dispatch'}
        $refused++
    }
    $expected=if($name -ceq 'Invoke-RetainedPgNative'){'identifier'}else{'auditId'}
    $line='Assert-RetainedObservedWorkArguments $Arguments -ExpectedIdentifier $'+$expected
    if(-not $source.Contains($line)){throw 'Guard wiring changed'}
    $mutant=$source.Replace($line,('Assert-ImmuData ($Arguments -ccontains $'+$expected+') ''old-membership'''))
    . ([scriptblock]::Create($mutant))
    $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
    $null=& $name @('exec',$foreign,'psql','-v',$owned)
    if($script:dispatches -ne 1){throw 'Old membership mutant not reproduced'}
    $mutants++
}
Write-Output 'RETAINED DISPATCH TARGET PASS:4 actual-dispatch positives,4 cross-role refusals before native work,2 old-membership mutants reproduced; Docker and custody reads stubbed; no live authority claim.'
