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
    $role=if($name -ceq 'Invoke-RetainedPgNative'){'postgres'}else{'audit'}
    $validCalls=if($role -ceq 'postgres'){@(@('exec',$owned,'pg_isready','-q','-U','postgres'),@('exec','-i','-e','PGCLIENTENCODING=UTF8',$owned,'psql','-XqAt','-U','postgres','-d','postgres'))}
        else{@(@('exec',$owned,'sha256sum','/tool/ServerBackendProbe.dll'),@('exec',$owned,'/bin/cat','/tmp/immudb.pid'))}
    foreach($argv in $validCalls){
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
    $crossCalls=if($role -ceq 'postgres'){@(@('exec',$owned,'/bin/cat','/tmp/immudb.pid'),@('exec',$owned,'sha256sum','/tool/ServerBackendProbe.dll'))}
        else{@(@('exec',$owned,'pg_isready','-q','-U','postgres'),@('exec','-i',$owned,'psql','-XqAt','-U','postgres','-d','postgres'))}
    foreach($argv in $crossCalls){
        $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
        try{$null=& $name $argv;throw 'Role-inappropriate program dispatched'}catch{
            if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: observed-client-role-program'){throw}
        }
        if($script:dispatches -ne 0 -or $meter.nativeDispatches -ne 0){throw 'Role refusal after dispatch'}
    }
    $foreignSlot=if($role -ceq 'postgres'){'/tmp/client.key'}else{'/tmp/hba.conf'}
    $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
    try{
        $null=& $name @('exec','-i',$owned,'/bin/sh','-c','set -eu; umask 077; test ! -L "$1"; cat > "$1"; stat -c %a:%u:%h "$1"; sha256sum "$1"','fixture',$foreignSlot)
        throw 'Role-inappropriate configuration slot dispatched'
    }catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: observed-client-role-configuration-path'){throw}
    }
    if($script:dispatches -ne 0 -or $meter.nativeDispatches -ne 0){throw 'Configuration role refusal after dispatch'}
    $expected=if($name -ceq 'Invoke-RetainedPgNative'){'identifier'}else{'auditId'}
    $line='Assert-RetainedObservedWorkArguments $Arguments -ExpectedIdentifier $'+$expected+' -ExpectedRole '+$role
    if(-not $source.Contains($line)){throw 'Guard wiring changed'}
    $mutant=$source.Replace($line,('Assert-ImmuData ($Arguments -ccontains $'+$expected+') ''old-membership'''))
    . ([scriptblock]::Create($mutant))
    $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
    $null=& $name @('exec',$foreign,'psql','-v',$owned)
    if($script:dispatches -ne 1){throw 'Old membership mutant not reproduced'}
    $mutants++
}
Write-Output 'RETAINED ROLE DISPATCH PASS:4 cross-role program and2 configuration-slot refusals before native work; no native resources.'
Write-Output 'RETAINED DISPATCH TARGET PASS:4 actual-dispatch positives,4 cross-role refusals before native work,2 old-membership mutants reproduced; Docker and custody reads stubbed; no live authority claim.'

$launchNodes=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Start-RetainedPgBackend'},$true))
if($launchNodes.Count -ne 1){throw 'Backend launcher not unique'}
. ([scriptblock]::Create($launchNodes[0].Extent.Text))
function Invoke-RetainedPgNative([string[]]$Arguments,[byte[]]$InputBytes=$null,[switch]$AllowFailure){
    Assert-RetainedObservedWorkArguments $Arguments -ExpectedIdentifier $pgOwned -ExpectedRole postgres
    $script:launchCalls++;return @{ExitCode=0}
}
$identifier=$pgOwned
foreach($server in @($false,$true)){
    $listen='listen_addresses=';$tlsArguments=@()
    if($server){
        $listen='listen_addresses=127.0.0.1'
        $tlsArguments=@('-c','hba_file=/tmp/hba.conf','-c','ssl=on','-c','ssl_cert_file=/tmp/server.crt','-c','ssl_key_file=/tmp/server.key','-c','ssl_min_protocol_version=TLSv1.2')
    }
    $script:launchCalls=0;$meter=@{bootstrapped=$false}
    Start-RetainedPgBackend
    if($script:launchCalls -ne 2 -or -not $meter.bootstrapped){throw 'Actual backend builder not admitted'}
}
Write-Output 'RETAINED BACKEND BUILDER PASS:2 actual launch/readiness profiles admitted; native dispatch stubbed; no PostgreSQL started.'
