#requires -Version 7.3
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $repo 'eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $repo 'eng/pilot/PgDataRoundtripPolicy.ps1')
. (Join-Path $repo 'eng/pilot/historical/RetainedConfiguration.ps1')
$configuration=@{Values=[Collections.ObjectModel.ReadOnlyDictionary[string,string]]::new([Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal))}
$restorePins=[Collections.ObjectModel.ReadOnlyDictionary[string,string]]::new([Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal))
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

$packets=@{'application-postgres'=[Text.Encoding]::ASCII.GetBytes('PGDMP'+('a'*59));'signer-postgres'=[Text.Encoding]::ASCII.GetBytes('PGDMP'+('b'*59));'audit-immudb'=[Text.Encoding]::ASCII.GetBytes('IMMUBACKUP'+('c'*54))}
$pinValues=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
foreach($kind in $packets.Keys){$pinValues.Add($kind,(Get-ImmuDataHash $packets[$kind]))}
$restorePins=[Collections.ObjectModel.ReadOnlyDictionary[string,string]]::new($pinValues)
$accepted=0;$rejected=0
$cases=@(@{kind='application-postgres';name='Invoke-RetainedPgNative';argv=@('exec','-i',$pgOwned,'pg_restore','--exit-on-error','--single-transaction','--no-password','--role=fleetory_migrator','--username=postgres','--dbname=fleetory')},
    @{kind='signer-postgres';name='Invoke-RetainedPgNative';argv=@('exec','-i',$pgOwned,'pg_restore','--exit-on-error','--single-transaction','--no-password','--role=fleetory_signer_owner','--username=postgres','--dbname=fleetory_signer')})
foreach($mode in @('verify','restore')){$cases+=@{kind='audit-immudb';name='Invoke-RetainedAuditNative';argv=(Get-ImmuDataCliArguments $auditOwned $mode)}}
foreach($case in $cases){
    $node=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $case.name},$true))
    if($node.Count -ne 1){throw 'Restore dispatcher not unique'}
    . ([scriptblock]::Create($node[0].Extent.Text))
    $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
    $null=& $case.name $case.argv $packets[$case.kind]
    if($script:dispatches -ne 1 -or $meter.nativeDispatches -ne 1){throw 'Pinned restore not dispatched'}
    $accepted++
    foreach($fault in @('changed','wrong-packet','missing','missing-pin')){
        $data=[byte[]]$packets[$case.kind].Clone();$saved=$restorePins
        if($fault -ceq 'changed'){$data[63]=$data[63] -bxor 1}
        elseif($fault -ceq 'wrong-packet'){if($case.kind -ceq 'application-postgres'){$data=$packets['signer-postgres']}elseif($case.kind -ceq 'signer-postgres'){$data=$packets['application-postgres']}else{$data[62]=$data[62] -bxor 2}}
        elseif($fault -ceq 'missing'){$data=$null}
        else{$restorePins=[Collections.ObjectModel.ReadOnlyDictionary[string,string]]::new([Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal))}
        $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
        try{$null=& $case.name $case.argv $data;throw 'Changed restore input dispatched'}catch{
            $expected=if($fault -ceq 'missing-pin'){'Audit data fixture refused: retained-restore-packet-pin'}else{
                $prefix=if($case.kind -ceq 'audit-immudb'){'Audit'}else{'PostgreSQL'}
                $prefix+' data fixture refused: '+$(if($fault -ceq 'missing'){'packet-bound'}else{'packet-pin-format'})
            }
            if($_.Exception.GetBaseException().Message -cne $expected){throw}
        }finally{$restorePins=$saved}
        if($script:dispatches -ne 0 -or $meter.nativeDispatches -ne 0){throw 'Restore refusal after dispatch'}
        $rejected++
    }
}
if($accepted -ne 4 -or $rejected -ne 16){throw 'Restore input regression count'}
Write-Output 'RETAINED RESTORE INPUT PASS:4 pinned-input calls and16 changed/wrong/missing input/pin refusals before native dispatch; synthetic headers only; no databases.'

$fakeTls=@{RootCertificatePem='generated-ca';ServerCertificatePem='generated-server-cert';ServerPrivateKeyPem='generated-server-key';ClientCertificatePem='generated-client-cert';ClientPrivateKeyPem='generated-client-key'}
$material=@{Tls=$fakeTls;PostgresTls=$fakeTls;GatewayTls=@{agent=$fakeTls;admin=$fakeTls};SigningPem='generated-state-key';Secrets=@{admin=('a'*64);reader=('b'*64);writer=('c'*64);database=('d'*64);signer=('e'*64)}}
$configuration=New-RetainedConfiguration $material $true $true
$configCases=@()
foreach($key in $configuration.Values.Keys){
    if($key.StartsWith('postgres:',[StringComparison]::Ordinal) -or $key.StartsWith('audit:',[StringComparison]::Ordinal)){
        $parts=$key.Split(':',2);$role=$parts[0];$target=if($role -ceq 'postgres'){$pgOwned}else{$auditOwned}
        $name=if($role -ceq 'postgres'){'Invoke-RetainedPgNative'}else{'Invoke-RetainedAuditNative'}
        $argv=@('exec','-i',$target,'/bin/sh','-c','set -eu; umask 077; test ! -L "$1"; cat > "$1"; stat -c %a:%u:%h "$1"; sha256sum "$1"','fixture',$parts[1])
        $configCases+=@{name=$name;argv=$argv;bytes=[Text.Encoding]::UTF8.GetBytes($configuration.Values[$key])}
    }
}
$configCases+=@{name='Invoke-RetainedAuditNative';argv=(Get-ImmuDataCliArguments $auditOwned 'login');bytes=[Text.Encoding]::UTF8.GetBytes($material.Secrets.admin)}
$configAccepted=0;$configRejected=0
foreach($case in $configCases){
    $node=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $case.name},$true))
    if($node.Count -ne 1){throw 'Configuration dispatcher not unique'}
    . ([scriptblock]::Create($node[0].Extent.Text))
    $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
    $null=& $case.name $case.argv $case.bytes
    if($script:dispatches -ne 1 -or $meter.nativeDispatches -ne 1){throw 'Bound configuration input not dispatched'}
    $configAccepted++
    foreach($fault in @('changed','missing','unknown-key','mutable-values')){
        $data=[byte[]]$case.bytes.Clone();$saved=$configuration
        if($fault -ceq 'changed'){$data[0]=$data[0] -bxor 1}
        elseif($fault -ceq 'missing'){$data=$null}
        elseif($fault -ceq 'unknown-key'){$configuration=@{Values=[Collections.ObjectModel.ReadOnlyDictionary[string,string]]::new([Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal))}}
        else{$configuration=@{Values=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)}}
        $script:dispatches=0;$meter=@{workInspections=0;nativeDispatches=0}
        try{$null=& $case.name $case.argv $data;throw 'Unbound configuration input dispatched'}catch{
            $expected='Audit data fixture refused: '+$(if($fault -cin @('unknown-key','mutable-values')){'retained-configuration-input-key'}else{'retained-configuration-input-bytes'})
            if($_.Exception.GetBaseException().Message -cne $expected){throw}
        }finally{$configuration=$saved}
        if($script:dispatches -ne 0 -or $meter.nativeDispatches -ne 0){throw 'Configuration input refusal after dispatch'}
        $configRejected++
    }
}
if($configAccepted -ne 23 -or $configRejected -ne 92){throw 'Configuration input count drift'}
Write-Output 'RETAINED CONFIGURATION INPUT PASS:22 file slots and1 generated login;92 byte/key/mutability refusals before native dispatch; no secrets read or services started.'
