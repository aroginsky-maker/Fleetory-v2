#requires -Version 7.3
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Require($Condition,[string]$Category){if(-not $Condition){throw $Category}}
. (Join-Path $PSScriptRoot '../../eng/pilot/ImmuDataRoundtripPolicy.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/historical/RetainedInFlightSql.ps1')
Assert-RetainedObservedWorkArguments @('exec',('a'*64),'pg_isready','-q','-U','postgres')
$purposeRefusals=0
foreach($arguments in @($null,([string[]]@()),@('EXEC','target','command'),@('create','target','image'),@('run','target','image'),@('build','target','image'),@('exec'),@('exec','target'))){
    try{Assert-RetainedObservedWorkArguments $arguments}catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: observed-client-exec-only'){throw}
        $purposeRefusals++;continue
    }
    throw 'Observed creation/build or incomplete exec purpose accepted.'
}
Require ($purposeRefusals-eq8) 'observed-exec-purpose-only-no-resource-authority'
$commandRefusals=0
foreach($arguments in @(@('exec',('a'*64),'/bin/true'),@('exec',('a'*64),'/bin/sh','-c','unlisted'),
    @('exec',('a'*64),'dotnet','/tmp/other.dll'),@('exec','--privileged',('a'*64),'psql'),
    @('exec','target','psql'),@('exec','-e','broken',('a'*64),'psql'))){
    try{Assert-RetainedObservedWorkArguments $arguments;throw 'Unlisted native command shape accepted.'}catch{
        if($_.Exception.Message -notmatch '^Audit data fixture refused: observed-client-'){throw}
        $commandRefusals++
    }
}
Require ($commandRefusals -eq 6) 'observed-command-boundary-refusals'
. (Join-Path $PSScriptRoot '../../eng/pilot/historical/RetainedCoupledAudit.ps1')
$id='a'*64
Assert-RetainedObservedWorkArguments (Get-RetainedAuditStartArguments $id)
foreach($mode in @('login','backup','verify','restore')){Assert-RetainedObservedWorkArguments (Get-ImmuDataCliArguments $id $mode)}
Assert-RetainedObservedWorkArguments @('exec','-i','-e','PGCLIENTENCODING=UTF8',$id,'psql','-XqAt','-U','postgres','-d','postgres')
Assert-RetainedObservedWorkArguments @('exec','-i','-e','PGAPPNAME=fleetory-generated-lock-123',$id,'pg_restore','--data-only','--exit-on-error','--single-transaction','--no-password','--role=fleetory_migrator','--username=postgres','--dbname=fleetory')
Assert-RetainedObservedWorkArguments @('exec','-i',$id,'/bin/sh','-c','set -eu; umask 077; test ! -L "$1"; cat > "$1"; stat -c %a:%u:%h "$1"; sha256sum "$1"','fixture','/tmp/server.crt')
$environmentRefusals=0
foreach($entry in @('LD_PRELOAD=/tmp/library','PATH=/tmp','HOME=/root','SSL_CERT_FILE=/tmp/foreign','SSL_CERT_DIR=/etc/ssl','PGCLIENTENCODING=LATIN1','PGAPPNAME=contains space')){
    try{Assert-RetainedObservedWorkArguments @('exec','-e',$entry,$id,'psql');throw 'Unknown environment accepted.'}catch{
        if($_.Exception.Message -cne 'Audit data fixture refused: observed-client-environment-purpose'){throw}
        $environmentRefusals++
    }
}
try{Assert-RetainedObservedWorkArguments @('exec','-e','HOME=/tmp','-e','HOME=/tmp',$id,'psql');throw 'Duplicate environment accepted.'}catch{
    if($_.Exception.Message -cne 'Audit data fixture refused: observed-client-environment-duplicate'){throw}
    $environmentRefusals++
}
Require ($environmentRefusals -eq 8) 'observed-environment-purpose-refusals'


Write-Output 'OBSERVED COMMAND PURPOSE PASS:8 real-builder positives,6 command refusals,8 environment refusals; no Docker invocation.'

# The expected ID comes from the live owner, never from the argument packet.
Assert-RetainedObservedWorkArguments @('exec',$id,'pg_isready','-q','-U','postgres') -ExpectedIdentifier $id
Assert-RetainedObservedWorkArguments @('exec','-i','-e','PGCLIENTENCODING=UTF8',$id,'psql','-XqAt') -ExpectedIdentifier $id
$foreign='b'*64;$ownedTargetRefusals=0
foreach($arguments in @(@('exec',$foreign,'psql','-XqAt','-v',$id),@('exec','-i',$foreign,'psql',$id),
    @('exec','-e',('PGAPPNAME='+$id),$foreign,'psql'),@('exec',$foreign,'dotnet','/tool/ServerBackendProbe.dll',$id))){
    Require ($arguments -ccontains $id -or $arguments -ccontains ('PGAPPNAME='+$id)) 'owned-id-reproduction'
    try{Assert-RetainedObservedWorkArguments $arguments -ExpectedIdentifier $id;throw 'Foreign target with owned ID elsewhere accepted.'}catch{
        if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: observed-client-owned-target'){throw}
        $ownedTargetRefusals++
    }
}
Require ($ownedTargetRefusals -eq 4) 'observed-owned-target-refusals'
Write-Output 'OBSERVED OWNED TARGET PASS:2 exact-target positives and 4 misplaced-owned-ID refusals; no Docker invocation.'

$utilityPositives=0
foreach($tail in @(@('sha256sum','/tool/ServerBackendProbe.dll'),@('/bin/cat','/tmp/immudb.pid'),
    @('/bin/mkdir','-m','700','/tmp/empty-ca-dir'),@('/bin/mkdir','-m','700','/run/fleetory-native/server'),
    @('/bin/kill','-TERM','123'),@('/bin/kill','-0','123'))){
    Assert-RetainedObservedWorkArguments (@('exec',$id)+$tail);$utilityPositives++
}
$writeScript='set -eu; umask 077; test ! -L "$1"; cat > "$1"; stat -c %a:%u:%h "$1"; sha256sum "$1"'
$paths=@('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/client.crt','/tmp/client.key','/tmp/state.key','/tmp/immudb.toml','/tmp/cli.toml','/tmp/hba.conf',
    '/run/fleetory-native/server/infrastructure-ca','/run/fleetory-native/server/audit-immudb-password','/run/fleetory-native/server/fleetory-postgresql','/run/fleetory-native/server/fleetory-signer-postgresql')
foreach($role in @('agent','admin')){foreach($slot in @('root-ca','server-cert','server-key')){$paths+=('/run/fleetory-native/server/'+$role+'-gateway-'+$slot)}}
foreach($path in $paths){Assert-RetainedObservedWorkArguments @('exec','-i',$id,'/bin/sh','-c',$writeScript,'fixture',$path);$utilityPositives++}
$utilityRefusals=0
$invalid=@(@('sha256sum','/tmp/server.key'),@('sha256sum','/tool/ServerBackendProbe.dll','/etc/passwd'),
    @('/bin/cat','/tmp/server.key'),@('/bin/cat','/tmp/immudb.pid','/etc/passwd'),
    @('/bin/mkdir','-m','777','/tmp/empty-ca-dir'),@('/bin/mkdir','-p','/tmp/other'),
    @('/bin/kill','-KILL','123'),@('/bin/kill','-TERM','-1'),@('/bin/kill','-TERM','0'),@('/bin/kill','-TERM','123','124'))
foreach($path in @('/etc/passwd','/tmp/../etc/passwd','/run/fleetory-native/server/foreign','/tmp/server.key/child',"/tmp/server.key`n")){
    $invalid+=,@('/bin/sh','-c',$writeScript,'fixture',$path)
}
foreach($tail in $invalid){
    try{Assert-RetainedObservedWorkArguments (@('exec',$id)+$tail);throw 'Unlisted recovery utility arguments accepted.'}catch{
        if($_.Exception.GetBaseException().Message -notmatch '^Audit data fixture refused: observed-client-'){throw}
        $utilityRefusals++
    }
}
Require ($utilityPositives -eq 25 -and $utilityRefusals -eq 15) 'observed-utility-catalog'
Write-Output 'OBSERVED UTILITY CATALOG PASS:25 fixed-purpose positives and 15 path/option/signal refusals; no Docker invocation.'

$postgresCatalog=@(@('initdb','-D','/var/lib/postgresql/18/recovery','--auth-local=peer','--auth-host=reject','--no-instructions'),
    @('pg_isready','-q','-U','postgres'),@('pg_ctl','-D','/var/lib/postgresql/18/recovery','stop','-m','fast','-w','-t','5'))
foreach($pair in @(@('fleetory','fleetory_migrator'),@('fleetory_signer','fleetory_signer_owner'))){
    $postgresCatalog+=,@('pg_restore','--exit-on-error','--single-transaction','--no-password',('--role='+$pair[1]),'--username=postgres',('--dbname='+$pair[0]))
}
foreach($mode in @('--section=pre-data','--data-only')){
    $postgresCatalog+=,@('pg_restore',$mode,'--exit-on-error','--single-transaction','--no-password','--role=fleetory_migrator','--username=postgres','--dbname=fleetory')
}
$launch=@('postgres','-D','/var/lib/postgresql/18/recovery','-c','listen_addresses=','-c','unix_socket_directories=/var/run/postgresql',
    '-c','shared_buffers=32MB','-c','max_connections=20','-c','password_encryption=scram-sha-256','-c','log_statement=none','-c','log_min_error_statement=panic')
$postgresCatalog+=,$launch
$tlsLaunch=[string[]]$launch.Clone();$tlsLaunch[4]='listen_addresses=127.0.0.1'
$postgresCatalog+=,@($tlsLaunch+@('-c','hba_file=/tmp/hba.conf','-c','ssl=on','-c','ssl_cert_file=/tmp/server.crt',
    '-c','ssl_key_file=/tmp/server.key','-c','ssl_min_protocol_version=TLSv1.2'))
$postgresRefusals=0
foreach($tail in $postgresCatalog){
    Assert-RetainedObservedWorkArguments (@('exec',$id)+$tail)
    $bad=@();$bad+=,@($tail+'--unlisted');$bad+=,@($tail[0..($tail.Count-2)])
    for($position=1;$position -lt $tail.Count;$position++){
        $changed=[string[]]$tail.Clone();$changed[$position]='unlisted';$bad+=,$changed
    }
    foreach($changed in $bad){
        try{Assert-RetainedObservedWorkArguments (@('exec',$id)+$changed);throw 'Unlisted PostgreSQL argv accepted.'}catch{
            if($_.Exception.GetBaseException().Message -cne 'Audit data fixture refused: observed-client-postgres-purpose'){throw}
            $postgresRefusals++
        }
    }
}
Require ($postgresCatalog.Count -eq 9 -and $postgresRefusals -eq 102) 'observed-postgres-catalog'
Write-Output 'OBSERVED POSTGRES CATALOG PASS:9 exact profiles and 102 option/path/role/database/TLS mutations refused; no Docker invocation.'
