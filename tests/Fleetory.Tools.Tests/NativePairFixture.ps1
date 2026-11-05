#requires -Version 7.3
# Shared closed pair resources. Caller supplies bounded Invoke-Docker and owns the ledger.
function Assert-Pair([bool]$Condition,[string]$Category){if(-not $Condition){throw ('Native pair refused: '+$Category)}}
function Pair-Ledger($State){
    $rows=@($State.Sides|ForEach-Object {@{Session=$_.Session;Role=$_.Role;Id=$_.Id;Name=$_.Name;Started=$_.Started}})
    $audits=@($State.Audits|ForEach-Object {@{Session=$_.Session;Id=$_.Id;Name=$_.Name;Image=$_.Image;Started=$_.Started;DatabaseId=$_.Side.Id}})
    [IO.File]::WriteAllText((Join-Path $State.Root 'owned-resources.json'),(@{fixture=$State.Fixture;image=$State.Image;imageId=$State.ImageId;postgresImageId=$State.PgImageId;sides=$rows;audits=$audits}|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
}
function Read-PairStore($State,$Store,[string]$Kind,[switch]$Cleanup){
    $r=@((Invoke-Docker @('inspect',$Store.Id)).Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-Pair ($r.Count -eq 1) 'store-inspect'
    if($Kind -ceq 'postgres'){Assert-NativeJournal $r[0] $Store.Id $Store.Session $State.PgImageId $Store.Started -CleanupOnly:$Cleanup}
    else{
        Assert-Pair ($Kind -ceq 'audit') 'store-kind'
        Assert-NativeAudit $r[0] $Store.Id $Store.Session $State.ImageId $Store.Side.Id $Store.Started -CleanupOnly:$Cleanup
    }
}
function Write-PairFile($State,$Store,[string]$Kind,[string]$Path,[string]$Value){
    $allowed=@('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/hba.conf')
    if($Kind -ceq 'audit'){
        $allowed=@('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/client.crt','/tmp/client.key','/tmp/state.key','/tmp/immudb.toml','/tmp/cli.toml')+
            @('fleetory-postgresql','infrastructure-ca','audit-immudb-password','agent-gateway-root-ca','agent-gateway-server-cert','agent-gateway-server-key','admin-gateway-root-ca','admin-gateway-server-cert','admin-gateway-server-key'|ForEach-Object {'/tmp/server/'+$_})
    }
    Assert-Pair ($Path -cin $allowed -and $Value.Length -gt 0 -and $Value.Length -le 16384) 'file-slot'
    Read-PairStore $State $Store $Kind
    $null=Invoke-Docker @('exec','-i',$Store.Id,'/bin/sh','-c','umask 077; cat > "$1"','fixture',$Path) ([Text.Encoding]::UTF8.GetBytes($Value))
    $uid=if($Kind -ceq 'postgres'){'999'}else{'3322'}
    Assert-Pair ((Invoke-Docker @('exec',$Store.Id,'stat','-c','%a:%u:%h',$Path)).Stdout.Trim() -ceq ('600:'+$uid+':1')) 'file-permissions'
}
function Pair-Sql($State,$Side,[string]$Database,[string]$Text,[switch]$AllowFailure){
    Assert-Pair ($Database -cin @('postgres','fleetory')) 'sql-database'
    Read-PairStore $State $Side 'postgres'
    return Invoke-Docker @('exec','-i',$Side.Id,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',$Database) ([Text.Encoding]::UTF8.GetBytes($Text)) -AllowFailure:$AllowFailure
}
function Start-PairPostgres($State,$Side){
    Read-PairStore $State $Side 'postgres'
    $null=Invoke-Docker @('exec','-d',$Side.Id,'postgres','-D','/var/lib/postgresql/18/recovery','-c','listen_addresses=127.0.0.1',
        '-c','unix_socket_directories=/var/run/postgresql','-c','hba_file=/tmp/hba.conf','-c','password_encryption=scram-sha-256',
        '-c','ssl=on','-c','ssl_cert_file=/tmp/server.crt','-c','ssl_key_file=/tmp/server.key','-c','ssl_min_protocol_version=TLSv1.2',
        '-c','shared_buffers=32MB','-c','max_connections=20','-c','log_statement=none','-c','log_min_error_statement=panic')
    $ready=$false
    for($n=0;$n -lt 40;$n++){$r=Invoke-Docker @('exec',$Side.Id,'pg_isready','-q','-U','postgres') -AllowFailure;if($r.ExitCode -eq 0){$ready=$true;break};Start-Sleep -Milliseconds 200}
    Assert-Pair $ready 'postgres-ready'
}
function New-PairDatabase($State,$Side){
    $null=Pair-Sql $State $Side 'postgres' 'CREATE DATABASE fleetory OWNER fleetory_migrator;REVOKE ALL ON DATABASE fleetory FROM PUBLIC;GRANT CONNECT ON DATABASE fleetory TO fleetory_server;'
}
function New-PairSide($State,[string]$Role){
    Assert-Pair ($Role -cin @('source','target')) 'side-role'
    $session=[Guid]::NewGuid().ToString('D');$name='fleetory-native-journal-'+$session.Replace('-','')
    $absent=Invoke-Docker @('inspect',$name) -AllowFailure
    Assert-Pair ($absent.ExitCode -ne 0 -and ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|container)') 'fresh-postgres'
    $side=@{Id=$null;Session=$session;Name=$name;Role=$Role;Started=[DateTimeOffset]::UtcNow;Audit=$null;Secrets=@{}}
    foreach($slot in @('admin','writer','reader','database')){$side.Secrets[$slot]=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();$State.Canaries.Add($side.Secrets[$slot])}
    $State.Sides.Add($side);Pair-Ledger $State
    $side.Id=(Invoke-Docker (Get-NativeJournalArguments $session)).Stdout.Trim();Pair-Ledger $State
    Read-PairStore $State $side 'postgres'
    $null=Invoke-Docker @('exec',$side.Id,'initdb','-D','/var/lib/postgresql/18/recovery','--auth-local=peer','--auth-host=reject','--no-instructions')
    foreach($entry in @(@('/tmp/ca.pem',$State.Tls.RootCertificatePem),@('/tmp/server.crt',$State.Tls.ServerCertificatePem),@('/tmp/server.key',$State.Tls.ServerPrivateKeyPem),
        @('/tmp/hba.conf',"local all postgres peer`nlocal all all reject`nhostssl fleetory fleetory_server 127.0.0.1/32 scram-sha-256`nhost all all 0.0.0.0/0 reject`nhost all all ::/0 reject`n"))){Write-PairFile $State $side 'postgres' $entry[0] $entry[1]}
    Start-PairPostgres $State $side
    $null=Pair-Sql $State $side 'postgres' ("SET password_encryption='scram-sha-256';CREATE ROLE fleetory_migrator NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;CREATE ROLE fleetory_server LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '"+$side.Secrets.database+"';")
    New-PairDatabase $State $side
    return $side
}
function Invoke-PairProbe($State,$Side,[string]$Mode,[switch]$Refusal){
    Read-PairStore $State $Side 'postgres';Read-PairStore $State $Side.Audit 'audit'
    $body=@{fixture=$State.Fixture};foreach($key in $Side.Secrets.Keys){$body[$key]=$Side.Secrets[$key]}
    $r=Invoke-Docker @('exec','-i','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',$Side.Audit.Id,'dotnet','/tool/ServerBackendProbe.dll',$Mode) ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Compress))) -AllowFailure
    $value=$r.Stdout|ConvertFrom-Json -AsHashtable -Depth 16
    if($Refusal){
        Assert-Pair ($r.ExitCode -eq 1 -and [string]::IsNullOrWhiteSpace($r.Stderr) -and $value.category -ceq 'unexpected' -and $value.errorType -ceq 'FreshPairPreflightException') 'preflight-refusal'
    }else{
        if($r.ExitCode -ne 0 -and $Mode -cne 'audit-health'){
            foreach($field in @('errorType','causeType','location')){if($value.ContainsKey($field) -and $value[$field] -cmatch '^[A-Za-z0-9_]{1,80}\z'){[Console]::Error.WriteLine('Pair probe '+$Mode+': '+$field+'='+$value[$field])}}
        }
        Assert-Pair ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.Stderr) -and $value.category -ceq $Mode) 'native-probe'
    }
    return $value
}
function Start-PairAudit($State,$Side){
    $a=$Side.Audit;Read-PairStore $State $a 'audit'
    $null=Invoke-Docker @('exec','-d','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',$a.Id,'/usr/sbin/immudb','--config=/tmp/immudb.toml','--dir=/data','--address=127.0.0.1','--port=3322',
        '--auth=true','--devmode=false','--web-server=true','--web-server-port=8090','--pgsql-server=false','--metrics-server=false','--certificate=/tmp/server.crt','--pkey=/tmp/server.key',
        '--clientcas=/tmp/ca.pem','--signingKey=/tmp/state.key','--pidfile=/tmp/immudb.pid','--logdir=/tmp','--logfile=fixture.log','--max-active-databases=3')
    $ready=$false
    for($n=0;$n -lt 20;$n++){try{$null=Invoke-PairProbe $State $Side 'audit-health';$ready=$true;break}catch{Start-Sleep -Milliseconds 200}}
    Assert-Pair $ready 'audit-ready'
}
function New-PairAudit($State,$Side){
    $session=[Guid]::NewGuid().ToString('D');$alias=Get-NativeAuditImageName $session;$name='fleetory-native-audit-'+$session.Replace('-','')
    foreach($kind in @('container','image')){
        $r=if($kind -ceq 'image'){Invoke-Docker @('image','inspect',$alias) -AllowFailure}else{Invoke-Docker @('inspect',$name) -AllowFailure}
        Assert-Pair ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container|image)') 'fresh-audit'
    }
    $a=@{Id=$null;Name=$name;Image=$alias;Session=$session;Side=$Side;Started=[DateTimeOffset]::UtcNow}
    $State.Audits.Add($a);$Side.Audit=$a;Pair-Ledger $State
    $null=Invoke-Docker @('tag',$State.Image,$alias)
    $a.Id=(Invoke-Docker (Get-NativeAuditArguments $session $Side.Id)).Stdout.Trim();Pair-Ledger $State
    Read-PairStore $State $a 'audit'
    $null=Invoke-Docker @('exec',$a.Id,'/bin/mkdir','-m','700','/tmp/empty-ca-dir','/tmp/server')
    Assert-Pair ((Invoke-Docker @('exec',$a.Id,'sha256sum','/tool/ServerBackendProbe.dll')).Stdout.Split(' ')[0] -ceq $State.ProbeHash) 'probe-build-identity'
    foreach($entry in @(@('/tmp/ca.pem',$State.Tls.RootCertificatePem),@('/tmp/server.crt',$State.Tls.ServerCertificatePem),@('/tmp/server.key',$State.Tls.ServerPrivateKeyPem),
        @('/tmp/client.crt',$State.Tls.ClientCertificatePem),@('/tmp/client.key',$State.Tls.ClientPrivateKeyPem),@('/tmp/state.key',$State.SigningPem),
        @('/tmp/immudb.toml',('admin-password = "'+$Side.Secrets.admin+'"'+"`n")),@('/tmp/cli.toml',"# Fixed fresh-only CLI profile`n"))){Write-PairFile $State $a 'audit' $entry[0] $entry[1]}
    Start-PairAudit $State $Side
    $null=Invoke-Docker (Get-ImmuDataCliArguments $a.Id 'login') ([Text.Encoding]::UTF8.GetBytes($Side.Secrets.admin))
}
function Write-PairHostFiles($State,$Side){
    $a=$Side.Audit
    $slots=@{'infrastructure-ca'=$State.Tls.RootCertificatePem;'audit-immudb-password'=$Side.Secrets.writer;
        'fleetory-postgresql'=('Host=127.0.0.1;Port=5432;Database=fleetory;Username=fleetory_server;Password='+$Side.Secrets.database+';SSL Mode=VerifyFull;Root Certificate=/tmp/server/infrastructure-ca;GSS Encryption Mode=Disable;Timeout=5;Command Timeout=5;Pooling=false')}
    foreach($role in @('agent','admin')){
        $material=$State.GatewayTls[$role]
        $slots[$role+'-gateway-root-ca']=$material.RootCertificatePem;$slots[$role+'-gateway-server-cert']=$material.ServerCertificatePem;$slots[$role+'-gateway-server-key']=$material.ServerPrivateKeyPem
    }
    foreach($slot in $slots.Keys){Write-PairFile $State $a 'audit' ('/tmp/server/'+$slot) $slots[$slot]}
}
function Remove-PairAudit($State,$Store){
    $lookup=if($Store.Id){$Store.Id}else{$Store.Name}
    $r=Invoke-Docker @('inspect',$lookup) -AllowFailure
    if($r.ExitCode -eq 0){if(-not $Store.Id){$Store.Id=@($r.Stdout|ConvertFrom-Json -AsHashtable)[0].Id};Read-PairStore $State $Store 'audit' -Cleanup;$null=Invoke-Docker @('rm','-f','-v',$Store.Id);$r=Invoke-Docker @('inspect',$Store.Id) -AllowFailure}
    Assert-Pair ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|container)') 'audit-cleanup'
    $r=Invoke-Docker @('image','inspect',$Store.Image) -AllowFailure
    if($r.ExitCode -eq 0){$i=@($r.Stdout|ConvertFrom-Json -AsHashtable);Assert-Pair ($i.Count -eq 1 -and $i[0].Id -ceq $State.ImageId -and $i[0].Config.Labels['fleetory.native-pair.build'] -ceq $State.Fixture) 'alias-cleanup-owner';$null=Invoke-Docker @('image','rm',$Store.Image);$r=Invoke-Docker @('image','inspect',$Store.Image) -AllowFailure}
    Assert-Pair ($r.ExitCode -ne 0 -and ($r.Stderr+$r.Stdout) -match '(?i)no such (object|image)') 'alias-cleanup'
}
