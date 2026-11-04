#requires -Version 7.3
# Fresh Server DI components, PostgreSQL and immudb. No retained material or VPS.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($test in @('NativeJournalBoundary.Tests.ps1','NativeSignerBoundary.Tests.ps1','NativeAuditBoundary.Tests.ps1','NativeWorkerRuntime.Tests.ps1')){& (Join-Path $PSScriptRoot $test)}
$repoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
foreach($helper in @('PilotNativeProcess.ps1','../../eng/pilot/ProviderRecoveryTransport.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1',
    'PilotDisposableTls.ps1','NativeSignerFixture.ps1','NativeJournalFixture.ps1','NativeAuditFixture.ps1','NativeWorkerRuntime.ps1','NativeOutboxPipeline.ps1','NativeOutboxWorker.ps1','NativeServerHost.ps1')){. (Join-Path $PSScriptRoot $helper)}
$session=[Guid]::NewGuid().ToString('D');$dbId=$auditId=$worker=$null;$dbStarted=$auditStarted=$null;$dbImageId=$auditImageId=$null;$dbClaimed=$auditClaimed=$false
$publicRoot=Join-Path $repoRoot ('artifacts/native-server-'+$session);$proof=$null;$stage='publish'
$auditBuildClaimed=$false
$previousBuildKit=$env:DOCKER_BUILDKIT
$canaries=[Collections.Generic.List[string]]::new();$secrets=@{}
foreach($name in @('database','wrong','admin','writer','reader')){$secrets[$name]=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();$canaries.Add($secrets[$name])}
$material=$agent=$admin=$wrongMaterial=$null
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=90,[switch]$AllowFailure){
    $result=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments -ClassicBuilder:($Arguments[0] -ceq 'build'))) $InputBytes $TimeoutSeconds}
        else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    if(-not $AllowFailure -and $result.ExitCode -ne 0){
        if($Arguments[0] -ceq 'build'){
            # This input is a public COPY-only Dockerfile; no credentials or private context.
            $diagnostic=$result.Stderr
            foreach($value in $canaries){$diagnostic=$diagnostic.Replace($value,'[redacted]')}
            [Console]::Error.WriteLine('Public fixture build failed; exit='+$result.ExitCode+'; '+$diagnostic.Substring(0,[Math]::Min(6000,$diagnostic.Length)))
        }
        throw ('Generated Server Docker operation failed: '+$Arguments[0]+';exit='+$result.ExitCode)
    }
    return $result
}
function Read-Store([string]$Role,[switch]$CleanupOnly){
    $id=if($Role -ceq 'postgres'){$dbId}else{$auditId}
    $info=@((Invoke-Docker @('inspect',$id)).Stdout|ConvertFrom-Json -AsHashtable)
    Assert-True ($info.Count -eq 1) 'Store identity ambiguous.'
    if($Role -ceq 'postgres'){Assert-NativeJournal $info[0] $id $session $dbImageId $dbStarted -CleanupOnly:$CleanupOnly}
    else{Assert-NativeAudit $info[0] $id $session $auditImageId $dbId $auditStarted -CleanupOnly:$CleanupOnly}
}
function Write-StoreFile([string]$Role,[string]$Path,[string]$Value){
    $allowed=if($Role -ceq 'postgres'){@('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/hba.conf')}else{@('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/immudb.toml')}
    Assert-True ($Path -cin $allowed) 'Unknown store slot.';Read-Store $Role
    $id=if($Role -ceq 'postgres'){$dbId}else{$auditId}
    $null=Invoke-Docker @('exec','-i',$id,'/bin/sh','-c','umask 077; cat > "$1"','fixture',$Path) ([Text.Encoding]::UTF8.GetBytes($Value))
}
function Invoke-Database([string]$Database,[string]$Sql){
    Assert-True ($Database -cin @('postgres','fleetory')) 'Unknown fixture database.';Read-Store 'postgres'
    return Invoke-Docker @('exec','-i',$dbId,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',$Database) ([Text.Encoding]::UTF8.GetBytes($Sql))
}
function Write-ServerSlot([string]$Name,[string]$Value){Write-NativeWorkerFile $worker ('/run/fleetory-native/server/'+$Name) ([Text.Encoding]::UTF8.GetBytes($Value))}
function Write-ServerConnection([string]$Password,[string]$Mode='VerifyFull'){
    Assert-True ($Password -cmatch '^[a-f0-9]{64}$' -and $Mode -cin @('VerifyFull','Disable')) 'Connection packet invalid.'
    Write-ServerSlot 'fleetory-postgresql' ('Host=127.0.0.1;Port=5432;Database=fleetory;Username=fleetory_server;Password='+$Password+
        ';SSL Mode='+$Mode+';Root Certificate=/run/fleetory-native/server/infrastructure-ca;GSS Encryption Mode=Disable;Timeout=5;Command Timeout=5;Pooling=false')
}
function Invoke-ServerProbe([string]$Mode,[string]$Expected,[byte[]]$Packet=$null,[switch]$WrongTrust){
    Read-Store 'postgres';if($auditId){Read-Store 'audit'}
    $r=Invoke-NativeWorker $worker 'ServerBackendProbe' $Mode $Packet $canaries.ToArray() -WrongTrust:$WrongTrust
    $record=$r.Stdout|ConvertFrom-Json -AsHashtable
    if($r.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($r.Stderr) -or $record.category -cne $Expected){
        $category=if($record.category -cmatch '^[a-z-]{1,32}$'){$record.category}else{'invalid'}
        if($Mode -cne 'audit-health'){
            foreach($field in @('errorType','causeType','location')){if($record.ContainsKey($field) -and $record[$field] -cmatch '^[A-Za-z0-9_]{1,80}$'){[Console]::Error.WriteLine('Native Server '+$field+'='+$record[$field])}}
            if($record.ContainsKey('controlStatus') -and $record.controlStatus -is [long]){[Console]::Error.WriteLine('Native Server controlStatus='+$record.controlStatus)}
        }
        throw ('Server probe mismatch: '+$Mode+';category='+$category+';exit='+$r.ExitCode+';stderrLength='+$r.Stderr.Length)
    }
    if($Mode -cne 'schema'){Assert-True ($record.httpHostStarted -eq ($Mode -cin @('host-degraded','host-drain')) -and $record.issuerActivated -eq $false) 'Host or issuer scope drift.'}
    return $record
}
function Assert-DatabaseCount([int]$Expected){
    $sql='SELECT (SELECT count(*) FROM platform.audit_events)='+$Expected+' AND (SELECT count(*) FROM platform.audit_export_queue)='+$Expected+' AND (SELECT count(*) FROM platform.audit_events e JOIN platform.audit_export_queue q ON q.audit_event_id=e.event_id)='+$Expected+';'
    Assert-True ((Invoke-Database 'fleetory' $sql).Stdout.Trim() -ceq 't') 'Audit/outbox transaction count mismatch.'
}
function Remove-Store([string]$Role){
    $claimed=if($Role -ceq 'postgres'){$dbClaimed}else{$auditClaimed};if(-not $claimed){return}
    $id=if($Role -ceq 'postgres'){$dbId}else{$auditId}
    $name=if($Role -ceq 'postgres'){'fleetory-native-journal-'}else{'fleetory-native-audit-'}
    $lookup=if($id){$id}else{$name+$session.Replace('-','')}
    $i=Invoke-Docker @('inspect',$lookup) -AllowFailure
    if($i.ExitCode -eq 0){
        $found=@($i.Stdout|ConvertFrom-Json -AsHashtable);Assert-True ($found.Count -eq 1) 'Cleanup identity ambiguous.';$ownedId=[string]$found[0].Id
        if($Role -ceq 'postgres'){Assert-NativeJournal $found[0] $ownedId $session $dbImageId $dbStarted -CleanupOnly}
        else{Assert-NativeAudit $found[0] $ownedId $session $auditImageId $dbId $auditStarted -CleanupOnly}
        $null=Invoke-Docker @('rm','-f','-v',$ownedId);$i=Invoke-Docker @('inspect',$ownedId) -AllowFailure
    }
    Assert-True ($i.ExitCode -ne 0 -and ($i.Stderr+$i.Stdout) -match '(?i)no such (object|container)') 'Store absence unverified.'
}
try{
    # Keep the existing closed CLI-config wrapper empty; buildx writes state there.
    # This code-only multi-stage build requires no BuildKit-only instruction.
    $env:DOCKER_BUILDKIT='0'
    $null=New-Item -ItemType Directory -Path $publicRoot
    $published=Publish-NativeProbe $repoRoot 'ServerBackendProbe' $publicRoot
    $stage='images';$images=@{}
    foreach($image in @($script:nativeJournalImage,$script:nativeAuditSourceImage,$script:nativeSignerImage)){
        $i=Invoke-Docker @('image','inspect',$image) -AllowFailure
        if($i.ExitCode -ne 0){$null=Invoke-Docker @('pull',$image) -TimeoutSeconds 120}
        $images[$image]=@((Invoke-Docker @('image','inspect',$image)).Stdout|ConvertFrom-Json -AsHashtable)[0]
    }
    $dbImageId=[string]$images[$script:nativeJournalImage].Id
    $stage='audit-image';$auditImageName=Get-NativeAuditImageName $session
    $absent=Invoke-Docker @('image','inspect',$auditImageName) -AllowFailure
    Assert-True ($absent.ExitCode -ne 0 -and ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|image)') 'Audit image name not fresh.'
    $auditBuildClaimed=$true
    $null=Invoke-Docker @('build','--network','none','--pull=false','--tag',$auditImageName,'-') ([Text.Encoding]::UTF8.GetBytes((Get-NativeAuditBuildDefinition $session))) -TimeoutSeconds 120
    $built=@((Invoke-Docker @('image','inspect',$auditImageName)).Stdout|ConvertFrom-Json -AsHashtable)
    Assert-True ($built.Count -eq 1 -and $built[0].Config.Labels['fleetory.native-audit.build'] -ceq $session) 'Audit image identity drift.'
    $auditImageId=[string]$built[0].Id
    foreach($prefix in @('fleetory-native-journal-','fleetory-native-audit-')){
        $absent=Invoke-Docker @('inspect',($prefix+$session.Replace('-',''))) -AllowFailure
        Assert-True ($absent.ExitCode -ne 0 -and ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|container)') 'Store name not fresh.'
    }
    $stage='postgres';$dbStarted=[DateTimeOffset]::UtcNow;$dbClaimed=$true
    $dbId=(Invoke-Docker (Get-NativeJournalArguments $session)).Stdout.Trim();Read-Store 'postgres'
    $material=New-PilotDisposableTlsMaterial;$agent=New-PilotDisposableTlsMaterial;$admin=New-PilotDisposableTlsMaterial;$wrongMaterial=New-PilotDisposableTlsMaterial
    foreach($tls in @($material,$agent,$admin)){
        foreach($line in ($tls.ServerPrivateKeyPem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$canaries.Add($line.Substring(0,40))}}
    }
    Write-StoreFile 'postgres' '/tmp/ca.pem' $material.RootCertificatePem
    Write-StoreFile 'postgres' '/tmp/server.crt' $material.ServerCertificatePem
    Write-StoreFile 'postgres' '/tmp/server.key' $material.ServerPrivateKeyPem
    Write-StoreFile 'postgres' '/tmp/hba.conf' "local all postgres peer`nlocal all all reject`nhostssl fleetory fleetory_server 127.0.0.1/32 scram-sha-256`nhost all all 0.0.0.0/0 reject`nhost all all ::/0 reject`n"
    $null=Invoke-Docker @('exec',$dbId,'initdb','-D','/var/lib/postgresql/18/recovery','--auth-local=peer','--auth-host=reject','--no-instructions')
    $null=Invoke-Docker @('exec','-d',$dbId,'postgres','-D','/var/lib/postgresql/18/recovery','-c','listen_addresses=127.0.0.1',
        '-c','unix_socket_directories=/var/run/postgresql','-c','hba_file=/tmp/hba.conf','-c','password_encryption=scram-sha-256',
        '-c','ssl=on','-c','ssl_cert_file=/tmp/server.crt','-c','ssl_key_file=/tmp/server.key','-c','ssl_min_protocol_version=TLSv1.2',
        '-c','shared_buffers=32MB','-c','max_connections=20','-c','log_statement=none','-c','log_min_error_statement=panic')
    $ready=$false
    for($n=0;$n -lt 60;$n++){$r=Invoke-Docker @('exec',$dbId,'pg_isready','-q','-U','postgres') -AllowFailure;if($r.ExitCode -eq 0){$ready=$true;break};Start-Sleep -Milliseconds 250}
    Assert-True $ready 'Fresh PostgreSQL not ready.'
    $null=Invoke-Database 'postgres' ("CREATE ROLE fleetory_owner NOLOGIN; CREATE ROLE fleetory_server LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '"+$secrets.database+"'; CREATE DATABASE fleetory OWNER fleetory_owner; REVOKE ALL ON DATABASE fleetory FROM PUBLIC; GRANT CONNECT ON DATABASE fleetory TO fleetory_server;")
    Assert-True ((Invoke-Database 'postgres' "SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE rolname='fleetory_server';").Stdout.Trim() -ceq 't') 'Generated password not SCRAM.'
    $stage='worker';$worker=New-NativeWorkerContext $session $dbId $published $images[$script:nativeSignerImage];Start-NativeWorkerContext $worker
    $null=Invoke-Docker @('exec',$worker.Id,'/bin/mkdir','-m','700','/run/fleetory-native/server','/tmp/empty-ca-dir')
    Write-NativeWorkerFile $worker '/tmp/ca.pem' ([Text.Encoding]::UTF8.GetBytes($material.RootCertificatePem))
    Write-NativeWorkerFile $worker '/tmp/wrong-ca.pem' ([Text.Encoding]::UTF8.GetBytes($wrongMaterial.RootCertificatePem))
    foreach($role in @('agent','admin')){
        $tls=if($role -ceq 'agent'){$agent}else{$admin}
        Write-ServerSlot ($role+'-gateway-root-ca') $tls.RootCertificatePem
        Write-ServerSlot ($role+'-gateway-server-cert') $tls.ServerCertificatePem
        Write-ServerSlot ($role+'-gateway-server-key') $tls.ServerPrivateKeyPem
    }
    Write-ServerSlot 'infrastructure-ca' $material.RootCertificatePem;Write-ServerSlot 'audit-immudb-password' $secrets.writer;Write-ServerConnection $secrets.database
    $stage='schema';$schema=Invoke-ServerProbe 'schema' 'schema'
    Assert-True ($schema.sql.Length -gt 0 -and $schema.sql.Length -le 131072) 'Native schema unbounded.'
    $null=Invoke-Database 'fleetory' ('SET ROLE fleetory_owner;'+"`n"+$schema.sql+"`nRESET ROLE; GRANT USAGE ON SCHEMA core,platform TO fleetory_server; GRANT SELECT ON ALL TABLES IN SCHEMA core,platform TO fleetory_server; GRANT INSERT ON platform.audit_events,platform.audit_export_queue TO fleetory_server;")
    $stage='database-cases';$null=Invoke-ServerProbe 'db-ready' 'db-ready';Assert-DatabaseCount 0
    $null=Invoke-Database 'fleetory' 'REVOKE INSERT ON platform.audit_export_queue FROM fleetory_server;'
    try{$null=Invoke-ServerProbe 'db-atomic' 'db-privilege';Assert-DatabaseCount 0}finally{$null=Invoke-Database 'fleetory' 'GRANT INSERT ON platform.audit_export_queue TO fleetory_server;'}
    $null=Invoke-ServerProbe 'db-rollback' 'db-rollback';Assert-DatabaseCount 0
    $null=Invoke-ServerProbe 'db-write' 'db-write';Assert-DatabaseCount 1
    foreach($mode in @('db-update','db-delete','db-schema','db-temp','db-owner')){$null=Invoke-ServerProbe $mode 'db-privilege'}
    Write-ServerConnection $secrets.wrong;try{$null=Invoke-ServerProbe 'db-password' 'db-authentication'}finally{Write-ServerConnection $secrets.database}
    Write-ServerSlot 'infrastructure-ca' $wrongMaterial.RootCertificatePem
    try{$null=Invoke-ServerProbe 'db-tls' 'db-tls'}finally{Write-ServerSlot 'infrastructure-ca' $material.RootCertificatePem}
    Write-ServerConnection $secrets.database 'Disable';try{$null=Invoke-ServerProbe 'db-plaintext' 'db-plaintext'}finally{Write-ServerConnection $secrets.database}
    $null=Invoke-ServerProbe 'db-ready' 'db-ready';Assert-DatabaseCount 1
    $stage='immudb';Read-Store 'postgres';$auditStarted=[DateTimeOffset]::UtcNow;$auditClaimed=$true
    $stage='immudb-create';$auditId=(Invoke-Docker (Get-NativeAuditArguments $session $dbId)).Stdout.Trim();Read-Store 'audit'
    Write-StoreFile 'audit' '/tmp/server.crt' $material.ServerCertificatePem;Write-StoreFile 'audit' '/tmp/server.key' $material.ServerPrivateKeyPem
    Write-StoreFile 'audit' '/tmp/ca.pem' $material.RootCertificatePem
    Write-StoreFile 'audit' '/tmp/immudb.toml' ('admin-password = "'+$secrets.admin+'"'+"`n")
    $null=Invoke-Docker @('exec',$auditId,'/bin/mkdir','-m','700','/tmp/empty-ca-dir')
    $stage='immudb-start';$null=Invoke-Docker @('exec','-d','-e','SSL_CERT_FILE=/tmp/ca.pem','-e','SSL_CERT_DIR=/tmp/empty-ca-dir',
        $auditId,'/usr/sbin/immudb','--config=/tmp/immudb.toml','--dir=/data','--address=127.0.0.1','--port=3322',
        '--auth=true','--devmode=false','--web-server=true','--web-server-port=8090','--pgsql-server=false','--metrics-server=false',
        '--certificate=/tmp/server.crt','--pkey=/tmp/server.key','--clientcas=/tmp/ca.pem','--pidfile=/tmp/immudb.pid','--logdir=/tmp','--logfile=fixture.log','--max-active-databases=3')
    $packet=[Text.Encoding]::UTF8.GetBytes((@{admin=$secrets.admin;writer=$secrets.writer;reader=$secrets.reader}|ConvertTo-Json -Compress))
    $ready=$false
    for($n=0;$n -lt 20;$n++){
        try{$null=Invoke-ServerProbe 'audit-health' 'audit-health';$ready=$true;break}catch{Start-Sleep -Milliseconds 250}
    }
    Assert-True $ready 'Fresh TLS immudb not healthy.'
    $stage='audit-cases';$null=Invoke-ServerProbe 'audit-prepare' 'audit-prepare' $packet
    $null=Invoke-ServerProbe 'audit-publish' 'audit-publish';$null=Invoke-ServerProbe 'audit-repeat' 'audit-repeat'
    $null=Invoke-ServerProbe 'audit-conflict' 'audit-conflict'
    Write-ServerSlot 'audit-immudb-password' $secrets.wrong;try{$null=Invoke-ServerProbe 'audit-password' 'audit-authentication'}finally{Write-ServerSlot 'audit-immudb-password' $secrets.writer}
    Write-ServerSlot 'audit-immudb-password' $secrets.reader;try{$null=Invoke-ServerProbe 'audit-readonly' 'audit-privilege'}finally{Write-ServerSlot 'audit-immudb-password' $secrets.writer}
    $null=Invoke-ServerProbe 'audit-database' 'audit-database';$null=Invoke-ServerProbe 'audit-tls' 'audit-tls' -WrongTrust
    $null=Invoke-ServerProbe 'audit-verify' 'audit-verify' $packet;Assert-DatabaseCount 1
    $stage='outbox-pipeline';$pipeline=Invoke-NativeOutboxPipeline
    $stage='outbox-worker';$workerLifecycle=Invoke-NativeOutboxWorker
    $stage='server-host';$hostLifecycle=Invoke-NativeServerHost
    $proof=[ordered]@{schema='fleetory.native-server-backend.v1';verified=$true;nativeDbContexts=2;nativeHealthChecksAccepted=2;
        auditOutboxCommitVerified=$true;explicitRollbackVerified=$true;partialWriteRollbackVerified=$true;databaseRefusals=9;
        auditPublicationsAccepted=2;singleRevisionVerified=$true;auditKeyCount=5;directSinkAuditKeyCount=1;auditFieldsVerified=10;auditRefusals=5;pipeline=$pipeline;workerLifecycle=$workerLifecycle;hostLifecycle=$hostLifecycle;originalMaterialUsed=$false;
        sourceVpsAccessed=$false;httpHostStarted=$true;issuerActivated=$false;publishedPorts=0;workerOnlyLoopback=$true;
        postgresBoundaryRefusals=16;workerBoundaryRefusals=23;auditBoundaryRefusals=17;sharedWorkerRefusals=9;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
catch{
    if($_.Exception.Message -cmatch '^Server probe mismatch: ([a-z-]+;category=[a-z-]+;exit=[0-9]+;stderrLength=[0-9]+)$'){[Console]::Error.WriteLine('Server diagnostic: '+$Matches[1])}
    [Console]::Error.WriteLine('Generated Server fixture failed at '+$stage+'; type='+$_.Exception.GetType().Name+'; line='+$_.InvocationInfo.ScriptLineNumber+'. No raw SQL, response or credential emitted.')
    throw 'Generated Server fixture did not pass.'
}
finally{
    $env:DOCKER_BUILDKIT=$previousBuildKit
    $failures=[Collections.Generic.List[string]]::new()
    try{Remove-NativeWorker $worker}catch{$failures.Add('worker')}
    foreach($role in @('audit','postgres')){try{Remove-Store $role}catch{$failures.Add($role)}}
    try{
        if($auditBuildClaimed){
            $image=Invoke-Docker @('image','inspect',(Get-NativeAuditImageName $session)) -AllowFailure
            if($image.ExitCode -eq 0){
                $found=@($image.Stdout|ConvertFrom-Json -AsHashtable)
                Assert-True ($found.Count -eq 1 -and $found[0].Config.Labels['fleetory.native-audit.build'] -ceq $session -and
                    ($null -eq $auditImageId -or $found[0].Id -ceq $auditImageId)) 'Audit image cleanup identity drift.'
                $null=Invoke-Docker @('image','rm',(Get-NativeAuditImageName $session));$image=Invoke-Docker @('image','inspect',(Get-NativeAuditImageName $session)) -AllowFailure
            }
            Assert-True ($image.ExitCode -ne 0 -and ($image.Stderr+$image.Stdout) -match '(?i)no such (object|image)') 'Audit image absence unverified.'
        }
    }catch{$failures.Add('audit-image')}
    try{Remove-NativePublicPayload $repoRoot $publicRoot}catch{$failures.Add('public-payload')}
    $secrets.Clear();$canaries.Clear();$material=$agent=$admin=$wrongMaterial=$packet=$null
    if($failures.Count -ne 0){throw ('Native Server cleanup unverified: '+($failures -join ','))}
}
if($proof){$proof.cleanupVerified=$true;$proof|ConvertTo-Json -Compress}
