#requires -Version 7.3
# Fresh local PostgreSQL and native Signer readiness. No retained DB, PKI or credentials.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
& (Join-Path $PSScriptRoot 'NativeJournalBoundary.Tests.ps1')
& (Join-Path $PSScriptRoot 'NativeSignerBoundary.Tests.ps1')
& (Join-Path $PSScriptRoot 'NativeWorkerRuntime.Tests.ps1')
$repoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $PSScriptRoot 'PilotNativeProcess.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/ProviderRecoveryTransport.ps1')
. (Join-Path $PSScriptRoot '../../eng/pilot/ProviderRecoveryPolicy.ps1')
. (Join-Path $PSScriptRoot 'PilotDisposableTls.ps1')
. (Join-Path $PSScriptRoot 'NativeSignerFixture.ps1')
. (Join-Path $PSScriptRoot 'NativeJournalFixture.ps1')
. (Join-Path $PSScriptRoot 'NativeWorkerRuntime.ps1')
$session=[Guid]::NewGuid().ToString('D');$dbId=$null;$dbStarted=$null;$dbImageId=$null;$dbClaimed=$false;$worker=$null
$publicRoot=Join-Path $repoRoot ('artifacts/native-journal-'+$session)
$material=$wrongMaterial=$null;$proof=$null;$stage='publish'
$password=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$wrongPassword=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
$canaries=[Collections.Generic.List[string]]::new();$canaries.Add($password);$canaries.Add($wrongPassword)
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Invoke-Docker([string[]]$Arguments,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=90,[switch]$AllowFailure){
    $result=if($IsLinux){Invoke-NativeBytes '/bin/sh' @('-c',(Get-ProviderDockerShellCommand $Arguments)) $InputBytes $TimeoutSeconds}
        else{Invoke-NativeBytes 'docker' (@('--context','desktop-linux')+$Arguments) $InputBytes $TimeoutSeconds}
    if(-not $AllowFailure -and $result.ExitCode -ne 0){throw 'Generated journal Docker operation failed.'}
    return $result
}
function Read-Journal{
    $info=@((Invoke-Docker @('inspect',$dbId)).Stdout|ConvertFrom-Json -AsHashtable)
    Assert-True ($info.Count -eq 1) 'Journal identity ambiguous.'
    Assert-NativeJournal $info[0] $dbId $session $dbImageId $dbStarted
}
function Write-JournalPublic([string]$Path,[string]$Value){
    Assert-True ($Path -cin @('/tmp/ca.pem','/tmp/server.crt','/tmp/server.key','/tmp/hba.conf')) 'Unknown PG slot.'
    Read-Journal
    $null=Invoke-Docker @('exec','-i',$dbId,'/bin/sh','-c','umask 077; cat > "$1"','fixture',$Path) ([Text.Encoding]::UTF8.GetBytes($Value))
}
function Invoke-JournalAdmin([string]$Database,[string]$Sql){
    Assert-True ($Database -cin @('postgres','fleetory_signer')) 'Unknown fixture database.'
    Read-Journal
    return Invoke-Docker @('exec','-i',$dbId,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',$Database) ([Text.Encoding]::UTF8.GetBytes($Sql))
}
function Write-JournalConnection([string]$Password,[string]$Mode='VerifyFull'){
    Assert-True ($Password -cmatch '^[a-f0-9]{64}$' -and $Mode -cin @('VerifyFull','Disable')) 'Connection packet invalid.'
    $value='Host=127.0.0.1;Port=5432;Database=fleetory_signer;Username=fleetory_signer;Password='+$Password+
        ';SSL Mode='+$Mode+';Root Certificate=/run/fleetory-native/signer/infrastructure-ca;GSS Encryption Mode=Disable;Timeout=5;Command Timeout=5;Pooling=false'
    Write-NativeWorkerFile $worker '/run/fleetory-native/signer/signer-postgresql' ([Text.Encoding]::UTF8.GetBytes($value))
}
function Invoke-JournalProbe([string]$Mode,[string]$Expected){
    $r=Invoke-NativeWorker $worker 'SignerJournalProbe' $Mode $null $canaries.ToArray()
    $record=$r.Stdout|ConvertFrom-Json -AsHashtable
    if($r.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($r.Stderr) -or $record.category -cne $Expected){
        $category=if($record.category -cmatch '^[a-z-]{1,32}$'){$record.category}else{'invalid'}
        $kind=if($r.Stderr -match '^(warn|info|WARNING|Error|error|Exception|Unhandled|Failed)'){$Matches[1]}else{'other'}
        [Console]::Error.WriteLine('Journal protocol diagnostic: expected='+$Expected+';stderrLength='+$r.Stderr.Length+';stderrKind='+$kind+';stderrJson='+$r.Stderr.TrimStart().StartsWith('{'))
        throw ('Journal probe mismatch: '+$Mode+';category='+$category+';exit='+$r.ExitCode)
    }
    Assert-True ($record.httpHostStarted -eq $false -and $record.issuerActivated -eq $false) 'Unexpected host or issuer startup.'
}
try{
    $null=New-Item -ItemType Directory -Path $publicRoot
    $published=Publish-NativeProbe $repoRoot 'SignerJournalProbe' $publicRoot
    $stage='images'
    foreach($image in @($script:nativeJournalImage,$script:nativeSignerImage)){
        $i=Invoke-Docker @('image','inspect',$image) -AllowFailure
        if($i.ExitCode -ne 0){$null=Invoke-Docker @('pull',$image) -TimeoutSeconds 120}
    }
    $dbImage=@((Invoke-Docker @('image','inspect',$script:nativeJournalImage)).Stdout|ConvertFrom-Json -AsHashtable)[0]
    $runtime=@((Invoke-Docker @('image','inspect',$script:nativeSignerImage)).Stdout|ConvertFrom-Json -AsHashtable)[0]
    $dbImageId=[string]$dbImage.Id
    $dbName='fleetory-native-journal-'+$session.Replace('-','')
    $absent=Invoke-Docker @('inspect',$dbName) -AllowFailure
    Assert-True ($absent.ExitCode -ne 0 -and ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|container)') 'Database name not fresh.'
    $dbStarted=[DateTimeOffset]::UtcNow;$dbClaimed=$true;$stage='postgres'
    $dbId=(Invoke-Docker (Get-NativeJournalArguments $session)).Stdout.Trim();Read-Journal
    $material=New-PilotDisposableTlsMaterial;$wrongMaterial=New-PilotDisposableTlsMaterial
    foreach($line in ($material.ServerPrivateKeyPem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$canaries.Add($line.Substring(0,40))}}
    Write-JournalPublic '/tmp/ca.pem' $material.RootCertificatePem
    Write-JournalPublic '/tmp/server.crt' $material.ServerCertificatePem
    Write-JournalPublic '/tmp/server.key' $material.ServerPrivateKeyPem
    Write-JournalPublic '/tmp/hba.conf' "local all postgres peer`nlocal all all reject`nhostssl fleetory_signer fleetory_signer 127.0.0.1/32 scram-sha-256`nhost all all 0.0.0.0/0 reject`nhost all all ::/0 reject`n"
    $init=Invoke-Docker @('exec',$dbId,'initdb','-D','/var/lib/postgresql/18/recovery','--auth-local=peer','--auth-host=reject','--no-instructions')
    $null=Invoke-Docker @('exec','-d',$dbId,'postgres','-D','/var/lib/postgresql/18/recovery','-c','listen_addresses=127.0.0.1',
        '-c','unix_socket_directories=/var/run/postgresql','-c','hba_file=/tmp/hba.conf','-c','password_encryption=scram-sha-256',
        '-c','ssl=on','-c','ssl_cert_file=/tmp/server.crt','-c','ssl_key_file=/tmp/server.key','-c','ssl_min_protocol_version=TLSv1.2',
        '-c','shared_buffers=32MB','-c','max_connections=20','-c','log_statement=none','-c','log_min_error_statement=panic')
    $ready=$false
    for($n=0;$n -lt 60;$n++){$r=Invoke-Docker @('exec',$dbId,'pg_isready','-q','-U','postgres') -AllowFailure;if($r.ExitCode -eq 0){$ready=$true;break};Start-Sleep -Milliseconds 250}
    Assert-True $ready 'Fresh PostgreSQL not ready.'
    $stage='schema'
    $sql="CREATE ROLE fleetory_signer_owner NOLOGIN; CREATE ROLE fleetory_signer LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '"+$password+"'; CREATE DATABASE fleetory_signer OWNER fleetory_signer_owner; REVOKE ALL ON DATABASE fleetory_signer FROM PUBLIC; GRANT CONNECT ON DATABASE fleetory_signer TO fleetory_signer;"
    $null=Invoke-JournalAdmin 'postgres' $sql
    $schema=Get-Content -LiteralPath (Join-Path $repoRoot 'eng/provision-signing-journal.sql') -Raw
    $null=Invoke-JournalAdmin 'fleetory_signer' ('SET ROLE fleetory_signer_owner;'+"`n"+$schema+"`nRESET ROLE; GRANT USAGE ON SCHEMA signer TO fleetory_signer; GRANT SELECT,INSERT ON signer.signing_requests,signer.signing_results,signer.signing_rejections TO fleetory_signer; GRANT SELECT ON signer.client_certificate_revocations TO fleetory_signer;")
    $scram=Invoke-JournalAdmin 'postgres' "SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE rolname='fleetory_signer';"
    Assert-True ($scram.Stdout.Trim() -ceq 't') 'Generated password is not SCRAM.'
    $stage='worker';Read-Journal
    $worker=New-NativeWorkerContext $session $dbId $published $runtime;Start-NativeWorkerContext $worker
    $null=Invoke-Docker @('exec',$worker.Id,'/bin/mkdir','-m','700','/run/fleetory-native/signer','/tmp/empty-ca-dir')
    $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($material.ServerCertificatePem)
    try{$fingerprint=$cert.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256)}finally{$cert.Dispose()}
    $now=[DateTimeOffset]::UtcNow
    $policy=@{rootsPem=$material.RootCertificatePem;intermediatesPem='';callers=@(@{callerId='fixture-server';certificateSha256=$fingerprint;
        deviceIds=@([Guid]::NewGuid().ToString('D'));notBefore=$now.AddMinutes(-1).ToString('O');expiresAt=$now.AddHours(1).ToString('O')})}|ConvertTo-Json -Depth 8 -Compress
    $key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try{$spki=[Convert]::ToBase64String($key.ExportSubjectPublicKeyInfo())}finally{$key.Dispose()}
    $placeholder='fixture-'+[Guid]::NewGuid().ToString('N');$canaries.Add($placeholder)
    $packets=@{'infrastructure-ca'=$material.RootCertificatePem;'signer-policy'=$policy;'signer-server-ca'=$material.RootCertificatePem;
        'signer-server-cert'=$material.ServerCertificatePem;'signer-server-key'=$material.ServerPrivateKeyPem;'signer-transit-public-key'=$spki;'signer-transit-token'=$placeholder}
    foreach($slot in $packets.Keys){Write-NativeWorkerFile $worker ('/run/fleetory-native/signer/'+$slot) ([Text.Encoding]::UTF8.GetBytes($packets[$slot]))}
    Write-JournalConnection $password
    $stage='native';Invoke-JournalProbe 'ready' 'ready'
    foreach($case in @(
        @('GRANT UPDATE ON signer.signing_results TO fleetory_signer;','REVOKE UPDATE ON signer.signing_results FROM fleetory_signer;'),
        @('GRANT UPDATE(signing_key_id) ON signer.signing_results TO fleetory_signer;','REVOKE UPDATE(signing_key_id) ON signer.signing_results FROM fleetory_signer;'),
        @('GRANT CREATE ON SCHEMA signer TO fleetory_signer;','REVOKE CREATE ON SCHEMA signer FROM fleetory_signer;'),
        @('GRANT fleetory_signer_owner TO fleetory_signer;','REVOKE fleetory_signer_owner FROM fleetory_signer;'),
        @('ALTER ROLE fleetory_signer BYPASSRLS;','ALTER ROLE fleetory_signer NOBYPASSRLS;'),
        @('GRANT INSERT ON signer.client_certificate_revocations TO fleetory_signer;','REVOKE INSERT ON signer.client_certificate_revocations FROM fleetory_signer;')
    )){
        $null=Invoke-JournalAdmin 'fleetory_signer' $case[0]
        try{Invoke-JournalProbe 'unsafe' 'unsafe-permissions'}finally{$null=Invoke-JournalAdmin 'fleetory_signer' $case[1]}
    }
    foreach($mode in @('update','delete','schema','revocation','owner')){Invoke-JournalProbe $mode 'privilege'}
    Write-JournalConnection $wrongPassword
    try{Invoke-JournalProbe 'password' 'authentication'}finally{Write-JournalConnection $password}
    Write-NativeWorkerFile $worker '/run/fleetory-native/signer/infrastructure-ca' ([Text.Encoding]::UTF8.GetBytes($wrongMaterial.RootCertificatePem))
    try{Invoke-JournalProbe 'tls' 'tls'}finally{Write-NativeWorkerFile $worker '/run/fleetory-native/signer/infrastructure-ca' ([Text.Encoding]::UTF8.GetBytes($material.RootCertificatePem))}
    Write-JournalConnection $password 'Disable'
    try{Invoke-JournalProbe 'plaintext' 'plaintext'}finally{Write-JournalConnection $password}
    Invoke-JournalProbe 'ready' 'ready'
    $proof=[ordered]@{schema='fleetory.native-journal-backend.v1';verified=$true;nativeReadinessAccepted=2;unsafePermissionRefusals=6;nativeSqlPrivilegeRefusals=5;
        wrongPasswordRefusals=1;wrongCaRefusals=1;plaintextRefusals=1;scramVerifierObserved=$true;verifiedTcpTls=$true;
        providerBoundaryMutations=16;workerBoundaryMutations=23;workerOnlyLoopback=$true;publishedPorts=0;originalMaterialUsed=$false;
        sourceVpsAccessed=$false;httpHostStarted=$false;issuerActivated=$false;transitBackendContacted=$false;originalRoleRecoveryVerified=$false;fullSystemRecoveryVerified=$false;phase7Complete=$false}
}
catch{
    if($_.Exception.Message -cmatch '^Journal probe mismatch: ([a-z-]+;category=[a-z-]+;exit=[0-9]+)$'){[Console]::Error.WriteLine('Journal diagnostic: '+$Matches[1])}
    [Console]::Error.WriteLine('Generated native journal fixture failed at '+$stage+'; type='+$_.Exception.GetType().Name+'; line='+$_.InvocationInfo.ScriptLineNumber+'. No raw SQL, response or credentials emitted.')
    throw 'Generated native journal fixture did not pass.'
}
finally{
    $failures=[Collections.Generic.List[string]]::new()
    try{Remove-NativeWorker $worker}catch{$failures.Add('worker')}
    try{
        if($dbClaimed){
            $lookup=if($dbId){$dbId}else{'fleetory-native-journal-'+$session.Replace('-','')}
            $i=Invoke-Docker @('inspect',$lookup) -AllowFailure
            if($i.ExitCode -eq 0){$found=@($i.Stdout|ConvertFrom-Json -AsHashtable);Assert-True ($found.Count -eq 1) 'Cleanup ambiguous.';$id=[string]$found[0].Id;Assert-NativeJournal $found[0] $id $session $dbImageId $dbStarted -CleanupOnly;$null=Invoke-Docker @('rm','-f','-v',$id);$i=Invoke-Docker @('inspect',$id) -AllowFailure}
            Assert-True ($i.ExitCode -ne 0 -and ($i.Stderr+$i.Stdout) -match '(?i)no such (object|container)') 'Database absence unverified.'
        }
    }catch{$failures.Add('postgres')}
    try{Remove-NativePublicPayload $repoRoot $publicRoot}catch{$failures.Add('public-payload')}
    $password=$wrongPassword=$placeholder=$material=$wrongMaterial=$null;$canaries.Clear()
    if($failures.Count -ne 0){throw ('Native journal cleanup unverified: '+($failures -join ','))}
}
if($proof){$proof.cleanupVerified=$true;$proof|ConvertTo-Json -Compress}
