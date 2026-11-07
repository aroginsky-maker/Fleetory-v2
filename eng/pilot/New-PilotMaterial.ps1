#requires -Version 7.3
# Offline keys are filesystem secrets, not independent HSM custody. Upload only upload/.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory,[Parameter(Mandatory)][string]$AppHost,[Parameter(Mandatory)][string]$AuthHost,[Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ApplicationCommit)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ([Environment]::Version.Major -lt 7) { throw 'Requires PowerShell 7.3 or later on .NET 7 or later.' }
foreach ($hostName in @($AppHost,$AuthHost)) { if ([Uri]::CheckHostName($hostName) -ne [UriHostNameType]::Dns -or $hostName.Contains('*')) { throw 'Hosts must be DNS names.' } }
if ($AppHost.TrimEnd('.').Equals($AuthHost.TrimEnd('.'),[StringComparison]::OrdinalIgnoreCase)) { throw 'AppHost and AuthHost must differ.' }
if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory)) { throw 'OutputDirectory must be absolute.' }
$out=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar)
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd([IO.Path]::DirectorySeparatorChar)
$comparison=if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
if ($out.Equals($repo,$comparison) -or $out.StartsWith($repo+[IO.Path]::DirectorySeparatorChar,$comparison)) { throw 'Output must be outside the repository.' }
if (Test-Path -LiteralPath $out) {
 if (-not (Test-Path -LiteralPath $out -PathType Container)) { throw 'Output is not a directory.' }
 if (@(Get-ChildItem -LiteralPath $out -Force).Count) { throw 'Output must be empty; refusing credential rotation.' }
}
$ancestor=[IO.DirectoryInfo]::new($out)
while ($null -ne $ancestor) {
 if (Test-Path -LiteralPath (Join-Path $ancestor.FullName '.git')) { throw 'Output must be outside every Git checkout.' }
 if ($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Output cannot traverse links.' }
 $ancestor=$ancestor.Parent
}
$null=[IO.Directory]::CreateDirectory($out)
if ($IsWindows) {
 $acl=[Security.AccessControl.DirectorySecurity]::new(); $acl.SetAccessRuleProtection($true,$false)
 foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
 }
 [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($out),$acl)
} else { [IO.File]::SetUnixFileMode($out,[IO.UnixFileMode]448) }
function New-PrivateDirectory([string]$relative) {
 $path=Join-Path $out $relative; $null=[IO.Directory]::CreateDirectory($path)
 if (-not $IsWindows) { [IO.File]::SetUnixFileMode($path,[IO.UnixFileMode]448) }
}
function Write-Private([string]$relative,[string]$value) {
 $path=Join-Path $out $relative
 [IO.File]::WriteAllText($path,$value.Replace("`r`n","`n"),[Text.UTF8Encoding]::new($false))
 if (-not $IsWindows) { [IO.File]::SetUnixFileMode($path,[IO.UnixFileMode]384) }
}
function New-Password { [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)) }
$now=[DateTimeOffset]::UtcNow; $start=$now.AddMinutes(-5)
$resources=[Collections.Generic.List[IDisposable]]::new()
function New-Root([string]$name) {
 $key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256); $resources.Add($key)
 $req=[Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=Fleetory PILOT $name Root",$key,[Security.Cryptography.HashAlgorithmName]::SHA256)
 $null=$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
 $null=$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign),$true))
 $null=$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($req.PublicKey,$false))
 $cert=$req.CreateSelfSigned($start,$now.AddYears(2)); $resources.Add($cert)
 Write-Private "offline/$name-root.key" ($key.ExportPkcs8PrivateKeyPem())
 Write-Private "offline/$name-root.crt" ($cert.ExportCertificatePem())
 return $cert
}
function New-Leaf($issuer,[string]$cn,[string[]]$dns,[bool]$client=$false,[int]$days=30,[bool]$loopback=$false) {
 $key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256); $resources.Add($key)
 $req=[Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$cn",$key,[Security.Cryptography.HashAlgorithmName]::SHA256)
 $null=$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
 $null=$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,$true))
 $oids=[Security.Cryptography.OidCollection]::new()
 $oid=if ($client) { '1.3.6.1.5.5.7.3.2' } else { '1.3.6.1.5.5.7.3.1' }
 $null=$oids.Add([Security.Cryptography.Oid]::new($oid))
 $null=$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$true))
 $null=$req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($req.PublicKey,$false))
 if ($dns.Count -gt 0 -or $loopback) {
  $san=[Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
  foreach ($d in $dns) { $san.AddDnsName($d) }
  if ($loopback) { $san.AddIpAddress([Net.IPAddress]::Loopback) }
  $null=$req.CertificateExtensions.Add($san.Build())
 }
 $serial=[Security.Cryptography.RandomNumberGenerator]::GetBytes(16); $serial[0]=$serial[0] -bor 1
 $bare=$req.Create($issuer,$start,$now.AddDays($days),$serial)
 try { $cert=[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($bare,$key) } finally { $bare.Dispose() }
 $resources.Add($cert)
 return @{Cert=$cert;Pem=$cert.ExportCertificatePem();Key=$key.ExportPkcs8PrivateKeyPem()}
}
try {
 foreach ($dir in @('offline','operator','upload','upload/secrets','upload/config','upload/secrets/postgres','upload/secrets/postgres-init','upload/secrets/server','upload/secrets/signer','upload/secrets/openbao','upload/secrets/immudb','upload/secrets/audit-gateway','upload/secrets/keycloak')) { New-PrivateDirectory $dir }
 $roots=@{}
 foreach ($name in @('infrastructure','agent','admin','signer-client')) { $roots[$name]=New-Root $name }
 $infraPem=$roots.infrastructure.ExportCertificatePem()
 foreach ($entry in @(@('postgres','postgres'),@('openbao','openbao'),@('immudb','audit-store'),@('audit-gateway','immudb'))) {
  $leaf=New-Leaf $roots.infrastructure $entry[1] @($entry[1],'localhost')
  Write-Private "upload/secrets/$($entry[0])/server.crt" $leaf.Pem
  Write-Private "upload/secrets/$($entry[0])/server.key" $leaf.Key
  $caName=if ($entry[0] -in @('postgres','openbao')) { 'ca.crt' } else { 'infrastructure-ca' }
  Write-Private "upload/secrets/$($entry[0])/$caName" $infraPem
 }
 foreach ($name in @('agent','admin')) {
  $leaf=New-Leaf $roots[$name] 'localhost' @('localhost') $false 30 $true
  Write-Private "upload/secrets/server/$name-gateway-root-ca" ($roots[$name].ExportCertificatePem())
  Write-Private "upload/secrets/server/$name-gateway-server-cert" $leaf.Pem
  Write-Private "upload/secrets/server/$name-gateway-server-key" $leaf.Key
 }
 $signer=New-Leaf $roots.infrastructure 'command-signer' @('command-signer','localhost')
 Write-Private 'upload/secrets/signer/signer-server-ca' $infraPem
 Write-Private 'upload/secrets/signer/signer-server-cert' $signer.Pem
 Write-Private 'upload/secrets/signer/signer-server-key' $signer.Key
 foreach ($name in @('server','signer','keycloak')) { Write-Private "upload/secrets/$name/infrastructure-ca" $infraPem }
 $device=[Guid]::NewGuid().ToString()
 $client=New-Leaf $roots['signer-client'] 'pilot-verification' @() $true 7
 $fingerprint=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($client.Cert.RawData))
 Write-Private 'operator/signer-client.crt' $client.Pem
 Write-Private 'operator/signer-client.key' $client.Key
 Write-Private 'operator/infrastructure-root.crt' $infraPem
 Write-Private 'operator/pilot-device-id' $device
 # Caller grants are limited to 24 hours independently of the seven-day mTLS leaf.
 $grantNotBefore=[DateTimeOffset]::new($client.Cert.NotBefore.ToUniversalTime())
 $grantExpiresAt=$grantNotBefore.AddHours(24)
 $policy=@{rootsPem=$roots['signer-client'].ExportCertificatePem();callers=@(@{callerId='pilot-verification';certificateSha256=$fingerprint;deviceIds=@($device);notBefore=$grantNotBefore.ToString('o');expiresAt=$grantExpiresAt.ToString('o')})}
 Write-Private 'upload/secrets/signer/signer-policy' ($policy | ConvertTo-Json -Depth 6)
 $credentials=@{}
 foreach ($name in @('postgresAdmin','fleetoryMigrator','fleetoryRuntime','keycloakDb','signerRuntime','immudbAdmin','immudbWriter','keycloakBootstrap')) { $credentials[$name]=New-Password }
 foreach ($name in @('immudbAdmin','immudbWriter')) { $credentials[$name]='A1!'+$credentials[$name] }
 Write-Private 'offline/credentials.json' ($credentials | ConvertTo-Json)
 Write-Private 'upload/secrets/postgres/admin-password' $credentials.postgresAdmin
 Write-Private 'upload/secrets/immudb/admin-password' $credentials.immudbAdmin
 Write-Private 'upload/secrets/immudb/immudb.toml' ('admin-password = ' + [char]34 + $credentials.immudbAdmin + [char]34 + [char]10)
 Write-Private 'upload/secrets/server/audit-immudb-password' $credentials.immudbWriter
 Write-Private 'upload/secrets/keycloak/bootstrap-password' $credentials.keycloakBootstrap
 Write-Private 'upload/secrets/server/fleetory-postgresql' "Host=postgres;Database=fleetory;Username=fleetory_server;Password=$($credentials.fleetoryRuntime);SSL Mode=VerifyFull;Root Certificate=/run/fleetory-server/infrastructure-ca;Maximum Pool Size=15"
 Write-Private 'upload/secrets/signer/signer-postgresql' "Host=postgres;Database=fleetory_signer;Username=fleetory_signer;Password=$($credentials.signerRuntime);SSL Mode=VerifyFull;Root Certificate=/run/fleetory-signer/infrastructure-ca;Maximum Pool Size=8"
 Write-Private 'upload/secrets/keycloak/keycloak.conf' @"
db=postgres
db-url=jdbc:postgresql://postgres:5432/keycloak?sslmode=verify-full&sslrootcert=/run/secrets/keycloak/infrastructure-ca
db-username=keycloak
db-password=$($credentials.keycloakDb)
hostname=https://$AuthHost
http-enabled=true
http-host=0.0.0.0
http-port=8080
proxy-headers=xforwarded
health-enabled=true
"@
 $stateKey=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256); $resources.Add($stateKey)
 Write-Private 'upload/secrets/immudb/state-signing.pem' ($stateKey.ExportECPrivateKeyPem())
 Write-Private 'upload/config/Caddyfile' (([IO.File]::ReadAllText((Join-Path $repo 'infra/pilot/Caddyfile.template'))).Replace('__FLEETORY_HOST__',$AppHost).Replace('__FLEETORY_AUTH_HOST__',$AuthHost))
 Write-Private 'upload/config/audit-gateway.conf' ([IO.File]::ReadAllText((Join-Path $repo 'infra/pilot/audit-gateway.conf')))
 Write-Private 'upload/config/openbao.hcl' @"
ui = false
api_addr = "https://openbao:8200"
cluster_addr = "https://openbao:8201"
disable_mlock = true
storage "raft" {
 path = "/openbao/data"
 node_id = "pilot-1"
}
listener "tcp" {
 address = "0.0.0.0:8200"
 tls_cert_file = "/run/secrets/openbao/server.crt"
 tls_key_file = "/run/secrets/openbao/server.key"
 tls_min_version = "tls12"
 disable_unauthed_generate_root_endpoints = true
}
audit "file" "pilot-file" {
 options {
  file_path = "/openbao/data/audit.log"
  mode = "0600"
  log_raw = "false"
 }
}
"@
 Write-Private 'upload/config/postgresql.conf' @"
listen_addresses = '*'
ssl = on
ssl_cert_file = '/run/secrets/postgres/server.crt'
ssl_key_file = '/run/secrets/postgres/server.key'
ssl_ca_file = '/run/secrets/postgres/ca.crt'
hba_file = '/etc/postgresql/pg_hba.conf'
shared_buffers = '128MB'
max_connections = 50
password_encryption = 'scram-sha-256'
"@
 Write-Private 'upload/config/pg_hba.conf' @"
local all all peer
hostssl fleetory fleetory_server 172.30.77.20/32 scram-sha-256
hostssl keycloak keycloak 172.30.77.11/32 scram-sha-256
hostssl fleetory_signer fleetory_signer 172.30.78.30/32 scram-sha-256
host all all 0.0.0.0/0 reject
host all all ::/0 reject
"@
 $rootHashes=@{}
 foreach ($name in $roots.Keys) { $rootHashes[$name]=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($roots[$name].RawData)) }
 Write-Private 'manifest.json' (@{schema=1;date=$now.ToString('o');appHost=$AppHost;authHost=$AuthHost;applicationCommit=$ApplicationCommit.ToLowerInvariant();pilotDeviceId=$device;signerClientCertSha256=$fingerprint;publicRootDerFingerprints=$rootHashes;productionVerified=$false;independentWormCustodyVerified=$false} | ConvertTo-Json -Depth 6)
 Write-Output "PILOT material created at $out. Upload only upload/; retain offline/ and operator/ privately."
} catch {
 throw 'PILOT generation failed. Partial output retained; do not reuse it. Inspect privately.'
} finally { foreach ($resource in $resources) { $resource.Dispose() } }
