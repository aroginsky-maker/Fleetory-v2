#requires -Version 7.3
# End-to-end disposable pilot provisioning; never targets operator material or a VPS.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$materialGenerator = Join-Path $repoRoot 'eng/pilot/New-PilotMaterial.ps1'
$databaseGenerator = Join-Path $repoRoot 'eng/pilot/New-PilotDatabaseScript.ps1'
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$work = Join-Path $tempRoot ('fleetory-pilot-test-' + [Guid]::NewGuid().ToString('N'))
$insideGit = Join-Path $repoRoot ('pilot-rejected-' + [Guid]::NewGuid().ToString('N'))
$containerId = $null
$oldMigrationConnection = [Environment]::GetEnvironmentVariable('FLEETORY_MIGRATION_CONNECTION_STRING')
$resources = [Collections.Generic.List[IDisposable]]::new()
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-Rejected([scriptblock]$Action, [string]$Message) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-True $rejected $Message
}
function Invoke-DisposableSql([string]$Database, [string]$Sql) {
    # Native error text can contain SQL/passwords: retain no diagnostics in output.
    $captured = $Sql | & docker exec -i $containerId psql -X -U postgres -d $Database -v ON_ERROR_STOP=1 -q 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL assertion failed; SQL diagnostics suppressed.' }
}
function Assert-Leaf([string]$Relative, [string]$RootName, [string]$Purpose) {
    $certPath = Join-Path $work "material/upload/secrets/$Relative"
    $keyPath = [IO.Path]::ChangeExtension($certPath, '.key')
    if ($Relative -eq 'server/agent-gateway-server-cert') { $keyPath = Join-Path $work 'material/upload/secrets/server/agent-gateway-server-key' }
    if ($Relative -eq 'server/admin-gateway-server-cert') { $keyPath = Join-Path $work 'material/upload/secrets/server/admin-gateway-server-key' }
    if ($Relative -eq 'signer/signer-server-cert') { $keyPath = Join-Path $work 'material/upload/secrets/signer/signer-server-key' }
    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($certPath,$keyPath)
    $resources.Add($cert)
    Assert-True $cert.HasPrivateKey 'Leaf key does not match its certificate.'
    $eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    Assert-True ($eku.Count -eq 1 -and @($eku[0].EnhancedKeyUsages | Where-Object Value -EQ $Purpose).Count -eq 1) 'Leaf purpose is incorrect.'
    $root = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText((Join-Path $work "material/offline/$RootName-root.crt")))
    $resources.Add($root)
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $null = $chain.ChainPolicy.CustomTrustStore.Add($root)
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.DisableCertificateDownloads = $true
        Assert-True ($chain.Build($cert)) 'Leaf does not chain to its dedicated root.'
        Assert-True ($chain.ChainElements.Count -eq 2) 'Unexpected certificate chain.'
    } finally { $chain.Dispose() }
}
try {
    New-Item -ItemType Directory -Path $work | Out-Null
    if (-not $IsWindows) { [IO.File]::SetUnixFileMode($work,[IO.UnixFileMode]448) }
    $material = Join-Path $work 'material'
    $argsForMaterial = @{OutputDirectory=$material; AppHost='app.pilot.invalid'; AuthHost='auth.pilot.invalid'; ApplicationCommit=('a' * 40)}
    & $materialGenerator @argsForMaterial | Out-Null
    Assert-Rejected { & $materialGenerator @argsForMaterial } 'Existing material was reused.'
    $invalidOutput = Join-Path $work 'invalid-host'
    Assert-Rejected { & $materialGenerator -OutputDirectory $invalidOutput -AppHost '*.invalid' -AuthHost 'auth.invalid' -ApplicationCommit ('a'*40) } 'Invalid hostname accepted.'
    Assert-True (-not (Test-Path -LiteralPath $invalidOutput)) 'Invalid hostname wrote output.'
    Assert-Rejected { & $materialGenerator -OutputDirectory $insideGit -AppHost 'app.invalid' -AuthHost 'auth.invalid' -ApplicationCommit ('a'*40) } 'Repository output accepted.'
    Assert-True (-not (Test-Path -LiteralPath $insideGit)) 'Rejected repository output was created.'
    foreach ($entry in @(@('postgres/server.crt','infrastructure'),@('openbao/server.crt','infrastructure'),@('immudb/server.crt','infrastructure'),@('audit-gateway/server.crt','infrastructure'),@('server/agent-gateway-server-cert','agent'),@('server/admin-gateway-server-cert','admin'),@('signer/signer-server-cert','infrastructure'))) {
        Assert-Leaf $entry[0] $entry[1] '1.3.6.1.5.5.7.3.1'
    }
    $client = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile((Join-Path $material 'operator/signer-client.crt'),(Join-Path $material 'operator/signer-client.key'))
    $resources.Add($client)
    Assert-True ($client.HasPrivateKey -and ($client.NotAfter-$client.NotBefore).TotalDays -gt 6) 'Client leaf/key lifetime failed.'
    $clientEku = $client.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
    Assert-True (@($clientEku.EnhancedKeyUsages | Where-Object Value -EQ '1.3.6.1.5.5.7.3.2').Count -eq 1) 'Signer client purpose failed.'
    $policyText = Get-Content -LiteralPath (Join-Path $material 'upload/secrets/signer/signer-policy') -Raw
    $baoConfig = [IO.File]::ReadAllText((Join-Path $material 'upload/config/openbao.hcl'))
    Assert-True ($baoConfig -match 'disable_unauthed_generate_root_endpoints\s*=\s*true') 'Normal listener permits unauthenticated root recovery.'
    Assert-True ($baoConfig -match 'audit "file" "pilot-file"' -and $baoConfig -match 'log_raw\s*=\s*"false"') 'OpenBao declarative audit is missing or logs raw secrets.'
    $policy = $policyText | ConvertFrom-Json
    $clientRoot = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([string]$policy.rootsPem)
    $resources.Add($clientRoot)
    $clientChain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $clientChain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $null = $clientChain.ChainPolicy.CustomTrustStore.Add($clientRoot)
        $clientChain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $clientChain.ChainPolicy.DisableCertificateDownloads = $true
        Assert-True ($clientChain.Build($client)) 'Signer caller does not chain to its configured policy root.'
    } finally { $clientChain.Dispose() }
    $grant = $policy.callers[0]
    # Inspect actual JSON strings: newer PowerShell implicitly coerces ISO timestamps.
    $policyDocument = [System.Text.Json.JsonDocument]::Parse($policyText)
    $resources.Add($policyDocument)
    $grantJson = $policyDocument.RootElement.GetProperty('callers')[0]
    $notBefore = $grantJson.GetProperty('notBefore').GetString()
    $expiresAt = $grantJson.GetProperty('expiresAt').GetString()
    Assert-True ($notBefore -match '(Z|\+00:00)$' -and $expiresAt -match '(Z|\+00:00)$') 'Grant timestamps are not UTC.'
    $grantStart = [DateTimeOffset]::Parse($notBefore)
    $grantEnd = [DateTimeOffset]::Parse($expiresAt)
    Assert-True ($grantEnd -gt $grantStart -and ($grantEnd-$grantStart).TotalHours -le 24) 'Grant exceeds 24 hours.'
    Assert-True ($grant.certificateSha256 -ceq [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($client.RawData))) 'Caller fingerprint mismatch.'
    $rootKeys = @(Get-ChildItem -LiteralPath (Join-Path $material 'offline') -Filter '*-root.key' | ForEach-Object { [IO.File]::ReadAllText($_.FullName).Trim() })
    Assert-True ($rootKeys.Count -eq 4) 'Dedicated CA roots missing.'
    $rootFingerprints = [Collections.Generic.HashSet[string]]::new()
    foreach ($rootKeyFile in Get-ChildItem -LiteralPath (Join-Path $material 'offline') -Filter '*-root.key') {
        $rootCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile([IO.Path]::ChangeExtension($rootKeyFile.FullName,'.crt'),$rootKeyFile.FullName)
        $resources.Add($rootCertificate)
        $constraints = $rootCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
        $usage = $rootCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' }
        Assert-True ($rootCertificate.HasPrivateKey -and $constraints.CertificateAuthority -and ($usage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign) -ne 0) 'CA purpose/key match failed.'
        Assert-True ($rootFingerprints.Add([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rootCertificate.RawData)))) 'Trust domains share a CA.'
    }
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $material 'upload') -File -Recurse) {
        $content = [IO.File]::ReadAllText($file.FullName)
        foreach ($rootKey in $rootKeys) { Assert-True (-not $content.Contains($rootKey)) 'CA private key leaked into upload.' }
    }
    foreach ($item in @(Get-Item -LiteralPath $material) + @(Get-ChildItem -LiteralPath $material -Recurse -Force)) {
        if ($IsWindows) {
            $allowed = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
            foreach ($rule in (Get-Acl -LiteralPath $item.FullName).Access) {
                if ($rule.AccessControlType -eq 'Allow') { Assert-True ($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -in $allowed) 'Material ACL grants unrelated access.' }
            }
        } else { Assert-True (([int][IO.File]::GetUnixFileMode($item.FullName) -band 63) -eq 0) 'Material mode permits group/other access.' }
    }
    [Environment]::SetEnvironmentVariable('FLEETORY_MIGRATION_CONNECTION_STRING','Host=localhost;Database=fleetory_test_export;Username=unused;Password=unused')
    $platformSql = Join-Path $work 'platform.sql'
    $coreSql = Join-Path $work 'core.sql'
    Push-Location $repoRoot
    try {
        foreach ($export in @(@('Fleetory.Platform','PlatformDbContext',$platformSql),@('Fleetory.Core','CoreDbContext',$coreSql))) {
            $captured = & dotnet ef migrations script --idempotent --no-build --configuration Release --project "src/$($export[0])" --startup-project "src/$($export[0])" --context $export[1] --output $export[2] 2>&1
            if ($LASTEXITCODE -ne 0) { throw 'Offline EF script export failed.' }
        }
    } finally { Pop-Location }
    $initSql = Join-Path $material 'upload/secrets/postgres-init/001-pilot.sql'
    $dbArgs = @{CredentialsPath=(Join-Path $material 'offline/credentials.json');PlatformMigrationPath=$platformSql;CoreMigrationPath=$coreSql;SignerSchemaPath=(Join-Path $repoRoot 'eng/provision-signing-journal.sql');OutputPath=$initSql}
    & $databaseGenerator @dbArgs | Out-Null
    Assert-Rejected { & $databaseGenerator @dbArgs } 'Existing database SQL output was overwritten.'
    # Trust is exclusively inside this disposable container: no network, ports or host data mounts.
    $runResult = & docker run --detach --network none --memory 384m --cpus 1 --env POSTGRES_HOST_AUTH_METHOD=trust postgres:18.6 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL container could not start.' }
    $containerId = [string]($runResult | Select-Object -Last 1)
    Assert-True ($containerId -cmatch '\A[0-9a-f]{64}\z') 'Docker returned an invalid container identity.'
    $ready = $false
    for ($attempt=0;$attempt -lt 30;$attempt++) {
        $captured = & docker exec $containerId pg_isready -U postgres 2>&1
        if ($LASTEXITCODE -eq 0) { $ready=$true; break }
        Start-Sleep -Seconds 1
    }
    Assert-True $ready 'Disposable PostgreSQL did not become ready.'
    $captured = & docker cp $initSql "${containerId}:/tmp/pilot-init.sql" 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Disposable SQL copy failed.' }
    $captured = & docker exec $containerId psql -X -U postgres -d postgres -v ON_ERROR_STOP=1 -q -f /tmp/pilot-init.sql 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Fresh-cluster provisioning failed; SQL diagnostics suppressed.' }
    Invoke-DisposableSql fleetory @'
DO $$ BEGIN
 IF (SELECT count(*) FROM platform."__EFMigrationsHistory") <> 9 OR
    (SELECT count(*) FROM core."__EFMigrationsHistory") <> 6 THEN RAISE EXCEPTION 'history'; END IF;
 IF EXISTS (SELECT FROM pg_roles WHERE rolname IN ('fleetory_server','fleetory_signer') AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN RAISE EXCEPTION 'elevation'; END IF;
 IF EXISTS (SELECT FROM pg_auth_members JOIN pg_roles ON member=pg_roles.oid WHERE rolname IN ('fleetory_server','fleetory_signer')) THEN RAISE EXCEPTION 'membership'; END IF;
 IF has_database_privilege('fleetory_server','fleetory','CREATE') OR has_database_privilege('fleetory_server','fleetory','TEMP') OR has_schema_privilege('fleetory_server','platform','CREATE') OR has_schema_privilege('fleetory_server','core','CREATE') THEN RAISE EXCEPTION 'create'; END IF;
 IF EXISTS (SELECT FROM pg_tables WHERE schemaname IN ('core','platform') AND tableowner='fleetory_server') THEN RAISE EXCEPTION 'ownership'; END IF;
 IF (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='fleetory') <> 'fleetory_migrator' OR (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='keycloak') <> 'keycloak' OR (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='fleetory_signer') <> 'fleetory_signer_owner' THEN RAISE EXCEPTION 'database owners'; END IF;
 IF (SELECT rolcanlogin FROM pg_roles WHERE rolname='fleetory_signer_owner') THEN RAISE EXCEPTION 'owner login'; END IF;
 IF has_database_privilege('fleetory_server','fleetory_signer','CONNECT') OR has_database_privilege('fleetory_server','keycloak','CONNECT') OR has_database_privilege('fleetory_signer','fleetory','CONNECT') THEN RAISE EXCEPTION 'cross database'; END IF;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['platform.audit_events','platform.authorization_role_versions','platform.authorization_scope_versions'] LOOP
  IF NOT has_table_privilege('fleetory_server',t,'SELECT') OR NOT has_table_privilege('fleetory_server',t,'INSERT') OR has_table_privilege('fleetory_server',t,'UPDATE') OR has_table_privilege('fleetory_server',t,'DELETE') OR has_table_privilege('fleetory_server',t,'TRUNCATE') THEN RAISE EXCEPTION 'append-only'; END IF;
 END LOOP;
 FOREACH t IN ARRAY ARRAY['platform.admin_certificate_registrations','platform.admin_certificate_revocations','platform."__EFMigrationsHistory"','core."__EFMigrationsHistory"'] LOOP
  IF NOT has_table_privilege('fleetory_server',t,'SELECT') OR has_table_privilege('fleetory_server',t,'INSERT') OR has_table_privilege('fleetory_server',t,'UPDATE') OR has_table_privilege('fleetory_server',t,'DELETE') THEN RAISE EXCEPTION 'read-only'; END IF;
 END LOOP;
END $$;
'@
    Invoke-DisposableSql fleetory_signer @'
DO $$ DECLARE t text; BEGIN
 IF has_database_privilege('fleetory_signer','fleetory_signer','CREATE') OR has_database_privilege('fleetory_signer','fleetory_signer','TEMP') OR has_schema_privilege('fleetory_signer','signer','CREATE') THEN RAISE EXCEPTION 'create'; END IF;
 IF EXISTS (SELECT FROM pg_tables WHERE schemaname='signer' AND tableowner<>'fleetory_signer_owner') THEN RAISE EXCEPTION 'owner'; END IF;
 FOREACH t IN ARRAY ARRAY['signer.signing_requests','signer.signing_results','signer.signing_rejections'] LOOP
  IF NOT has_table_privilege('fleetory_signer',t,'SELECT') OR NOT has_table_privilege('fleetory_signer',t,'INSERT') OR has_table_privilege('fleetory_signer',t,'UPDATE') OR has_table_privilege('fleetory_signer',t,'DELETE') OR has_table_privilege('fleetory_signer',t,'TRUNCATE') OR has_table_privilege('fleetory_signer',t,'REFERENCES') OR has_table_privilege('fleetory_signer',t,'TRIGGER') THEN RAISE EXCEPTION 'journal grants'; END IF;
 END LOOP;
 IF NOT has_table_privilege('fleetory_signer','signer.client_certificate_revocations','SELECT') OR has_table_privilege('fleetory_signer','signer.client_certificate_revocations','INSERT') OR has_table_privilege('fleetory_signer','signer.client_certificate_revocations','UPDATE') OR has_table_privilege('fleetory_signer','signer.client_certificate_revocations','DELETE') THEN RAISE EXCEPTION 'denylist'; END IF;
END $$;
'@
    Write-Output 'Pilot provisioning regression PASS: disposable PKI, negative inputs, actual EF exports, fresh PostgreSQL and runtime grants.'
} finally {
    [Environment]::SetEnvironmentVariable('FLEETORY_MIGRATION_CONNECTION_STRING',$oldMigrationConnection)
    foreach ($resource in $resources) { $resource.Dispose() }
    if ($containerId -cmatch '\A[0-9a-f]{64}\z') { $captured = & docker rm --force --volumes $containerId 2>&1 }
    $resolvedWork = [IO.Path]::GetFullPath($work)
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    $tempPrefix = $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedWork.StartsWith($tempPrefix,$comparison) -or [IO.Path]::GetFileName($resolvedWork) -notmatch '^fleetory-pilot-test-[0-9a-f]{32}$') { throw 'Refusing unsafe temporary cleanup.' }
    if (Test-Path -LiteralPath $resolvedWork) {
        if ((Get-Item -LiteralPath $resolvedWork).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing linked temporary cleanup.' }
        Remove-Item -LiteralPath $resolvedWork -Recurse -Force
    }
}
