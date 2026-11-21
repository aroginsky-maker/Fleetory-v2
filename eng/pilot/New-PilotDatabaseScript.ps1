# Generates sensitive fresh-cluster initialization SQL; never executes it.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CredentialsPath,
    [Parameter(Mandatory)][string]$PlatformMigrationPath,
    [Parameter(Mandatory)][string]$CoreMigrationPath,
    [Parameter(Mandatory)][string]$SignerSchemaPath,
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
foreach ($inputPath in @($CredentialsPath,$PlatformMigrationPath,$CoreMigrationPath,$SignerSchemaPath)) {
    if (-not [IO.Path]::IsPathFullyQualified($inputPath) -or -not [IO.File]::Exists($inputPath)) {
        throw 'All input paths must be absolute existing files.'
    }
}
if (-not [IO.Path]::IsPathFullyQualified($OutputPath)) { throw 'OutputPath must be absolute.' }
$destination = [IO.Path]::GetFullPath($OutputPath)
$parent = [IO.Path]::GetDirectoryName($destination)
if (-not [IO.Directory]::Exists($parent) -or [IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)) {
    throw 'Output requires an existing protected parent directory and a new filename.'
}
# Reject repositories, worktrees (.git files) and junction/symlink parent paths.
$ancestor = [IO.DirectoryInfo]::new($parent)
while ($null -ne $ancestor) {
    if (Test-Path -LiteralPath (Join-Path $ancestor.FullName '.git')) { throw 'Output must be outside Git.' }
    if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Output parent paths must not be links.' }
    $ancestor = $ancestor.Parent
}
try { $credentials = [IO.File]::ReadAllText($CredentialsPath,$utf8) | ConvertFrom-Json -ErrorAction Stop }
catch { throw 'Credentials must be valid UTF-8 JSON.' }
foreach ($key in @('fleetoryMigrator','fleetoryRuntime','keycloakDb','signerRuntime')) {
    $property = $credentials.PSObject.Properties[$key]
    if ($null -eq $property -or $property.Value -isnot [string] -or $property.Value -cnotmatch '\A[0-9A-F]{48}\z') {
        throw "Credential '$key' must be a 48-character uppercase hexadecimal string."
    }
}
$platform = [IO.File]::ReadAllText($PlatformMigrationPath,$utf8)
$core = [IO.File]::ReadAllText($CoreMigrationPath,$utf8)
$signer = [IO.File]::ReadAllText($SignerSchemaPath,$utf8)
if ([string]::IsNullOrWhiteSpace($platform) -or [string]::IsNullOrWhiteSpace($core) -or [string]::IsNullOrWhiteSpace($signer)) {
    throw 'Schema inputs must not be empty.'
}
$parts = [Collections.Generic.List[string]]::new()
$parts.Add(@"
-- SENSITIVE: fresh PostgreSQL cluster initialization only, executed as postgres.
-- Fails on existing roles/databases. Never resets or removes existing data.
-- Inputs are trusted reviewed EF exports and the signer schema, not arbitrary uploads.
\set ON_ERROR_STOP on
\connect postgres
CREATE ROLE fleetory_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$($credentials.fleetoryMigrator)';
CREATE ROLE fleetory_server LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$($credentials.fleetoryRuntime)';
CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$($credentials.keycloakDb)';
CREATE ROLE fleetory_signer_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE fleetory_signer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$($credentials.signerRuntime)';
CREATE DATABASE fleetory OWNER fleetory_migrator;
CREATE DATABASE keycloak OWNER keycloak;
CREATE DATABASE fleetory_signer OWNER fleetory_signer_owner;
REVOKE ALL ON DATABASE fleetory, keycloak, fleetory_signer FROM PUBLIC;
GRANT CONNECT ON DATABASE fleetory TO fleetory_migrator, fleetory_server;
GRANT CONNECT ON DATABASE keycloak TO keycloak;
GRANT CONNECT ON DATABASE fleetory_signer TO fleetory_signer;
\connect keycloak
REVOKE ALL ON SCHEMA public FROM PUBLIC;
\connect fleetory
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SET ROLE fleetory_migrator;
"@)
$parts.Add($platform)
$parts.Add($core)
$parts.Add(@'
RESET ROLE;
REVOKE ALL ON SCHEMA platform, core FROM PUBLIC;
GRANT USAGE ON SCHEMA platform, core TO fleetory_server;
-- No default grants: review future migrations before expanding runtime access.
DO $runtime_grants$
DECLARE target record;
BEGIN
    FOR target IN SELECT schemaname, tablename FROM pg_tables
                  WHERE schemaname IN ('platform','core') LOOP
        IF target.tablename = '__EFMigrationsHistory' THEN
            EXECUTE format('GRANT SELECT ON TABLE %I.%I TO fleetory_server', target.schemaname, target.tablename);
        ELSIF target.schemaname = 'platform' AND target.tablename IN
              ('admin_certificate_registrations', 'admin_certificate_revocations') THEN
            -- Enrollment/rotation/revocation are separate operator SQL operations.
            EXECUTE format('GRANT SELECT ON TABLE %I.%I TO fleetory_server', target.schemaname, target.tablename);
        ELSIF target.schemaname = 'platform' AND target.tablename IN
              ('audit_events', 'authorization_role_versions', 'authorization_scope_versions') THEN
            -- Runtime may append evidence but cannot rewrite or remove it.
            EXECUTE format('GRANT SELECT, INSERT ON TABLE %I.%I TO fleetory_server', target.schemaname, target.tablename);
        ELSE
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO fleetory_server', target.schemaname, target.tablename);
        END IF;
    END LOOP;
END
$runtime_grants$;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA platform, core TO fleetory_server;
\connect fleetory_signer
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SET ROLE fleetory_signer_owner;
'@)
$parts.Add($signer)
$parts.Add(@'
RESET ROLE;
REVOKE ALL ON SCHEMA signer FROM PUBLIC;
GRANT USAGE ON SCHEMA signer TO fleetory_signer;
GRANT SELECT, INSERT ON signer.signing_requests, signer.signing_results, signer.signing_rejections TO fleetory_signer;
GRANT SELECT ON signer.client_certificate_revocations TO fleetory_signer;
-- No runtime ownership, role memberships, schema CREATE, TEMP or journal mutations.
'@)
$sql = (($parts -join "`n") -replace "`r`n", "`n") -replace "`r", "`n"
$bytes = $utf8.GetBytes($sql + "`n")
# CreateNew closes the overwrite race. Caller provisions private parent ACL/mode.
$stream = [IO.FileStream]::new($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
finally { $stream.Dispose(); [Array]::Clear($bytes,0,$bytes.Length) }
# Intentionally emit neither credentials nor generated SQL.
