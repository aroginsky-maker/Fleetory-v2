#requires -Version 7.3
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BackupPath,
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedManifestSha256,
    [string]$PythonExecutable='python3'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$containerId=$null
$dumpBytes=$null
$manifestDocument=$null
$inventoryDocument=$null
$failed=$false
$result=$null
$stage='input'
$failureLine=0
$invariantNames=@('ownerEnabled','ownerRequiredActionsClear','passwordCredentialPresent','webauthnCredentialPresent','realmSigningPrivateKeyPresent','clientConfigurationValid','tokenMappersPresent')
$exclusions=@('roles','ACLs','nonMVCCSequences','externalHSM','postRestoreHumanLogin')

function Assert-SafeFile([string]$Path) {
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or -not [IO.File]::Exists($Path)) {throw 'Invalid input.'}
    $item=[IO.FileInfo]::new([IO.Path]::GetFullPath($Path))
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Linked input.'}
    $parent=$item.Directory
    while ($null -ne $parent) {
        if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Test-Path -LiteralPath (Join-Path $parent.FullName '.git'))) {throw 'Unsafe input ancestry.'}
        $parent=$parent.Parent
    }
    foreach ($protected in @($item.FullName,$item.DirectoryName)) {
        if ($IsWindows) {
            $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
            $acl=Get-Acl -LiteralPath $protected
            $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($owner -notin $allowed) {throw 'Untrusted input owner.'}
            # Python's private DACL uses OWNER RIGHTS, equivalent to its verified owner.
            $allowed+='S-1-3-4'
            foreach ($rule in $acl.Access) {
                if ($rule.AccessControlType -eq 'Allow' -and
                    $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed) {throw 'Broad input ACL.'}
            }
        } elseif (([int][IO.File]::GetUnixFileMode($protected) -band 63) -ne 0) {throw 'Broad input permissions.'}
    }
}
function Read-Bounded([string]$Path,[int]$Limit) {
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $buffer=[IO.MemoryStream]::new()
    try {
        $chunk=[byte[]]::new(8192)
        while (($read=$stream.Read($chunk,0,$chunk.Length)) -gt 0) {
            if ($buffer.Length+$read -gt $Limit) {throw 'Input too large.'}
            $buffer.Write($chunk,0,$read)
        }
        return ,$buffer.ToArray()
    } finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($buffer.GetBuffer())
        $buffer.Dispose();$stream.Dispose()
    }
}
function Test-Hash([string]$Left,[string]$Right) {
    if ($Left -notmatch '^[0-9a-fA-F]{64}$' -or $Right -notmatch '^[0-9a-fA-F]{64}$') {return $false}
    return [Security.Cryptography.CryptographicOperations]::FixedTimeEquals([Convert]::FromHexString($Left),[Convert]::FromHexString($Right))
}
function Assert-UniqueJson([System.Text.Json.JsonElement]$Element) {
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {throw 'Duplicate JSON property.'}
            Assert-UniqueJson $property.Value
        }
    } elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($entry in $Element.EnumerateArray()) {Assert-UniqueJson $entry}
    }
}
function Assert-Fields([System.Text.Json.JsonElement]$Element,[string[]]$Names) {
    if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {throw 'Invalid object.'}
    $actual=@($Element.EnumerateObject() | ForEach-Object Name)
    if ($actual.Count -ne $Names.Count -or @($actual | Where-Object {$_ -cnotin $Names}).Count) {throw 'Unexpected fields.'}
}
function Assert-Inventory([System.Text.Json.JsonElement]$Element,[bool]$IsManifest) {
    $fields=@('schema','inventoryAlgorithm','realm','owner','postgresMajor','inventorySha256','tableCount','totalRows','invariants','exclusions')
    if ($IsManifest) {$fields+='dumpSha256'}
    Assert-Fields $Element $fields
    $schema=if ($IsManifest) {'fleetory.keycloak-backup.v1'} else {'fleetory.keycloak-inventory.v1'}
    if ($Element.GetProperty('schema').GetString() -cne $schema -or
        $Element.GetProperty('inventoryAlgorithm').GetString() -cne 'fleetory.keycloak-inventory.v1' -or
        $Element.GetProperty('realm').GetString() -cnotmatch '^[A-Za-z0-9_-]{1,64}$' -or
        $Element.GetProperty('owner').GetString() -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
        [Guid]::Parse($Element.GetProperty('owner').GetString()) -eq [Guid]::Empty -or
        $Element.GetProperty('postgresMajor').GetInt32() -ne 18 -or
        $Element.GetProperty('inventorySha256').GetString() -notmatch '^[A-Fa-f0-9]{64}$' -or
        $Element.GetProperty('tableCount').GetInt64() -lt 1 -or $Element.GetProperty('tableCount').GetInt64() -gt 512 -or
        $Element.GetProperty('totalRows').GetInt64() -lt 0 -or $Element.GetProperty('totalRows').GetInt64() -gt 1000000) {throw 'Invalid inventory metadata.'}
    if ($IsManifest -and $Element.GetProperty('dumpSha256').GetString() -notmatch '^[A-Fa-f0-9]{64}$') {throw 'Invalid dump digest.'}
    $invariants=$Element.GetProperty('invariants')
    Assert-Fields $invariants $invariantNames
    foreach ($name in $invariantNames) {
        if ($invariants.GetProperty($name).ValueKind -ne [System.Text.Json.JsonValueKind]::True) {throw 'Unverified identity invariant.'}
    }
    $excluded=$Element.GetProperty('exclusions')
    if ($excluded.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $excluded.GetArrayLength() -ne $exclusions.Count) {throw 'Missing exclusions.'}
    $remaining=[Collections.Generic.HashSet[string]]::new([string[]]$exclusions,[StringComparer]::Ordinal)
    foreach ($entry in $excluded.EnumerateArray()) {if (-not $remaining.Remove($entry.GetString())) {throw 'Invalid exclusion.'}}
}
function Invoke-OwnDocker([string[]]$Arguments,[int]$TimeoutSeconds=30) {
    $start=[Diagnostics.ProcessStartInfo]::new('docker')
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    foreach ($arg in $Arguments) {$start.ArgumentList.Add($arg)}
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    try {
        $null=$process.Start();$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds*1000)) {$process.Kill($true);throw 'Disposable Docker timeout.'}
        $output=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {throw 'Disposable Docker operation failed.'}
        return $output.TrimEnd()
    } finally {$process.Dispose()}
}
try {
    Assert-SafeFile $BackupPath
    Assert-SafeFile $ManifestPath
    $stage='manifest-hash'
    $manifestBytes=Read-Bounded $ManifestPath 65536
    $manifestHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($manifestBytes))
    if (-not (Test-Hash $manifestHash $ExpectedManifestSha256)) {throw 'Manifest digest mismatch.'}
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $manifestText=$utf8.GetString($manifestBytes).TrimStart([char]0xFEFF)
    $jsonOptions=[System.Text.Json.JsonDocumentOptions]::new();$jsonOptions.MaxDepth=16
    $manifestDocument=[System.Text.Json.JsonDocument]::Parse($manifestText,$jsonOptions)
    $manifest=$manifestDocument.RootElement
    $stage='manifest-schema'
    Assert-UniqueJson $manifest
    Assert-Inventory $manifest $true
    $stage='backup-hash'
    $dumpBytes=Read-Bounded $BackupPath 67108864
    if ($dumpBytes.Length -lt 5 -or [Text.Encoding]::ASCII.GetString($dumpBytes,0,5) -cne 'PGDMP') {throw 'Expected custom PostgreSQL archive.'}
    $dumpHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($dumpBytes))
    if (-not (Test-Hash $dumpHash $manifest.GetProperty('dumpSha256').GetString())) {throw 'Backup digest mismatch.'}

    $stage='container'
    $runArgs=@('run','--detach','--network','none','--read-only','--user','999:999','--cap-drop','ALL',
        '--security-opt','no-new-privileges:true','--pids-limit','128','--memory','768m','--cpus','1',
        '--tmpfs','/var/lib/postgresql:rw,noexec,nosuid,nodev,uid=999,gid=999,mode=0700,size=512m',
        '--tmpfs','/var/run/postgresql:rw,noexec,nosuid,nodev,uid=999,gid=999,mode=0700,size=16m',
        '--tmpfs','/tmp:rw,noexec,nosuid,nodev,uid=999,gid=999,mode=0700,size=160m',
        '--env','POSTGRES_HOST_AUTH_METHOD=trust',
        'postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336',
        'postgres','-c','listen_addresses=','-c','unix_socket_directories=/var/run/postgresql')
    $containerId=(Invoke-OwnDocker $runArgs).Trim()
    if ($containerId -cnotmatch '^[0-9a-f]{64}$') {throw 'Invalid new container identity.'}
    $stage='readiness'
    $ready=$false
    for ($attempt=0;$attempt -lt 30;$attempt++) {
        $captured=& docker exec $containerId pg_isready -U postgres 2>&1
        if ($LASTEXITCODE -eq 0) {$ready=$true;break}
        Start-Sleep -Seconds 1
    }
    if (-not $ready) {throw 'Disposable PostgreSQL unavailable.'}
    $stage='roles'
    $null=Invoke-OwnDocker @('exec',$containerId,'psql','-X','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-q','-c',
        'CREATE ROLE restore_owner LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;')
    $null=Invoke-OwnDocker @('exec',$containerId,'psql','-X','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-q','-c',
        'CREATE DATABASE keycloak_restore OWNER restore_owner;')

    # Transfer exactly the hashed retained bytes into the owned tmpfs. Docker's
    # archive-copy API cannot write this read-only-root profile on every engine.
    # The command is static; no input value is interpolated into shell code.
    $stage='archive-copy'
    $start=[Diagnostics.ProcessStartInfo]::new('docker')
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    foreach ($arg in @('exec','-i','--user','999:999',$containerId,'sh','-c','umask 077; cat > /tmp/identity.dump')) {$start.ArgumentList.Add($arg)}
    $copy=[Diagnostics.Process]::new();$copy.StartInfo=$start
    try {
        $null=$copy.Start();$stdout=$copy.StandardOutput.ReadToEndAsync();$stderr=$copy.StandardError.ReadToEndAsync()
        if (-not $copy.StandardInput.BaseStream.WriteAsync($dumpBytes,0,$dumpBytes.Length).Wait(30000)) {$copy.Kill($true);throw 'Archive write timeout.'}
        $copy.StandardInput.Close()
        if (-not $copy.WaitForExit(30000)) {$copy.Kill($true);throw 'Archive copy timeout.'}
        $null=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
        if ($copy.ExitCode -ne 0) {throw 'Archive transfer failed.'}
    } finally {$copy.Dispose()}
    $stage='archive-permissions'
    if ((Invoke-OwnDocker @('exec',$containerId,'stat','-c','%u:%g:%a','/tmp/identity.dump')).Trim() -cne '999:999:600') {throw 'Unsafe archive permissions.'}
    $stage='pg-restore'
    $null=Invoke-OwnDocker @('exec','--env','PGOPTIONS=-c statement_timeout=30000 -c lock_timeout=5000',$containerId,
        'pg_restore','-U','restore_owner','--dbname=keycloak_restore',
        '--no-owner','--no-privileges','--exit-on-error','--single-transaction','/tmp/identity.dump') 120
    $pythonPath=Join-Path $PSScriptRoot 'identity_backup.py'
    $stage='inventory'
    $inventoryOutput=& $PythonExecutable $pythonPath inventory --container $containerId --database keycloak_restore --db-user restore_owner `
        --realm $manifest.GetProperty('realm').GetString() --owner $manifest.GetProperty('owner').GetString() 2>&1
    if ($LASTEXITCODE -ne 0) {throw 'Restored inventory failed.'}
    $inventoryText=$inventoryOutput -join "`n"
    if ([Text.Encoding]::UTF8.GetByteCount($inventoryText) -gt 65536) {throw 'Oversized restored inventory.'}
    $inventoryDocument=[System.Text.Json.JsonDocument]::Parse($inventoryText,$jsonOptions)
    $inventory=$inventoryDocument.RootElement
    $stage='inventory-schema'
    Assert-UniqueJson $inventory
    Assert-Inventory $inventory $false
    $stage='inventory-compare'
    Write-Verbose ('Identity inventory sourceTables={0} restoredTables={1} sourceRows={2} restoredRows={3}' -f
        $manifest.GetProperty('tableCount').GetInt64(),$inventory.GetProperty('tableCount').GetInt64(),
        $manifest.GetProperty('totalRows').GetInt64(),$inventory.GetProperty('totalRows').GetInt64())
    if (-not (Test-Hash $inventory.GetProperty('inventorySha256').GetString() $manifest.GetProperty('inventorySha256').GetString())) {throw 'Inventory mismatch.'}
    foreach ($name in @('realm','owner')) {if ($inventory.GetProperty($name).GetString() -cne $manifest.GetProperty($name).GetString()) {throw 'Identity mismatch.'}}
    foreach ($name in @('tableCount','totalRows')) {if ($inventory.GetProperty($name).GetInt64() -ne $manifest.GetProperty($name).GetInt64()) {throw 'Inventory count mismatch.'}}
    $result=@{schema='fleetory.keycloak-restore-verification.v1';verified=$true;manifestSha256=$manifestHash;dumpSha256=$dumpHash;
        inventorySha256=$inventory.GetProperty('inventorySha256').GetString();tableCount=$inventory.GetProperty('tableCount').GetInt64();
        totalRows=$inventory.GetProperty('totalRows').GetInt64();postRestoreHumanLoginVerified=$false;independentCustodyVerified=$false}
} catch {
    $failed=$true
    $failureLine=$_.InvocationInfo.ScriptLineNumber
    Write-Verbose "Identity verification stage=$stage line=$failureLine"
}
finally {
    if ($null -ne $inventoryDocument) {$inventoryDocument.Dispose()}
    if ($null -ne $manifestDocument) {$manifestDocument.Dispose()}
    if ($null -ne $dumpBytes) {[Security.Cryptography.CryptographicOperations]::ZeroMemory($dumpBytes)}
    if ($null -ne $containerId -and $containerId -cmatch '^[0-9a-f]{64}$') {
        try {$null=Invoke-OwnDocker @('rm','--force','--volumes',$containerId)} catch {
            $failed=$true
            Write-Verbose 'Identity verification cleanup failed.'
        }
    }
}
if ($failed) {throw "Identity backup verification failed at stage '$stage'. Sensitive diagnostics suppressed."}
$result | ConvertTo-Json -Compress
