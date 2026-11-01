#requires -Version 7.3
# Disposable live Keycloak/PostgreSQL identity snapshot and restore contract.
# The WebAuthn row below is opaque fixture data only and is never an authentication assertion.
param([string] $PythonExecutable = 'python3')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$captureTool = Join-Path $repoRoot 'eng/pilot/identity_backup.py'
$verifier = Join-Path $repoRoot 'eng/pilot/Test-IdentityBackup.ps1'
$postgresImage = 'postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336'
$keycloakImage = 'quay.io/keycloak/keycloak:26.8.0@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741'
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$work = Join-Path $tempRoot ('fleetory-identity-backup-' + [Guid]::NewGuid().ToString('N'))
$network = 'fleetory-identity-' + [Guid]::NewGuid().ToString('N')
$postgresName = 'fleetory-id-pg-' + [Guid]::NewGuid().ToString('N')
$keycloakName = 'fleetory-id-kc-' + [Guid]::NewGuid().ToString('N')
$containers = [Collections.Generic.List[string]]::new()
$captureDirectories = [Collections.Generic.List[string]]::new()
$networkCreated = $false
$stage = 'preflight'
$safeDetail = ''

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-Docker([string[]] $Arguments) {
    $output = & docker @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) {
        if ($Arguments[0] -eq 'port') {
            $metadata = & docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{json .HostConfig.PortBindings}}|{{json .NetworkSettings.Ports}}' $Arguments[1] 2>$null
            $script:safeDetail = "Docker port command exit: $LASTEXITCODE; container metadata: $(@($metadata) -join ' ')."
        }
        throw 'Disposable identity-backup fixture operation failed.'
    }
    return (@($output) -join "`n").Trim()
}

function Invoke-Python([string[]] $Arguments) {
    $output = & $PythonExecutable @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Identity backup helper rejected the disposable fixture.' }
    return (@($output) -join "`n").Trim()
}

function Assert-HelperRejects([string[]] $Arguments, [string] $Message) {
    & $PythonExecutable $captureTool @Arguments 2>$null | Out-Null
    Assert-True ($LASTEXITCODE -ne 0) $Message
}

function Get-CaptureDirectoryNames {
    return @((Get-ChildItem -LiteralPath $tempRoot -Directory -Filter 'fleetory-identity-capture-*' -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name) | Sort-Object -Unique)
}

function Assert-NoNewCaptureDirectory([string[]] $Before, [string] $Message) {
    $after = Get-CaptureDirectoryNames
    $newPaths = @($after | Where-Object { $_ -notin $Before })
    Assert-True ($newPaths.Count -eq 0) $Message
}

function Register-Capture([object] $Result) {
    $directory = [string]$Result.outputDirectory
    if (-not [IO.Path]::IsPathFullyQualified($directory)) { throw 'Capture output path is invalid.' }
    $full = [IO.Path]::GetFullPath($directory)
    $tempPrefix = $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($tempPrefix,[StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFileName($full).StartsWith('fleetory-identity-capture-',[StringComparison]::Ordinal) -or
        -not (Test-Path -LiteralPath $full -PathType Container) -or
        ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Capture output directory is outside the fixture temp root.'
    }
    $cursor = Get-Item -LiteralPath $full -Force
    $tempFull = $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Capture output ancestry contains a link.'
        }
        if ([IO.Path]::GetFullPath($cursor.FullName).TrimEnd([IO.Path]::DirectorySeparatorChar) -ceq $tempFull) { break }
        $cursor = $cursor.Parent
    }
    if ($null -eq $cursor) { throw 'Capture output ancestry did not reach the temp root.' }
    $entries = @(Get-ChildItem -LiteralPath $full -Force | Select-Object -ExpandProperty Name | Sort-Object)
    if ($entries.Count -ne 2 -or $entries[0] -cne 'database.dump' -or $entries[1] -cne 'manifest.json') {
        throw 'Capture output directory contains unexpected files.'
    }
    $captureDirectories.Add($full)
    return $full
}

function New-PrivateDirectory([string] $Path) {
    New-Item -ItemType Directory -Path $Path | Out-Null
    if ([System.OperatingSystem]::IsWindows()) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls $Path /inheritance:r /grant:r "*$($identity):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not protect the disposable test directory.' }
    }
    else { [IO.File]::SetUnixFileMode($Path, [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute) }
}

function New-RandomText([int] $Bytes = 32) {
    return [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes($Bytes)).ToLowerInvariant()
}

function Get-FreeLoopbackPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try { $listener.Start(); return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Invoke-KeycloakApi([string] $Method, [string] $Path, [string] $Token, $Body = $null) {
    $request = @{ Method = $Method; Uri = "$script:keycloakOrigin$Path"; TimeoutSec = 20; SkipHttpErrorCheck = $true; NoProxy = $true }
    if ($Token) { $request.Headers = @{ Authorization = "Bearer $Token" } }
    if ($null -ne $Body) {
        $request.ContentType = 'application/json'
        $request.Body = $Body | ConvertTo-Json -Depth 16 -Compress
    }
    try { return Invoke-WebRequest @request }
    catch { throw 'Keycloak fixture API request failed.' }
}

function Save-Private([string] $Directory, [string] $Name, [byte[]] $Bytes) {
    $path = Join-Path $Directory $Name
    [IO.File]::WriteAllBytes($path, $Bytes)
    if (-not [OperatingSystem]::IsWindows()) {
        [IO.File]::SetUnixFileMode($path, [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
    }
    return $path
}

function Copy-Backup([string] $Name) {
    $directory = Join-Path $work $Name
    New-PrivateDirectory $directory
    $dumpPath = Save-Private $directory 'database.dump' ([IO.File]::ReadAllBytes($backupDump))
    $manifestPath = Save-Private $directory 'manifest.json' ([IO.File]::ReadAllBytes($backupManifest))
    return @{ Directory = $directory; Dump = $dumpPath; Manifest = $manifestPath }
}

function Invoke-Verifier([hashtable] $Files, [string] $ManifestHash) {
    $result = $null
    try {
        $result = & $verifier -BackupPath $Files.Dump `
            -ManifestPath $Files.Manifest -ExpectedManifestSha256 $ManifestHash `
            -PythonExecutable $PythonExecutable -Verbose
    }
    catch {
        $script:safeDetail = $_.Exception.Message
        throw 'Positive restore verification failed.'
    }
    $verification = ($result -join "`n") | ConvertFrom-Json
    if ($verification.schema -cne 'fleetory.keycloak-restore-verification.v1' -or -not $verification.verified -or
        $verification.inventorySha256 -cne $capture.inventorySha256 -or
        $verification.postRestoreHumanLoginVerified -ne $false -or $verification.independentCustodyVerified -ne $false) {
        $script:safeDetail = 'Restore result contract fields did not match the captured inventory.'
        throw 'Positive restore result mismatch.'
    }
}

function Remove-CaptureDirectory([string] $Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $tempPrefix = $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($tempPrefix,[StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFileName($full).StartsWith('fleetory-identity-capture-',[StringComparison]::Ordinal) -or
        -not (Test-Path -LiteralPath $full -PathType Container) -or
        ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Refusing to clean an unexpected capture directory.'
    }
    $cursor = Get-Item -LiteralPath $full -Force
    $tempFull = $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Refusing to clean a linked capture ancestry.'
        }
        if ([IO.Path]::GetFullPath($cursor.FullName).TrimEnd([IO.Path]::DirectorySeparatorChar) -ceq $tempFull) { break }
        $cursor = $cursor.Parent
    }
    if ($null -eq $cursor) { throw 'Refusing to clean outside the temp root.' }
    foreach ($name in @('database.dump','manifest.json')) {
        $file = Join-Path $full $name
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            if (((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Refusing to clean linked capture material.'
            }
            Remove-Item -LiteralPath $file -Force
        }
    }
    if (@(Get-ChildItem -LiteralPath $full -Force).Count -ne 0) {
        throw 'Refusing to clean a capture directory with unexpected entries.'
    }
    Remove-Item -LiteralPath $full -Force
}

function Assert-VerifierRejects([hashtable] $Files, [string] $ManifestHash, [string] $ExpectedStage, [string] $Message) {
    $rejected = $false
    try {
        & $verifier -BackupPath $Files.Dump `
            -ManifestPath $Files.Manifest -ExpectedManifestSha256 $ManifestHash `
            -PythonExecutable $PythonExecutable -Verbose 4>$null | Out-Null
    }
    catch {
        $stageMatch = [regex]::Match($_.Exception.Message, "at stage '([^']+)'")
        $rejected = $stageMatch.Success -and $stageMatch.Groups[1].Value -ceq $ExpectedStage
    }
    Assert-True $rejected $Message
}

function Set-Manifest([hashtable] $Files, [scriptblock] $Mutation) {
    $manifest = [IO.File]::ReadAllText($backupManifest) | ConvertFrom-Json -AsHashtable
    & $Mutation $manifest
    $json = ($manifest | ConvertTo-Json -Depth 16 -Compress) + "`n"
    [IO.File]::WriteAllText($Files.Manifest, $json, [Text.UTF8Encoding]::new($false))
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($json))).ToLowerInvariant()
}

$bootstrapPassword = New-RandomText
$databasePassword = New-RandomText
$ownerPassword = New-RandomText
$ownerId = $null
$sessionId = [Guid]::NewGuid().ToString('D').ToLowerInvariant()
$webAuthnId = New-RandomText 18

try {
    $pythonVersion = Invoke-Python @('-c', 'import sys;print("%d.%d"%sys.version_info[:2])')
    $version = [version]$pythonVersion
    Assert-True ($version -ge [version]'3.11') 'Python 3.11 or later is required.'
    Assert-True (Test-Path -LiteralPath $captureTool -PathType Leaf) 'Identity backup capture helper is missing.'
    Assert-True (Test-Path -LiteralPath $verifier -PathType Leaf) 'Identity backup verifier is missing.'

    $stage = 'isolated Docker network'
    New-PrivateDirectory $work
    Invoke-Docker @('network','create',$network) | Out-Null
    $networkCreated = $true
    $postgresId = Invoke-Docker @('run','-d','--name',$postgresName,'--network',$network,
        '--network-alias','postgres','--memory','384m','--cpus','1','--pids-limit','128',
        '--label','com.fleetory.identity-backup.role=fixture-source',
        '--label',"com.fleetory.identity-backup.session=$sessionId",
        '-e','POSTGRES_USER=postgres','-e',"POSTGRES_PASSWORD=$databasePassword",
        '-e','POSTGRES_DB=keycloak',$postgresImage)
    $containers.Add($postgresId)
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            Invoke-Docker @('exec',$postgresId,'pg_isready','-U','postgres','-d','keycloak') | Out-Null
            $ready = $true
            break
        }
        catch { Start-Sleep -Seconds 1 }
    }
    Assert-True $ready 'Disposable PostgreSQL did not become ready.'

    $stage = 'Keycloak startup'
    $hostPort = Get-FreeLoopbackPort
    $keycloakId = Invoke-Docker @('run','-d','--name',$keycloakName,'--network',$network,
        '--memory','768m','--cpus','1','--pids-limit','256',
        '-p',"127.0.0.1:$($hostPort):8080",'-e','KC_DB=postgres','-e','KC_DB_URL_HOST=postgres',
        '-e','KC_DB_URL_DATABASE=keycloak','-e','KC_DB_USERNAME=postgres','-e',"KC_DB_PASSWORD=$databasePassword",
        '-e','KC_HEALTH_ENABLED=true','-e','KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin',
        '-e',"KC_BOOTSTRAP_ADMIN_PASSWORD=$bootstrapPassword",$keycloakImage,'start-dev')
    $containers.Add($keycloakId)
    $stage = 'Keycloak loopback publication'
    $published = Invoke-Docker @('port',$keycloakId,'8080/tcp')
    $match = [regex]::Match($published,'^127\.0\.0\.1:(\d+)$')
    if (-not $match.Success) {
        $safeDetail = "Unexpected port mapping: $published"
        throw 'Keycloak loopback publication failed.'
    }
    $script:keycloakOrigin = "http://127.0.0.1:$($match.Groups[1].Value)"
    $stage = 'Keycloak readiness'
    $healthy = $false
    for ($attempt = 0; $attempt -lt 180; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri "$keycloakOrigin/realms/master/.well-known/openid-configuration" `
                -TimeoutSec 2 -SkipHttpErrorCheck -NoProxy
            if ($response.StatusCode -eq 200) { $healthy = $true; break }
            Start-Sleep -Seconds 1
        }
        catch { Start-Sleep -Seconds 1 }
    }
    Assert-True $healthy 'Disposable Keycloak did not become ready.'

    $stage = 'Keycloak admin API fixture provisioning'
    $adminResponse = Invoke-WebRequest -Method Post -Uri "$keycloakOrigin/realms/master/protocol/openid-connect/token" `
        -ContentType 'application/x-www-form-urlencoded' -Body @{ grant_type='password'; client_id='admin-cli';
            username='fixture-admin'; password=$bootstrapPassword } -TimeoutSec 15 -SkipHttpErrorCheck -NoProxy
    Assert-True ($adminResponse.StatusCode -eq 200) 'Disposable Keycloak admin API authentication failed.'
    $adminToken = ($adminResponse.Content | ConvertFrom-Json).access_token
    Assert-True (-not [string]::IsNullOrWhiteSpace($adminToken)) 'Keycloak returned no operator token.'

    $created = Invoke-KeycloakApi 'Post' '/admin/realms' $adminToken @{ realm='fleetory'; enabled=$true }
    Assert-True ($created.StatusCode -eq 201) 'Could not create the disposable realm.'
    $owner = @{ username='fixture-owner'; enabled=$true; requiredActions=@();
        credentials=@(@{ type='password'; value=$ownerPassword; temporary=$false }) }
    $created = Invoke-KeycloakApi 'Post' '/admin/realms/fleetory/users' $adminToken $owner
    Assert-True ($created.StatusCode -eq 201) 'Could not create the enabled fixture owner.'
    $owners = (Invoke-KeycloakApi 'Get' '/admin/realms/fleetory/users?username=fixture-owner&exact=true' $adminToken).Content | ConvertFrom-Json
    $parsedOwnerId = [Guid]::Empty
    Assert-True (@($owners).Count -eq 1 -and
        [Guid]::TryParseExact($owners[0].id, 'D', [ref]$parsedOwnerId) -and
        $parsedOwnerId -ne [Guid]::Empty) 'Could not read the generated fixture owner ID.'
    $ownerId = ([Guid]$owners[0].id).ToString('D').ToLowerInvariant()

    $client = @{ clientId='fleetory-pilot'; enabled=$true; publicClient=$true; standardFlowEnabled=$true;
        directAccessGrantsEnabled=$false; implicitFlowEnabled=$false; serviceAccountsEnabled=$false;
        webOrigins=@(); redirectUris=@('http://127.0.0.1:48329/auth/callback');
        attributes=@{ 'pkce.code.challenge.method'='S256' } }
    $created = Invoke-KeycloakApi 'Post' '/admin/realms/fleetory/clients' $adminToken $client
    Assert-True ($created.StatusCode -eq 201) 'Could not create the PKCE fixture client.'
    $clientId = (Invoke-KeycloakApi 'Get' '/admin/realms/fleetory/clients?clientId=fleetory-pilot' $adminToken).Content |
        ConvertFrom-Json | Select-Object -First 1 -ExpandProperty id
    Assert-True (-not [string]::IsNullOrWhiteSpace($clientId)) 'Could not find the fixture client.'
    $mapperPath = "/admin/realms/fleetory/clients/$clientId/protocol-mappers/models"
    foreach ($mapper in @(
        @{ name='fleetory-admin-api-audience'; protocol='openid-connect'; protocolMapper='oidc-audience-mapper';
            config=@{ 'included.custom.audience'='fleetory-admin-api'; 'access.token.claim'='true'; 'id.token.claim'='false' } },
        @{ name='fleetory-authentication-methods'; protocol='openid-connect'; protocolMapper='oidc-amr-mapper';
            config=@{ 'access.token.claim'='true'; 'id.token.claim'='false' } }
    )) {
        $created = Invoke-KeycloakApi 'Post' $mapperPath $adminToken $mapper
        Assert-True ($created.StatusCode -eq 201) 'Could not install the fixture token mapper.'
    }

    $stage = 'actual realm key generation'
    # Force actual realm key generation; private-key presence is later inspected in PostgreSQL.
    $null = Invoke-WebRequest -Uri "$keycloakOrigin/realms/fleetory/protocol/openid-connect/certs" -TimeoutSec 20 -NoProxy
    Invoke-Docker @('stop',$keycloakId) | Out-Null

    $stage = 'opaque credential row seed'
    $ownerRequired = (& docker exec -u postgres $postgresId psql -XqAt -U postgres -d keycloak -v ON_ERROR_STOP=1 `
        -c "SELECT count(*) FROM public.user_required_action WHERE user_id='$ownerId'" 2>$null)
    if ($LASTEXITCODE -ne 0 -or $ownerRequired.Trim() -ne '0') { throw 'Fixture owner has required actions.' }
    $columns = Invoke-Docker @('exec','-u','postgres',$postgresId,'psql','-XqAt','-U','postgres','-d','keycloak',
        '-c',"SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='credential' ORDER BY ordinal_position")
    Assert-True ($columns -match 'credential_data' -and $columns -match 'secret_data' -and $columns -match 'user_id') 'Keycloak credential schema is unexpected.'
    Invoke-Docker @('exec','-u','postgres',$postgresId,'psql','-XqAt','-U','postgres','-d','keycloak',
        '-v','ON_ERROR_STOP=1','-c','CREATE TABLE public.fixture_probe (first_col text, fixture_drop_me text, later_col text); ALTER TABLE public.fixture_probe DROP COLUMN fixture_drop_me;') | Out-Null
    $hasLogicalColumnGap = Invoke-Docker @('exec','-u','postgres',$postgresId,'psql','-XqAt','-U','postgres','-d','keycloak',
        '-v','ON_ERROR_STOP=1','-c',"SELECT max(attnum)>count(*) FROM pg_attribute WHERE attrelid='public.fixture_probe'::regclass AND attnum>0 AND NOT attisdropped")
    Assert-True ($hasLogicalColumnGap -eq 't') 'The fixture did not retain a dropped middle-column slot.'
    $credential = @{ credentialId=$webAuthnId; type='public-key'; algorithm='ES256';
        userHandle=$ownerId; counter='0'; aaguid='fixture-only-opaque-data' } | ConvertTo-Json -Compress
    $secret = @{ fixtureOnly=(New-RandomText 24) } | ConvertTo-Json -Compress
    $credentialJson = $credential.Replace("'","''")
    $secretJson = $secret.Replace("'","''")
    $seedSql = "INSERT INTO public.credential(id,type,user_id,created_date,user_label,secret_data,credential_data,priority) VALUES ('$webAuthnId','webauthn','$ownerId',0,'fixture-only','$secretJson','$credentialJson',0)"
    Invoke-Docker @('exec','-u','postgres',$postgresId,'psql','-XqAt','-U','postgres','-d','keycloak',
        '-v','ON_ERROR_STOP=1','-c',$seedSql) | Out-Null

    $stage = 'actual database capture'
    $captureDirectoriesBeforeNegativeChecks = Get-CaptureDirectoryNames
    $traversalOption = Join-Path (Join-Path $work '..') ('rejected-traversal-' + $sessionId)
    $traversalTarget = [IO.Path]::GetFullPath($traversalOption)
    $absoluteTarget = Join-Path $work 'rejected-absolute-target'
    Assert-HelperRejects @('capture','--target','fixture','--session',$sessionId,'--owner',$ownerId,
        '--output-directory',$traversalOption) 'Caller-supplied traversal output option was accepted.'
    Assert-True (-not (Test-Path -LiteralPath $traversalTarget)) 'Traversal output option created a path.'
    Assert-HelperRejects @('capture','--target','fixture','--session',$sessionId,'--owner',$ownerId,
        '--output-directory',$absoluteTarget) 'Caller-supplied absolute output option was accepted.'
    Assert-True (-not (Test-Path -LiteralPath $absoluteTarget)) 'Absolute output option created a path.'
    foreach ($option in @('--container','--database','--db-user')) {
        Assert-HelperRejects @('capture','--target','fixture','--session',$sessionId,'--owner',$ownerId,
            $option,'untrusted-override') "Removed $option selector was accepted."
    }
    $wrongSession = [Guid]::NewGuid().ToString('D').ToLowerInvariant()
    Assert-HelperRejects @('capture','--target','fixture','--session',$wrongSession,'--owner',$ownerId) 'A valid but unowned session was accepted.'
    Assert-NoNewCaptureDirectory $captureDirectoriesBeforeNegativeChecks 'A failed session lookup created capture output.'
    $wrongOwner = [Guid]::NewGuid().ToString('D').ToLowerInvariant()
    Assert-HelperRejects @('capture','--target','fixture','--session',$sessionId,'--owner',$wrongOwner) 'A valid but unrelated owner was accepted.'
    Assert-NoNewCaptureDirectory $captureDirectoriesBeforeNegativeChecks 'A failed owner check created capture output.'

    $captureText = Invoke-Python @($captureTool,'capture','--target','fixture','--session',$sessionId,'--owner',$ownerId)
    $capture = $captureText | ConvertFrom-Json
    $backupDirectory = Register-Capture $capture
    $backupDump = Join-Path $backupDirectory 'database.dump'
    $backupManifest = Join-Path $backupDirectory 'manifest.json'
    Assert-True (Test-Path -LiteralPath $backupDump -PathType Leaf) 'Capture did not create a dump.'
    Assert-True (Test-Path -LiteralPath $backupManifest -PathType Leaf) 'Capture did not create a manifest.'
    $manifestHash = [string]$capture.manifestSha256
    Assert-True ($manifestHash -match '^[0-9a-f]{64}$') 'Capture returned no manifest hash.'

    $stage = 'actual database restore and inventory comparison'
    Invoke-Verifier @{ Dump=$backupDump; Manifest=$backupManifest } $manifestHash

    $stage = 'opaque credential-state mutation negative case'
    $updateSql = "UPDATE public.credential SET credential_data=replace(credential_data, 'fixture-only-opaque-data', 'changed-fixture-data') WHERE user_id='$ownerId' AND type='webauthn'"
    $stage = 'opaque credential row update'
    Invoke-Docker @('exec','-u','postgres',$postgresId,'psql','-XqAt','-U','postgres','-d','keycloak',
        '-v','ON_ERROR_STOP=1','-c',$updateSql) | Out-Null
    $changedCount = Invoke-Docker @('exec','-u','postgres',$postgresId,'psql','-XqAt','-U','postgres','-d','keycloak',
        '-v','ON_ERROR_STOP=1','-c',"SELECT count(*) FROM public.credential WHERE user_id='$ownerId' AND type='webauthn' AND credential_data LIKE '%changed-fixture-data%'")
    Assert-True ($changedCount -eq '1') 'The opaque fixture credential field was not changed exactly once.'
    $stage = 'capture changed credential state'
    $changedCapture = (Invoke-Python @($captureTool,'capture','--target','fixture','--session',$sessionId,'--owner',$ownerId)) | ConvertFrom-Json
    $changedDirectory = Register-Capture $changedCapture
    Assert-True ($changedCapture.inventorySha256 -cne $capture.inventorySha256) 'Opaque credential mutation did not change the real source inventory.'
    $stage = 'restore mismatched inventory candidate'
    $credentialMutation = Copy-Backup 'credential-mutation'
    [IO.File]::Copy((Join-Path $changedDirectory 'database.dump'),$credentialMutation.Dump,$true)
    $mutationHash = Set-Manifest $credentialMutation { param($value) $value.dumpSha256=$changedCapture.dumpSha256 }
    Assert-VerifierRejects $credentialMutation $mutationHash 'inventory-compare' 'A correctly hashed archive with changed credential state and stale inventory digest was accepted.'

    $stage = 'negative integrity cases'
    $tamperedDump = Copy-Backup 'tampered-dump'
    $bytes = [IO.File]::ReadAllBytes($tamperedDump.Dump)
    $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 0x01
    [IO.File]::WriteAllBytes($tamperedDump.Dump, $bytes)
    Assert-VerifierRejects $tamperedDump $manifestHash 'backup-hash' 'A byte-flipped dump was accepted.'

    $wrongHash = Copy-Backup 'wrong-hash'
    Assert-VerifierRejects $wrongHash ('0' * 64) 'manifest-hash' 'A mismatched expected manifest hash was accepted.'

    $badSchema = Copy-Backup 'bad-schema'
    $badSchemaHash = Set-Manifest $badSchema { param($value) $value.schema='wrong.schema' }
    Assert-VerifierRejects $badSchema $badSchemaHash 'manifest-schema' 'A wrong backup schema was accepted.'

    $badInventory = Copy-Backup 'bad-inventory'
    $badInventoryHash = Set-Manifest $badInventory { param($value) $value.inventorySha256=('0' * 64) }
    Assert-VerifierRejects $badInventory $badInventoryHash 'inventory-compare' 'A mismatched inventory hash was accepted.'

    $duplicateManifest = Copy-Backup 'duplicate-manifest'
    $raw = [IO.File]::ReadAllText($duplicateManifest.Manifest)
    $raw = $raw.Insert(1,'"schema":"duplicate",')
    [IO.File]::WriteAllText($duplicateManifest.Manifest,$raw,[Text.UTF8Encoding]::new($false))
    $duplicateHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($raw))).ToLowerInvariant()
    Assert-VerifierRejects $duplicateManifest $duplicateHash 'manifest-schema' 'A duplicate-property manifest was accepted.'

    Write-Host 'IDENTITY BACKUP TESTS PASS: actual Keycloak schema, private identity snapshot, restore inventory, and negative cases.'
}
catch {
    $suffix = if ($safeDetail) { " $safeDetail" } else { '' }
    throw "Disposable identity-backup contract failed during $stage;$suffix Fixture diagnostics suppressed."
}
finally {
    foreach ($id in $containers) {
        Invoke-Docker @('rm','-f','-v',$id) | Out-Null
    }
    if ($networkCreated) {
        Invoke-Docker @('network','rm',$network) | Out-Null
    }
    foreach ($directory in $captureDirectories) {
        Remove-CaptureDirectory $directory
    }
    $fullWork = [IO.Path]::GetFullPath($work)
    if ($fullWork.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($fullWork).StartsWith('fleetory-identity-backup-',[StringComparison]::Ordinal) -and
        (Test-Path -LiteralPath $fullWork)) {
        Remove-Item -LiteralPath $fullWork -Recurse -Force
    }
}
