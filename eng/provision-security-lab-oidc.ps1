$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$labDirectory = Join-Path (Split-Path -Parent $repoRoot) 'work/security-lab'
$envPath = Join-Path $labDirectory 'lab.env'
if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    throw 'Start the security lab before provisioning OIDC.'
}

$settings = @{}
foreach ($entry in [System.IO.File]::ReadAllLines($envPath)) {
    $separator = $entry.IndexOf('=')
    if ($separator -gt 0) { $settings[$entry.Substring(0, $separator)] = $entry.Substring($separator + 1) }
}
if ([string]::IsNullOrWhiteSpace($settings['FLEETORY_LAB_KEYCLOAK_ADMIN_PASSWORD'])) {
    throw 'The lab Keycloak administrator credential is missing.'
}

$origin = 'http://localhost:8088'
$token = Invoke-RestMethod -Method Post -Uri "$origin/realms/master/protocol/openid-connect/token" `
    -Body @{ grant_type = 'password'; client_id = 'admin-cli'; username = 'lab-admin';
        password = $settings['FLEETORY_LAB_KEYCLOAK_ADMIN_PASSWORD'] } -TimeoutSec 15
$headers = @{ Authorization = "Bearer $($token.access_token)" }
$realmUrl = "$origin/admin/realms/fleetory"

$realm = @{
    realm = 'fleetory'
    enabled = $true
    registrationAllowed = $false
    resetPasswordAllowed = $false
    bruteForceProtected = $true
    accessTokenLifespan = 300
    ssoSessionIdleTimeout = 900
    ssoSessionMaxLifespan = 28800
    revokeRefreshToken = $true
    eventsEnabled = $true
    adminEventsEnabled = $true
    adminEventsDetailsEnabled = $true
}

try {
    Invoke-RestMethod -Method Get -Uri $realmUrl -Headers $headers -TimeoutSec 15 | Out-Null
    $method = 'Put'
    $uri = $realmUrl
}
catch {
    if ([int]$_.Exception.Response.StatusCode -ne 404) { throw }
    $method = 'Post'
    $uri = "$origin/admin/realms"
}
Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -ContentType 'application/json' `
    -Body ($realm | ConvertTo-Json -Compress -Depth 5) -TimeoutSec 15 | Out-Null

$actions = Invoke-RestMethod -Method Get -Uri "$realmUrl/authentication/required-actions" `
    -Headers $headers -TimeoutSec 15
$webauthnAction = $actions.Where({ $_.alias -eq 'webauthn-register' })[0]
if ($null -eq $webauthnAction) { throw 'Keycloak WebAuthn registration action is unavailable.' }
$webauthnAction.enabled = $true
$webauthnAction.defaultAction = $true
Invoke-RestMethod -Method Put -Uri "$realmUrl/authentication/required-actions/$($webauthnAction.alias)" `
    -Headers $headers -ContentType 'application/json' `
    -Body ($webauthnAction | ConvertTo-Json -Compress -Depth 8) -TimeoutSec 15 | Out-Null

$executionsUrl = "$realmUrl/authentication/flows/browser/executions"
$requirements = @{
    'Browser - Conditional 2FA' = 'REQUIRED'
    'OTP Form' = 'DISABLED'
    'WebAuthn Authenticator' = 'REQUIRED'
}
foreach ($name in $requirements.Keys) {
    $executions = Invoke-RestMethod -Method Get -Uri $executionsUrl -Headers $headers -TimeoutSec 15
    $execution = $executions.Where({ $_.displayName -eq $name })[0]
    if ($null -eq $execution) { throw "Keycloak browser flow lacks $name." }
    $execution.requirement = $requirements[$name]
    Invoke-RestMethod -Method Put -Uri $executionsUrl -Headers $headers -ContentType 'application/json' `
        -Body ($execution | ConvertTo-Json -Compress -Depth 8) -TimeoutSec 15 | Out-Null
}

$executions = Invoke-RestMethod -Method Get -Uri $executionsUrl -Headers $headers -TimeoutSec 15
$webauthnExecution = $executions.Where({ $_.displayName -eq 'WebAuthn Authenticator' })[0]
$referenceConfig = @{
    alias = 'fleetory-webauthn-reference'
    config = @{
        'default.reference.value' = 'webauthn'
        'default.reference.maxAge' = '300'
    }
}
$executionDetail = Invoke-RestMethod -Method Get `
    -Uri "$realmUrl/authentication/executions/$($webauthnExecution.id)" `
    -Headers $headers -TimeoutSec 15
$configId = $executionDetail.authenticatorConfig
$configMethod = if ($configId) { 'Put' } else { 'Post' }
$configUri = if ($configId) {
    "$realmUrl/authentication/config/$configId"
} else {
    "$realmUrl/authentication/executions/$($webauthnExecution.id)/config"
}
Invoke-RestMethod -Method $configMethod -Uri $configUri `
    -Headers $headers -ContentType 'application/json' `
    -Body ($referenceConfig | ConvertTo-Json -Compress -Depth 5) -TimeoutSec 15 | Out-Null
$executionDetail = Invoke-RestMethod -Method Get `
    -Uri "$realmUrl/authentication/executions/$($webauthnExecution.id)" `
    -Headers $headers -TimeoutSec 15
$configReadback = Invoke-RestMethod -Method Get `
    -Uri "$realmUrl/authentication/config/$($executionDetail.authenticatorConfig)" `
    -Headers $headers -TimeoutSec 15
if ($configReadback.alias -ne 'fleetory-webauthn-reference' -or
    -not $configReadback.config.PSObject.Properties['default.reference.value'] -or
    -not $configReadback.config.PSObject.Properties['default.reference.maxAge']) {
    throw 'The WebAuthn AMR reference configuration was not retained.'
}

$clientsUrl = "$realmUrl/clients"
$clientId = 'fleetory-admin-lab'
$client = @{
    clientId = $clientId
    name = 'Fleetory Admin Lab'
    enabled = $true
    protocol = 'openid-connect'
    publicClient = $true
    standardFlowEnabled = $true
    directAccessGrantsEnabled = $false
    implicitFlowEnabled = $false
    serviceAccountsEnabled = $false
    redirectUris = @('http://127.0.0.1:4173/auth/callback')
    webOrigins = @('http://127.0.0.1:4173')
    attributes = @{ 'pkce.code.challenge.method' = 'S256' }
}
$existingClients = Invoke-RestMethod -Method Get -Uri "${clientsUrl}?clientId=$clientId" `
    -Headers $headers -TimeoutSec 15
$existingClient = $existingClients.Where({ $_.clientId -eq $clientId }) | Select-Object -First 1
if ($null -eq $existingClient) {
    Invoke-RestMethod -Method Post -Uri $clientsUrl -Headers $headers -ContentType 'application/json' `
        -Body ($client | ConvertTo-Json -Compress -Depth 8) -TimeoutSec 15 | Out-Null
}
else {
    $client.id = $existingClient.id
    Invoke-RestMethod -Method Put -Uri "$clientsUrl/$($client.id)" -Headers $headers `
        -ContentType 'application/json' -Body ($client | ConvertTo-Json -Compress -Depth 8) `
        -TimeoutSec 15 | Out-Null
}
$existingClients = Invoke-RestMethod -Method Get -Uri "${clientsUrl}?clientId=$clientId" `
    -Headers $headers -TimeoutSec 15
$clientUuid = $existingClients.Where({ $_.clientId -eq $clientId })[0].id
if ([string]::IsNullOrWhiteSpace($clientUuid)) { throw 'The Fleetory OIDC lab client was not created.' }

$mappersUrl = "$clientsUrl/$clientUuid/protocol-mappers/models"
$mappers = @(
    @{
        name = 'fleetory-admin-api-audience'
        protocol = 'openid-connect'
        protocolMapper = 'oidc-audience-mapper'
        config = @{
            'included.custom.audience' = 'fleetory-admin-api'
            'access.token.claim' = 'true'
            'id.token.claim' = 'false'
        }
    },
    @{
        name = 'fleetory-authentication-methods'
        protocol = 'openid-connect'
        protocolMapper = 'oidc-amr-mapper'
        config = @{
            'access.token.claim' = 'true'
            'id.token.claim' = 'false'
        }
    }
)
foreach ($mapper in $mappers) {
    $existingMappers = Invoke-RestMethod -Method Get -Uri $mappersUrl -Headers $headers -TimeoutSec 15
    $existingMapper = $existingMappers.Where({ $_.name -eq $mapper.name }) |
        Select-Object -First 1
    if ($null -eq $existingMapper) {
        $method = 'Post'
        $uri = $mappersUrl
    }
    else {
        $mapper.id = $existingMapper.id
        $method = 'Put'
        $uri = "$mappersUrl/$($mapper.id)"
    }
    Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -ContentType 'application/json' `
        -Body ($mapper | ConvertTo-Json -Compress -Depth 8) -TimeoutSec 15 | Out-Null
}

$executions = Invoke-RestMethod -Method Get -Uri $executionsUrl -Headers $headers -TimeoutSec 15
foreach ($name in $requirements.Keys) {
    $execution = $executions.Where({ $_.displayName -eq $name })[0]
    if ($null -eq $execution -or $execution.requirement -ne $requirements[$name]) {
        throw "Keycloak MFA flow did not retain $name."
    }
}
$actions = Invoke-RestMethod -Method Get -Uri "$realmUrl/authentication/required-actions" `
    -Headers $headers -TimeoutSec 15
$webauthnAction = $actions.Where({ $_.alias -eq 'webauthn-register' })[0]
if (-not $webauthnAction.enabled -or -not $webauthnAction.defaultAction) {
    throw 'Keycloak WebAuthn registration is not mandatory.'
}

$clientReadback = Invoke-RestMethod -Method Get -Uri "$clientsUrl/$clientUuid" `
    -Headers $headers -TimeoutSec 15
if (-not $clientReadback.publicClient -or -not $clientReadback.standardFlowEnabled -or
    $clientReadback.directAccessGrantsEnabled -or $clientReadback.implicitFlowEnabled -or
    $clientReadback.attributes.'pkce.code.challenge.method' -ne 'S256' -or
    $clientReadback.redirectUris.Count -ne 1 -or
    $clientReadback.redirectUris[0] -ne 'http://127.0.0.1:4173/auth/callback') {
    throw 'Fleetory OIDC lab client does not enforce the expected code flow and PKCE settings.'
}
$mappersReadback = Invoke-RestMethod -Method Get -Uri $mappersUrl -Headers $headers -TimeoutSec 15
if ($mappersReadback.Where({ $_.name -eq 'fleetory-admin-api-audience' }).Count -ne 1 -or
    $mappersReadback.Where({ $_.name -eq 'fleetory-authentication-methods' }).Count -ne 1) {
    throw 'Fleetory OIDC lab client token mappers are missing.'
}

$certDirectory = Join-Path $labDirectory 'certs'
$personIdPath = Join-Path $certDirectory 'admin-person-id'
New-Item -ItemType Directory -Path $certDirectory -Force | Out-Null
$usersUrl = "$realmUrl/users"
$users = Invoke-RestMethod -Method Get -Uri "${usersUrl}?username=lab-admin-person&exact=true" `
    -Headers $headers -TimeoutSec 15
$existingUser = $users.Where({ $_.username -eq 'lab-admin-person' }) |
    Select-Object -First 1
if ($null -eq $existingUser) {
    $passwordFile = Join-Path $certDirectory 'admin-user-password'
    if (-not (Test-Path -LiteralPath $passwordFile -PathType Leaf)) {
        $passwordBytes = [byte[]]::new(32)
        [Security.Cryptography.RandomNumberGenerator]::Fill($passwordBytes)
        [IO.File]::WriteAllText($passwordFile, [Convert]::ToHexString($passwordBytes),
            [Text.UTF8Encoding]::new($false))
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($passwordBytes)
        if ($env:OS -eq 'Windows_NT') {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            & icacls $passwordFile /inheritance:r /grant:r "${identity}:F" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not restrict lab user credential ACL.' }
        }
        else { & chmod 600 $passwordFile }
    }
    $newUser = @{
        username = 'lab-admin-person'
        enabled = $true
        requiredActions = @('webauthn-register')
        credentials = @(@{
            type = 'password'
            value = [IO.File]::ReadAllText($passwordFile)
            temporary = $false
        })
    }
    Invoke-RestMethod -Method Post -Uri $usersUrl -Headers $headers -ContentType 'application/json' `
        -Body ($newUser | ConvertTo-Json -Compress -Depth 8) -TimeoutSec 15 | Out-Null
}
$users = Invoke-RestMethod -Method Get -Uri "${usersUrl}?username=lab-admin-person&exact=true" `
    -Headers $headers -TimeoutSec 15
$labUsers = $users.Where({ $_.username -eq 'lab-admin-person' })
if ($labUsers.Count -ne 1) { throw 'The Fleetory OIDC lab user is not unique.' }
$personId = $labUsers[0].id
$parsedPersonId = [Guid]::Empty
if (-not [Guid]::TryParseExact($personId, 'D', [ref] $parsedPersonId) -or
    $parsedPersonId -eq [Guid]::Empty) {
    throw 'Keycloak returned an invalid lab user ID.'
}

$certificateId = if (Test-Path -LiteralPath $personIdPath -PathType Leaf) {
    [IO.File]::ReadAllText($personIdPath).Trim()
} else { $null }
$adminCertPath = Join-Path $certDirectory 'admin-client.crt'
$certificateSan = $null
if (Test-Path -LiteralPath $adminCertPath -PathType Leaf) {
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(
        [IO.File]::ReadAllText($adminCertPath))
    try {
        $certificateSan = $certificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::UrlName, $false)
    }
    finally { $certificate.Dispose() }
}
if ($certificateId -ne $personId -or
    $certificateSan -ne "urn:fleetory:admin:$personId") {
    [IO.File]::WriteAllText($personIdPath, $personId, [Text.UTF8Encoding]::new($false))
    if ($env:OS -eq 'Windows_NT') {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $personIdPath /inheritance:r /grant:r "${identity}:F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not restrict lab person ID ACL.' }
    }
    else { & chmod 600 $personIdPath }
    & (Join-Path $PSScriptRoot 'provision-security-lab-certificates.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Could not align the Admin certificate with the OIDC user.' }
}

$discovery = Invoke-RestMethod -Method Get `
    -Uri "$origin/realms/fleetory/.well-known/openid-configuration" -TimeoutSec 15
if ($discovery.issuer -ne "$origin/realms/fleetory" -or
    $discovery.jwks_uri -ne "$origin/realms/fleetory/protocol/openid-connect/certs") {
    throw 'Keycloak OIDC discovery does not match the Fleetory lab authority.'
}
$jwks = Invoke-RestMethod -Method Get -Uri $discovery.jwks_uri -TimeoutSec 15
if ($jwks.keys.Count -lt 1) { throw 'Keycloak has no public OIDC signing key.' }

Write-Host 'Fleetory lab realm provisioned: browser login requires WebAuthn as a second factor.'
Write-Host 'Fleetory lab OIDC client uses authorization code with S256 PKCE and a fixed loopback redirect.'
Write-Host 'Lab OIDC user ID matches the Admin certificate identity. Its password is outside Git.'
