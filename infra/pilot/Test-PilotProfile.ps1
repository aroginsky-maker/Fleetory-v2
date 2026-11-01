[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$composePath = Join-Path $PSScriptRoot 'compose.yaml'
$passedChecks = 0
$rejectedMutations = 0

function Assert-Profile {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Profile
    )

    $services = $Profile['services']
    $expectedNetworks = @{
        server = @('app_net')
        signer = @('signer_net')
        postgres = @('app_net', 'signer_net')
        'audit-store' = @('audit_net')
        'audit-gateway' = @('app_net', 'audit_net')
    }

    if (-not $services.Contains('caddy') -or
        $services['caddy']['network_mode'] -ne 'host') {
        throw 'Caddy must be the only host-network service.'
    }

    foreach ($serviceName in $services.Keys) {
        $service = $services[$serviceName]
        if ($serviceName -ne 'caddy' -and $service['network_mode'] -eq 'host') {
            throw "Backend service '$serviceName' uses host networking."
        }

        if ($service.Contains('ports')) {
            foreach ($port in $service['ports']) {
                if ($serviceName -eq 'caddy') {
                    throw 'Caddy must publish ports through host networking, not port mappings.'
                }

                if ($port['host_ip'] -ne '127.0.0.1') {
                    throw "Published backend port for '$serviceName' is not bound to 127.0.0.1."
                }
            }
        }

        $capabilities = @($service['cap_drop'])
        if ($capabilities -notcontains 'ALL') {
            throw "Service '$serviceName' must drop all Linux capabilities."
        }

        if (@($service['security_opt']) -notcontains 'no-new-privileges:true') {
            throw "Service '$serviceName' must set no-new-privileges:true."
        }

        if ($service.Contains('tmpfs')) {
            foreach ($mount in @($service['tmpfs'])) {
                if ($mount -isnot [string] -or
                    $mount -notmatch '^/[^:]+:[^,]+(?:,[^,=]+(?:=[^,]+)?)*$') {
                    throw "Service '$serviceName' has a malformed tmpfs mount entry."
                }
            }
        }

        if ($service.Contains('environment')) {
            foreach ($name in $service['environment'].Keys) {
                $value = [string] $service['environment'][$name]
                if ($name -match '(?i)(PASSWORD|TOKEN)' -and $name -notmatch '(?i)_FILE$') {
                    $isSecretPath = $name -match '(?i)Secrets__Directory$' -and
                        $value.StartsWith('/run/fleetory-', [System.StringComparison]::Ordinal)
                    if (-not $isSecretPath) {
                        throw "Service '$serviceName' exposes credential-like environment variable '$name'."
                    }
                }

                if ($name -match '(?i)(PASSWORD|TOKEN)_FILE$' -and
                    -not $value.StartsWith('/run/secrets/', [System.StringComparison]::Ordinal)) {
                    throw "Service '$serviceName' has a credential file setting outside /run/secrets/."
                }
            }
        }
    }

    foreach ($serviceName in $expectedNetworks.Keys) {
        $actualNetworks = @($services[$serviceName]['networks'].Keys | Sort-Object)
        $requiredNetworks = @($expectedNetworks[$serviceName] | Sort-Object)
        if (($actualNetworks -join ',') -ne ($requiredNetworks -join ',')) {
            throw "Service '$serviceName' has an unexpected network attachment."
        }
    }

    if (@($services['signer']['profiles']) -notcontains 'signer-approved') {
        throw 'Signer must be gated by the signer-approved Compose profile.'
    }

    if ($services['audit-store']['healthcheck']['disable'] -ne $true) {
        throw 'The inherited non-TLS immudb healthcheck must be disabled.'
    }

    if ($services['audit-store']['environment']['SSL_CERT_FILE'] -ne
        '/run/secrets/immudb/infrastructure-ca') {
        throw 'immudb client TLS must use the mounted infrastructure CA.'
    }

    $auditCommand = @($services['audit-store']['command']) -join ' '
    if ($auditCommand -notmatch '--address=audit-store' -or
        $auditCommand -notmatch '--clientcas=/run/secrets/immudb/infrastructure-ca') {
        throw 'immudb must bind a certificate-matching address and use the infrastructure CA.'
    }

    if ($services['keycloak']['environment'].Contains('KC_HTTP_RELATIVE_PATH')) {
        throw 'Keycloak must not override an unbaked optimized-image build option.'
    }

    if ($services['server']['environment']['DOTNET_ENVIRONMENT'] -ne 'Production') {
        throw 'Server must run in Production environment.'
    }

    $serverEnvironment = $services['server']['environment']
    foreach ($name in @(
        'FLEETORY_Fleetory__Web__Port',
        'FLEETORY_Fleetory__AuditExport__Address',
        'FLEETORY_Fleetory__AuditExport__Username',
        'FLEETORY_Fleetory__AuditExport__Database'
    )) {
        if (-not $serverEnvironment.Contains($name)) {
            throw "Server environment is missing required setting '$name'."
        }
    }

    if ($serverEnvironment['FLEETORY_Fleetory__Web__Port'] -ne '5088') {
        throw 'Server web listener must use Fleetory:Web:Port 5088.'
    }

    if ($serverEnvironment['FLEETORY_Fleetory__AuditExport__Address'] -notmatch '^https://') {
        throw 'The Server audit sink must use HTTPS.'
    }

    if ($serverEnvironment['FLEETORY_Fleetory__AdminGateway__Oidc__Authority'] -notmatch '^https://') {
        throw 'The Server Admin OIDC authority must use HTTPS.'
    }

    foreach ($serviceName in @('postgres', 'openbao', 'audit-store', 'audit-gateway', 'caddy')) {
        $image = [string] $services[$serviceName]['image']
        if ($image -notmatch '@sha256:[0-9a-f]{64}$') {
            throw "Infrastructure image for '$serviceName' is not pinned by digest."
        }
    }

    foreach ($serviceName in @('server', 'signer', 'keycloak')) {
        $build = $services[$serviceName]['build']
        $dockerfilePath = [string] $build['dockerfile']
        if ([System.IO.Path]::IsPathRooted($dockerfilePath)) {
            $localDockerfile = $dockerfilePath
        } else {
            $localDockerfile = Join-Path $PSScriptRoot $dockerfilePath
        }

        if ($serviceName -eq 'server' -or $serviceName -eq 'keycloak') {
            $localDockerfile = Join-Path $PSScriptRoot "$serviceName.Dockerfile"
        } elseif (-not (Test-Path -LiteralPath $localDockerfile -PathType Leaf)) {
            $localDockerfile = Join-Path $PSScriptRoot '..\command-signer\Dockerfile'
        }

        if (-not (Test-Path -LiteralPath $localDockerfile -PathType Leaf)) {
            throw "Pinned Dockerfile for local build '$serviceName' was not found."
        }

        $dockerfileText = Get-Content -LiteralPath $localDockerfile -Raw
        if ($dockerfileText -notmatch '(?m)^FROM\s+\S+@sha256:[0-9a-f]{64}\s*$') {
            throw "Local build '$serviceName' does not use a digest-pinned base image."
        }
    }
}

function Assert-RejectedMutation {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Profile,
        [Parameter(Mandatory)]
        [string] $Name
    )

    try {
        Assert-Profile -Profile $Profile
    } catch {
        $script:rejectedMutations++
        return
    }

    throw "Contract validator accepted unsafe mutation '$Name'."
}

$environmentNames = @('FLEETORY_HOST', 'FLEETORY_AUTH_HOST', 'FLEETORY_RELEASE')
$originalEnvironment = @{}
foreach ($name in $environmentNames) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    $env:FLEETORY_HOST = 'pilot.example.test'
    $env:FLEETORY_AUTH_HOST = 'auth.example.test'
    $env:FLEETORY_RELEASE = 'contract-test'

    $renderedJson = & docker compose --profile signer-approved -f $composePath config --format json 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'docker compose config --format json failed.'
    }

    $profile = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    Assert-Profile -Profile $profile
    $passedChecks++

    $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    $mutation['services']['server']['ports'][0]['host_ip'] = '0.0.0.0'
    Assert-RejectedMutation -Profile $mutation -Name 'public backend port'

    $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    $mutation['services']['signer']['networks']['app_net'] = @{}
    Assert-RejectedMutation -Profile $mutation -Name 'signer attached to app network'

    $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    $mutation['services']['signer']['profiles'] = @('other-profile')
    Assert-RejectedMutation -Profile $mutation -Name 'signer profile removed'

    $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    $mutation['services']['audit-gateway']['tmpfs'] = @('/tmp:rw', 'nosuid', 'noexec')
    Assert-RejectedMutation -Profile $mutation -Name 'split tmpfs options'

    $passedChecks += $rejectedMutations
    Write-Output "PASS: $passedChecks contract checks ($rejectedMutations unsafe mutations rejected)."
} catch {
    [Console]::Error.WriteLine("FAIL: $($_.Exception.Message)")
    exit 1
} finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
    }
}
