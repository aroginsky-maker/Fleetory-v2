[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$composePath = Join-Path $repoRoot 'infra\pilot\compose.yaml'
$passedChecks = 0
$rejectedMutations = 0

function Assert-SignerMounts {
    param(
        [System.Collections.IDictionary] $Service,
        [string] $SecretSource
    )

    $mounts = @($Service['volumes'])
    if ($mounts.Count -ne 1 -or $mounts[0] -isnot [System.Collections.IDictionary]) {
        throw 'Signer must have exactly one reviewed secret bind mount.'
    }

    $mount = $mounts[0]
    if ($mount['type'] -cne 'bind' -or $mount['target'] -cne '/run/fleetory-signer' -or
        $mount['read_only'] -isnot [bool] -or -not $mount['read_only'] -or
        $mount['source'] -isnot [string] -or [string]::IsNullOrWhiteSpace($mount['source'])) {
        throw 'Signer secret bind must retain its target and read-only access.'
    }

    $actualSource = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($mount['source']))
    $expectedSource = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($SecretSource))
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    if (-not $actualSource.Equals($expectedSource, $comparison)) {
        throw 'Signer secret bind source differs from the reviewed directory.'
    }

    if ($Service.Contains('tmpfs')) {
        $temporaryMounts = @($Service['tmpfs'])
        if ($temporaryMounts.Count -ne 1 -or $temporaryMounts[0] -isnot [string] -or
            -not $temporaryMounts[0].StartsWith('/tmp:', [StringComparison]::Ordinal)) {
            throw 'Signer may mount tmpfs only at /tmp without shadowing protected paths.'
        }
    }
}

function Assert-SignerIsolation {
    param(
        [System.Collections.IDictionary] $Service,
        [string] $SecretSource
    )

    if ($Service['read_only'] -isnot [bool] -or -not $Service['read_only']) {
        throw 'Signer root filesystem must be read-only.'
    }

    if ($Service.Contains('privileged') -and
        ($Service['privileged'] -isnot [bool] -or $Service['privileged'])) {
        throw 'Signer must not use privileged mode.'
    }

    if ($Service.Contains('cap_add') -and @($Service['cap_add']).Count -ne 0) {
        throw 'Signer must not add Linux capabilities.'
    }

    $options = @($Service['security_opt'])
    if ($options.Count -ne 1 -or $options[0] -cne 'no-new-privileges:true') {
        throw 'Signer must retain only the reviewed no-new-privileges security option.'
    }

    foreach ($name in @(
        'user', 'pid', 'ipc', 'network_mode', 'userns_mode', 'uts',
        'devices', 'device_cgroup_rules', 'gpus', 'volumes_from',
        'configs', 'secrets', 'use_api_socket', 'post_start', 'pre_stop', 'deploy', 'runtime'
    )) {
        if ($Service.Contains($name)) {
            throw "Signer must not override the reviewed isolation setting '$name'."
        }
    }

    Assert-SignerMounts -Service $Service -SecretSource $SecretSource
}

function Assert-Profile {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $ComposeModel
    )

    $services = $ComposeModel['services']
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

    Assert-SignerIsolation -Service $services['signer'] -SecretSource (
        Join-Path (Split-Path -Parent $composePath) 'secrets/signer')

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
            $sourceDockerfiles = @{
                server = 'infra\pilot\Server.Dockerfile'
                keycloak = 'infra\pilot\Keycloak.Dockerfile'
            }
            $localDockerfile = Join-Path $repoRoot $sourceDockerfiles[$serviceName]
        } elseif (-not (Test-Path -LiteralPath $localDockerfile -PathType Leaf)) {
            $localDockerfile = Join-Path $repoRoot 'infra\command-signer\Dockerfile'
        }

        if (-not (Test-Path -LiteralPath $localDockerfile -PathType Leaf)) {
            throw "Pinned Dockerfile for local build '$serviceName' was not found."
        }

        if ((Get-Item -LiteralPath $localDockerfile).Name -cne [IO.Path]::GetFileName($localDockerfile)) {
            throw 'Dockerfile path casing must match the tracked filename on Linux and Windows.'
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
        [System.Collections.IDictionary] $ComposeModel,
        [Parameter(Mandatory)]
        [string] $Name
    )

    try {
        Assert-Profile -ComposeModel $ComposeModel
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

    $composeModel = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    Assert-Profile -ComposeModel $composeModel
    $passedChecks++

    $equivalent = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    $equivalent['services']['signer']['privileged'] = $false
    $equivalent['services']['signer']['cap_add'] = @()
    $equivalent['services']['signer']['volumes'][0]['source'] = Join-Path (
        $equivalent['services']['signer']['volumes'][0]['source']) '.'
    Assert-Profile -ComposeModel $equivalent
    $passedChecks++

    $signerMutations = [ordered]@{
        'privileged signer' = { param($service) $service['privileged'] = $true }
        'signer capability addition' = { param($service) $service['cap_add'] = @('SYS_ADMIN') }
        'writable signer root' = { param($service) $service['read_only'] = $false }
        'missing signer root protection' = { param($service) $service.Remove('read_only') }
        'writable signer secrets' = { param($service) $service['volumes'][0]['read_only'] = $false }
        'missing secret read-only flag' = { param($service) $service['volumes'][0].Remove('read_only') }
        'substituted signer secret source' = { param($service) $service['volumes'][0]['source'] = '/var/run/docker.sock' }
        'changed signer secret target' = { param($service) $service['volumes'][0]['target'] = '/run/unrelated' }
        'non-bind signer secrets' = { param($service) $service['volumes'][0]['type'] = 'volume' }
        'missing signer secret mount' = { param($service) $service['volumes'] = @() }
        'extra signer socket bind' = {
            param($service)
            $service['volumes'] += @{ type = 'bind'; source = '/var/run/docker.sock'; target = '/var/run/docker.sock'; read_only = $true }
        }
        'shadowed signer secret mount' = { param($service) $service['tmpfs'] = @('/run/fleetory-signer:rw,noexec,nosuid,size=32m') }
        'extra signer tmpfs' = { param($service) $service['tmpfs'] += '/app:rw,noexec,nosuid,size=32m' }
        'unconfined signer security option' = { param($service) $service['security_opt'] += 'seccomp:unconfined' }
        'conflicting signer privilege option' = { param($service) $service['security_opt'] += 'no-new-privileges:false' }
    }
    $overrideValues = [ordered]@{
        user = '0:0'
        pid = 'host'
        ipc = 'host'
        network_mode = 'service:server'
        userns_mode = 'host'
        uts = 'host'
        devices = @('/dev/kvm:/dev/kvm')
        device_cgroup_rules = @('c 1:3 rwm')
        gpus = 'all'
        volumes_from = @('server')
        configs = @(@{ source = 'unrelated'; target = '/run/extra-config' })
        secrets = @(@{ source = 'unrelated'; target = 'extra-key' })
        use_api_socket = $true
        post_start = @(@{ command = 'true'; privileged = $true })
        pre_stop = @(@{ command = 'true'; user = 'root' })
        deploy = @{ resources = @{ reservations = @{ devices = @(@{ driver = 'nvidia'; count = 'all'; capabilities = @('gpu') }) } } }
        runtime = 'nvidia'
    }
    foreach ($name in $signerMutations.Keys) {
        $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
        $null = & $signerMutations[$name] $mutation['services']['signer']
        Assert-RejectedMutation -ComposeModel $mutation -Name $name
    }
    foreach ($name in $overrideValues.Keys) {
        $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
        $mutation['services']['signer'][$name] = $overrideValues[$name]
        Assert-RejectedMutation -ComposeModel $mutation -Name "signer $name override"
    }

    $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    $mutation['services']['server']['ports'][0]['host_ip'] = '0.0.0.0'
    Assert-RejectedMutation -ComposeModel $mutation -Name 'public backend port'

    $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    $mutation['services']['signer']['networks']['app_net'] = @{}
    Assert-RejectedMutation -ComposeModel $mutation -Name 'signer attached to app network'

    $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    $mutation['services']['signer']['profiles'] = @('other-profile')
    Assert-RejectedMutation -ComposeModel $mutation -Name 'signer profile removed'

    $mutation = ($renderedJson -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    $mutation['services']['audit-gateway']['tmpfs'] = @('/tmp:rw', 'nosuid', 'noexec')
    Assert-RejectedMutation -ComposeModel $mutation -Name 'split tmpfs options'

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
