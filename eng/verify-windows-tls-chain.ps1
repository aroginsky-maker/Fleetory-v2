$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# This probe modifies CurrentUser certificate trust and is limited to an ephemeral CI runner.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'Windows TLS chain verification runs only on an ephemeral GitHub Windows runner.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$work = Join-Path $env:RUNNER_TEMP ('fleetory-tls-' + [guid]::NewGuid().ToString('N'))
$openssl = (Get-Command openssl.exe -ErrorAction SilentlyContinue)?.Source
if (-not $openssl) {
    $openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
}
if (-not (Test-Path -LiteralPath $openssl -PathType Leaf)) {
    throw 'OpenSSL is required for root-only wire verification.'
}

$utf8 = [System.Text.UTF8Encoding]::new($false)
$serverProcess = $null
$installedRoot = $null

function Invoke-OpenSsl([string[]] $Arguments, [int] $TimeoutSeconds = 15) {
    $start = [System.Diagnostics.ProcessStartInfo]::new($openssl)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            throw "OpenSSL timed out after $TimeoutSeconds seconds."
        }
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "OpenSSL failed with exit code $($process.ExitCode): $output"
        }
        return $output
    }
    finally { $process.Dispose() }
}

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

try {
    New-Item -ItemType Directory -Path $work | Out-Null
    $rootConfig = @'
[req]
distinguished_name = dn
x509_extensions = ca
prompt = no
[dn]
CN = Fleetory Ephemeral CI Root
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
'@
    $intermediateExtensions = @'
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
'@
    $serverExtensions = @'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1
'@
    $clientExtensions = @'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = URI:urn:fleetory:admin:00000000-0000-4000-8000-000000000001
'@
    [System.IO.File]::WriteAllText((Join-Path $work 'root.cnf'), $rootConfig, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $work 'intermediate.ext'),
        $intermediateExtensions, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $work 'server.ext'), $serverExtensions, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $work 'client.ext'), $clientExtensions, $utf8)

    foreach ($name in @('root', 'intermediate', 'server', 'client')) {
        Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout',
            '-out', (Join-Path $work "$name.key"))
    }
    Invoke-OpenSsl -Arguments @('req', '-new', '-x509', '-key', (Join-Path $work 'root.key'),
        '-out', (Join-Path $work 'root.crt'), '-days', '1',
        '-config', (Join-Path $work 'root.cnf'))
    foreach ($name in @('intermediate', 'server', 'client')) {
        Invoke-OpenSsl -Arguments @('req', '-new', '-key', (Join-Path $work "$name.key"),
            '-out', (Join-Path $work "$name.csr"), '-subj', "/CN=Fleetory CI $name")
        $issuer = if ($name -eq 'intermediate') { 'root' } else { 'intermediate' }
        Invoke-OpenSsl -Arguments @('x509', '-req', '-in', (Join-Path $work "$name.csr"),
            '-CA', (Join-Path $work "$issuer.crt"),
            '-CAkey', (Join-Path $work "$issuer.key"), '-CAcreateserial',
            '-out', (Join-Path $work "$name.crt"), '-days', '1',
            '-extfile', (Join-Path $work "$name.ext"))
    }

    $rootPem = [System.IO.File]::ReadAllText((Join-Path $work 'root.crt'))
    $intermediatePem = [System.IO.File]::ReadAllText((Join-Path $work 'intermediate.crt'))
    $serverPem = [System.IO.File]::ReadAllText((Join-Path $work 'server.crt'))
    $clientPem = [System.IO.File]::ReadAllText((Join-Path $work 'client.crt'))
    [System.IO.File]::WriteAllText((Join-Path $work 'admin-gateway-root-ca'),
        $rootPem, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $work 'admin-gateway-server-cert'),
        $serverPem + $intermediatePem, $utf8)
    Copy-Item -LiteralPath (Join-Path $work 'server.key') -Destination (
        Join-Path $work 'admin-gateway-server-key')
    [System.IO.File]::WriteAllText((Join-Path $work 'client-chain.crt'),
        $clientPem + $intermediatePem, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $work 'fleetory-postgresql'),
        'Host=127.0.0.1;Port=1;Database=fleetory_test_tls_chain;Username=fleetory;Timeout=1', $utf8)

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Join-Path $work 'root.crt'))
    $thumbprint = $certificate.Thumbprint
    $certificate.Dispose()
    if (Test-Path -LiteralPath "Cert:\CurrentUser\Root\$thumbprint") {
        throw 'Ephemeral root unexpectedly exists before this CI probe.'
    }
    Import-Certificate -FilePath (Join-Path $work 'root.crt') `
        -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    $installedRoot = $thumbprint

    $webPort = Get-FreePort
    $adminPort = Get-FreePort
    while ($adminPort -eq $webPort) { $adminPort = Get-FreePort }
    $env:FLEETORY_Fleetory__Secrets__Directory = $work
    $env:FLEETORY_Fleetory__Web__Port = [string] $webPort
    $env:FLEETORY_Fleetory__AdminGateway__Enabled = 'true'
    $env:FLEETORY_Fleetory__AdminGateway__Port = [string] $adminPort
    $dll = Join-Path $repoRoot 'src/Fleetory.Server/bin/Release/net10.0/Fleetory.Server.dll'
    $serverProcess = Start-Process -FilePath 'dotnet' -ArgumentList @(
        ('"' + $dll + '"'), '--environment=Development') -WindowStyle Hidden `
        -PassThru -RedirectStandardOutput (Join-Path $work 'server.stdout.log') `
        -RedirectStandardError (Join-Path $work 'server.stderr.log')

    $ready = $false
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        Start-Sleep -Milliseconds 200
        if ($serverProcess.HasExited) { break }
        $socket = $null
        try {
            $socket = [System.Net.Sockets.TcpClient]::new()
            $socket.Connect('127.0.0.1', $adminPort)
            $socket.Dispose()
            $ready = $true
            break
        }
        catch { $socket?.Dispose() }
    }
    if (-not $ready) {
        throw ('Fleetory Server did not start: ' +
            [System.IO.File]::ReadAllText((Join-Path $work 'server.stderr.log')))
    }

    $wire = Invoke-OpenSsl -Arguments @('s_client', '-connect', "127.0.0.1:$adminPort",
        '-cert', (Join-Path $work 'client-chain.crt'),
        '-key', (Join-Path $work 'client.key'),
        '-CAfile', (Join-Path $work 'root.crt'), '-verify_return_error', '-showcerts')
    $certificateCount = [regex]::Matches($wire, '-----BEGIN CERTIFICATE-----').Count
    if ($wire -notmatch 'Verify return code: 0 \(ok\)' -or $certificateCount -lt 2) {
        throw "Windows root-only TLS verification failed; sent=$certificateCount`n$wire"
    }
    Write-Host "WINDOWS ROOT-ONLY TLS CHAIN PASS: $certificateCount certificates, verify code 0"
}
finally {
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force
        $serverProcess.WaitForExit()
    }
    if ($installedRoot) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\Root\$installedRoot" -Force
    }
}
