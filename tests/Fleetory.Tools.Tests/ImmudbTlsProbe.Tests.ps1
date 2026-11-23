# UTF-8 with BOM keeps this PowerShell test usable on Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$probe = Join-Path $repoRoot 'eng/verify-immudb-tls.ps1'
$work = Join-Path $repoRoot ('artifacts/immudb-tls-probe-test-' +
    [Guid]::NewGuid().ToString('N'))
$savedCurlHome = $env:CURL_HOME
$server = $null
$redirectTarget = $null
$authority = $null
$otherAuthority = $null

function Assert-Throws([scriptblock] $Action, [string] $Message, [string] $ExpectedError) {
    $thrown = $false
    try { & $Action } catch {
        if ($_.Exception.Message -notlike "*$ExpectedError*") { throw }
        $thrown = $true
    }
    if (-not $thrown) { throw $Message }
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $root = Join-Path $work 'root.pem'
    $compiler = @{ Path = (Join-Path $PSScriptRoot 'TlsProbeTestServer.cs') }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $compiler.ReferencedAssemblies = @('System.dll', 'System.Core.dll', 'System.Net.Http.dll')
    }
    Add-Type @compiler
    $authority = [TlsProbeTestServer]::CreateCertificate()
    $otherAuthority = [TlsProbeTestServer]::CreateCertificate()
    $wrongRoot = Join-Path $work 'wrong-root.pem'
    foreach ($entry in @(@($authority, $root), @($otherAuthority, $wrongRoot))) {
        $base64 = [Convert]::ToBase64String($entry[0].Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Cert),
            [Base64FormattingOptions]::InsertLineBreaks)
        [IO.File]::WriteAllText($entry[1],
            "-----BEGIN CERTIFICATE-----`n$base64`n-----END CERTIFICATE-----`n")
    }
    # A user's curl defaults must never weaken the probe's verification or follow redirects.
    foreach ($name in @('.curlrc', '_curlrc')) {
        [IO.File]::WriteAllText((Join-Path $work $name), "insecure`nlocation`n")
    }
    $env:CURL_HOME = $work

    Assert-Throws { & $probe -Address ([uri]'http://audit.example/') -RootCertificatePath $root } `
        'HTTP immudb origin was accepted.' 'HTTPS origin'
    Assert-Throws { & $probe -Address ([uri]'https://user:password@audit.example/') -RootCertificatePath $root } `
        'Embedded TLS credentials were accepted.' 'HTTPS origin'
    foreach ($address in @('/relative', 'https://audit.example/api/status',
        'https://audit.example/?secret=value', 'https://audit.example/#fragment')) {
        Assert-Throws { & $probe -Address ([uri]$address) -RootCertificatePath $root } `
            'A non-origin TLS address was accepted.' 'HTTPS origin'
    }
    Assert-Throws { & $probe -Address ([uri]'https://audit.example/') -RootCertificatePath 'relative.pem' } `
        'Relative root certificate path was accepted.' 'must be absolute'
    Assert-Throws { & $probe -Address ([uri]'https://audit.example/') -RootCertificatePath (Join-Path $work 'missing.pem') } `
        'Missing root certificate was accepted.' 'does not exist'

    $server = [TlsProbeTestServer]::new($authority)
    $redirectTarget = [TlsProbeTestServer]::new($authority)
    $origin = [uri]("https://localhost:{0}/" -f $server.Port)
    $result = & $probe -Address $origin -RootCertificatePath $root | ConvertFrom-Json
    if ($result.schema -cne 'fleetory.immudb-tls-probe.v1' -or
        $result.verified -ne $true -or $result.httpStatus -ne 200 -or
        $result.address -cne $origin.GetLeftPart([UriPartial]::Authority) -or
        $result.rootCertificateSha256 -cne (Get-FileHash $root -Algorithm SHA256).Hash -or
        $server.Requests -ne 1) {
        throw 'Trusted loopback TLS origin did not produce the expected verification record.'
    }
    Assert-Throws { & $probe -Address $origin -RootCertificatePath $wrongRoot } `
        'An untrusted TLS certificate was accepted.' 'certificate validation failed'
    $wrongName = [uri]("https://127.0.0.1:{0}/" -f $server.Port)
    Assert-Throws { & $probe -Address $wrongName -RootCertificatePath $root } `
        'A TLS certificate for another hostname was accepted.' 'certificate validation failed'
    if ($server.Requests -ne 1) { throw 'An invalid TLS peer received an HTTP request.' }

    $server.Location = "https://localhost:$($redirectTarget.Port)/"
    foreach ($status in @(301, 302, 307, 308, 404, 503)) {
        $server.Status = $status
        Assert-Throws { & $probe -Address $origin -RootCertificatePath $root } `
            "HTTP $status was accepted as verified." 'must return HTTP 2xx'
    }
    if ($redirectTarget.Requests -ne 0) { throw 'The TLS probe followed a redirect.' }
    Write-Host 'IMMUDB TLS PROBE TESTS PASS: real TLS, explicit CA, hostname, curl defaults, redirect/HTTP failure rejection and origin validation.'
}
catch {
    Write-Host $_.ScriptStackTrace
    if ($null -ne $server -and $server.LastError.Length -gt 0) {
        Write-Host $server.LastError
    }
    throw
}
finally {
    $env:CURL_HOME = $savedCurlHome
    foreach ($resource in @($server, $redirectTarget, $authority, $otherAuthority)) {
        if ($null -ne $resource) { $resource.Dispose() }
    }
    $target = [IO.Path]::GetFullPath($work)
    $artifacts = [IO.Path]::GetFullPath((Join-Path $repoRoot 'artifacts')) + [IO.Path]::DirectorySeparatorChar
    if (-not $target.StartsWith($artifacts, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'TLS test cleanup escaped the artifacts directory.'
    }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
