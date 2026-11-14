# Regression checks against real TLS peers; no OS trust changes or production tokens.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'eng/immudb-http.ps1')
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') `
    -Source (Join-Path $repoRoot 'eng/verify-immudb-state.ps1') -Names @('Get-ImmudbState')
. (Join-Path $PSScriptRoot 'TestProvisionerHelpers.ps1') `
    -Source (Join-Path $repoRoot 'eng/verify-immudb-restore.ps1') -Names @('Invoke-ImmudbRestoreGetJson')

$compiler = @{ Path = (Join-Path $PSScriptRoot 'TlsProbeTestServer.cs') }
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $compiler.ReferencedAssemblies = @('System.dll', 'System.Core.dll', 'System.Net.Http.dll')
}
Add-Type @compiler
$productionFactory = (Get-Command New-ImmudbHttpHandler).ScriptBlock
$certificate = $null
$server = $null
$target = $null
$sentinel = 'fleetory-disposable-test-bearer'
$script:rejections = 0

function Assert-Throws([scriptblock] $Action, [string] $Expected) {
    try { & $Action } catch {
        if ($_.ToString().Contains($sentinel)) { throw 'A transport failure exposed the bearer token.' }
        if ($_.Exception.Message -notlike "*$Expected*") { throw }
        $script:rejections++
        return
    }
    throw 'An unsafe immudb transport response was accepted.'
}

try {
    $certificate = [TlsProbeTestServer]::CreateCertificate()
    $server = [TlsProbeTestServer]::new($certificate)
    $target = [TlsProbeTestServer]::new($certificate)
    $origin = [uri]("https://localhost:{0}/" -f $server.Port)
    $server.Body = [Text.Encoding]::UTF8.GetBytes('{"db":"defaultdb","txId":42}')

    # Default OS trust must reject the untrusted fixture certificate.
    Assert-Throws { Get-ImmudbState $origin $sentinel } 'Could not read'
    if ($server.Requests -ne 0) { throw 'An untrusted TLS peer received a token-bearing request.' }

    function New-ImmudbHttpHandler {
        $handler = & $productionFactory
        if ($handler.AllowAutoRedirect -or $handler.UseCookies -or $handler.UseProxy -or
            -not $handler.CheckCertificateRevocationList) { throw 'Unsafe transport defaults.' }
        [TlsProbeTestServer]::PinClient($handler, $certificate)
        return $handler
    }
    $state = Get-ImmudbState $origin $sentinel
    if ($state.txId -ne 42 -or $server.LastPath -cne '/api/db/state' -or
        $server.LastAuthorization -cne ('Bearer ' + $sentinel)) {
        throw 'The state request did not use the expected TLS path and credential.'
    }
    [void](Invoke-ImmudbRestoreGetJson $origin $sentinel 'api/db/use/defaultdb' 'Restore read failed.')
    if ($server.LastPath -cne '/api/db/use/defaultdb') { throw 'The restore path changed.' }
    [void](Get-ImmudbState $origin '')
    if ($server.LastAuthorization.Length -ne 0) { throw 'Anonymous state verification retained a credential.' }
    $beforeMismatch = $server.Requests
    Assert-Throws { Get-ImmudbState ([uri]("https://127.0.0.1:{0}/" -f $server.Port)) $sentinel } 'Could not read'
    if ($server.Requests -ne $beforeMismatch) { throw 'A hostname mismatch exposed a token-bearing request.' }

    foreach ($address in @('http://localhost/', 'https://user:secret@localhost/',
        'https://localhost/api/db/', 'https://localhost/?token=x', 'https://localhost/#fragment', '/relative')) {
        Assert-Throws { Get-ImmudbState ([uri]$address) $sentinel } 'HTTPS origin'
    }
    foreach ($token in @("$sentinel`r`nInjected: true", ('A' * 8193))) {
        Assert-Throws { Get-ImmudbState $origin $token } 'token format is invalid'
    }
    foreach ($path in @('https://other.example/', '//other.example/', 'api/db/../../other',
        'api/db/state?token=x', 'api/db/state#fragment')) {
        Assert-Throws { Invoke-ImmudbGetJson $origin $sentinel $path 'Read failed.' } 'read path'
    }

    $server.Location = "https://localhost:$($target.Port)/api/db/state"
    foreach ($status in @(301, 302, 303, 307, 308)) {
        $server.Status = $status
        Assert-Throws { Get-ImmudbState $origin $sentinel } 'returned a redirect'
        Assert-Throws { Invoke-ImmudbRestoreGetJson $origin $sentinel 'api/db/use/defaultdb' 'Restore read failed.' } 'returned a redirect'
    }
    if ($target.Requests -ne 0 -or $target.LastAuthorization.Length -ne 0) {
        throw 'A redirect target received an immudb verification request.'
    }
    $server.Location = ''
    $server.Status = 503
    $server.Body = [Text.Encoding]::UTF8.GetBytes($sentinel)
    Assert-Throws { Get-ImmudbState $origin $sentinel } 'Could not read'
    $server.Status = 200
    foreach ($body in @('{broken', '[]', 'null')) {
        $server.Body = [Text.Encoding]::UTF8.GetBytes($body)
        Assert-Throws { Get-ImmudbState $origin $sentinel } 'UTF-8 JSON object'
    }
    $server.Body = [byte[]](0xFF)
    Assert-Throws { Get-ImmudbState $origin $sentinel } 'UTF-8 JSON object'
    $prefix = '{"value":"'
    $suffix = '"}'
    $valueLength = 16KB - $prefix.Length - $suffix.Length
    $server.Body = [Text.Encoding]::UTF8.GetBytes($prefix + ('A' * $valueLength) + $suffix)
    if ((Get-ImmudbState $origin $sentinel).value.Length -ne $valueLength) {
        throw 'The exact 16 KiB response boundary was rejected.'
    }
    $server.Body = [Text.Encoding]::UTF8.GetBytes('{"value":"' + ('A' * 20000) + '"}')
    Assert-Throws { Get-ImmudbState $origin $sentinel } 'response is too large'
    $server.Chunked = $true
    Assert-Throws { Get-ImmudbState $origin $sentinel } 'response is too large'
    $server.Chunked = $false
    $server.OmitContentLength = $true
    Assert-Throws { Invoke-ImmudbRestoreGetJson $origin $sentinel 'api/db/get/key' 'Restore read failed.' } 'response is too large'
    $server.OmitContentLength = $false
    $server.Body = [Text.Encoding]::UTF8.GetBytes('{"ok":true}')
    $server.DelayBodyMilliseconds = 1500
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    Assert-Throws { Invoke-ImmudbGetJson $origin $sentinel 'api/db/state' 'Read deadline exceeded.' -TimeoutMilliseconds 200 } 'Read deadline exceeded'
    if ($elapsed.ElapsedMilliseconds -ge 1200) { throw 'The body read exceeded its total deadline.' }
    Write-Host "IMMUDB HTTP TRANSPORT TESTS PASS: $script:rejections negative cases, real TLS, token isolation, streaming limit and total deadline."
}
finally {
    foreach ($resource in @($server, $target, $certificate)) {
        if ($null -ne $resource) { $resource.Dispose() }
    }
}
