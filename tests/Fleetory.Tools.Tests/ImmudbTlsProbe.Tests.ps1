# UTF-8 with BOM keeps this PowerShell test usable on Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$probe = Join-Path $repoRoot 'eng/verify-immudb-tls.ps1'
$work = Join-Path $repoRoot ('artifacts/immudb-tls-probe-test-' +
    [Guid]::NewGuid().ToString('N'))

function Assert-Throws([scriptblock] $Action, [string] $Message) {
    $thrown = $false
    try { & $Action } catch { $thrown = $true }
    if (-not $thrown) { throw $Message }
}

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $root = Join-Path $work 'root.pem'
    [IO.File]::WriteAllText($root, 'temporary test certificate', [Text.UTF8Encoding]::new($false))

    Assert-Throws { & $probe -Address ([uri]'http://audit.example/') -RootCertificatePath $root } `
        'HTTP immudb origin was accepted.'
    Assert-Throws { & $probe -Address ([uri]'https://user:password@audit.example/') -RootCertificatePath $root } `
        'Embedded TLS credentials were accepted.'
    Assert-Throws { & $probe -Address ([uri]'https://audit.example/') -RootCertificatePath 'relative.pem' } `
        'Relative root certificate path was accepted.'
    Assert-Throws { & $probe -Address ([uri]'https://audit.example/') -RootCertificatePath (Join-Path $work 'missing.pem') } `
        'Missing root certificate was accepted.'
    Write-Host 'IMMUDB TLS PROBE TESTS PASS: HTTPS-only origin, credential rejection and root-path validation.'
}
finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
