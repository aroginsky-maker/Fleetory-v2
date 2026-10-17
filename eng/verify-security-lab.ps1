$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$labDirectory = Join-Path (Split-Path -Parent $repoRoot) 'work/security-lab'
$tokenFile = Join-Path $labDirectory 'openbao-token'
$serverDll = Join-Path $repoRoot 'src/Fleetory.Server/bin/Debug/net10.0/Fleetory.Server.dll'
$stdoutPath = Join-Path $labDirectory 'fleetory-server.stdout.log'
$stderrPath = Join-Path $labDirectory 'fleetory-server.stderr.log'
$healthUri = 'http://127.0.0.1:5088/health/ready'

if (-not (Test-Path -LiteralPath $serverDll) -or -not (Test-Path -LiteralPath $tokenFile)) {
    throw 'Build Fleetory.Server and start the security lab first.'
}

$env:FLEETORY_Fleetory__Secrets__Provider = 'OpenBao'
$env:FLEETORY_Fleetory__Secrets__Address = 'http://127.0.0.1:8200/'
$env:FLEETORY_Fleetory__Secrets__TokenDirectory = $labDirectory

$server = $null
try {
    $server = Start-Process -FilePath 'dotnet' -ArgumentList @(
        ('"' + $serverDll + '"'), '--environment=Development',
        '--urls=http://127.0.0.1:5088') -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

    $healthy = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Seconds 1
        if ($server.HasExited) { break }
        try {
            $response = Invoke-WebRequest -Uri $healthUri -TimeoutSec 2
            if ($response.StatusCode -eq 200) { $healthy = $true; break }
        }
        catch { }
    }

    if (-not $healthy) {
        throw "Fleetory did not become ready with OpenBao. See $stderrPath"
    }

    Write-Host 'Fleetory /health/ready returned 200 with OpenBao-backed PostgreSQL configuration.'
}
finally {
    if ($null -ne $server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        $server.WaitForExit()
    }
    Remove-Item Env:FLEETORY_Fleetory__Secrets__Provider -ErrorAction SilentlyContinue
    Remove-Item Env:FLEETORY_Fleetory__Secrets__Address -ErrorAction SilentlyContinue
    Remove-Item Env:FLEETORY_Fleetory__Secrets__TokenDirectory -ErrorAction SilentlyContinue
}
