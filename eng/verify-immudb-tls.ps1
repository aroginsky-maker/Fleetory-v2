# Fleetory immudb TLS endpoint preflight.
# The probe is read-only and sends no credentials.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri] $Address,
    [Parameter(Mandatory)][string] $RootCertificatePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Address.Scheme -ne 'https' -or -not [string]::IsNullOrWhiteSpace($Address.UserInfo)) {
    throw 'The immudb TLS probe requires an HTTPS origin without embedded credentials.'
}
if ([string]::IsNullOrWhiteSpace($RootCertificatePath) -or
    $RootCertificatePath -notmatch '^(?:[A-Za-z]:[\\/]|\\\\|/)') {
    throw 'The root certificate path must be absolute.'
}
$root = [IO.Path]::GetFullPath($RootCertificatePath)
if (-not (Test-Path -LiteralPath $root -PathType Leaf)) {
    throw 'The root certificate file does not exist.'
}
$rootItem = Get-Item -LiteralPath $root -Force
if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'The root certificate cannot be a symbolic link.'
}
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    throw 'curl.exe is required for the immudb TLS probe.'
}

$temporary = [IO.Path]::GetTempFileName()
try {
    $curlArgs = @(
        '--silent', '--show-error', '--output', $temporary,
        '--write-out', '%{http_code}', '--proto', '=https', '--tlsv1.2',
        '--max-redirs', '0', '--cacert', $root, $Address.AbsoluteUri)
    $statusText = (& curl.exe @curlArgs 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'The immudb TLS handshake or certificate validation failed.' }
    $status = 0
    if (-not [int]::TryParse($statusText, [ref]$status) -or $status -lt 100) {
        throw 'The immudb TLS probe returned an invalid HTTP status.'
    }
    [ordered]@{
        schema = 'fleetory.immudb-tls-probe.v1'
        address = $Address.GetLeftPart([UriPartial]::Authority)
        httpStatus = $status
        rootCertificateSha256 = (Get-FileHash -LiteralPath $root -Algorithm SHA256).Hash
        verified = $true
    } | ConvertTo-Json -Compress
}
finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}
