# Fleetory immudb TLS endpoint preflight.
# The probe is read-only and sends no credentials.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri] $Address,
    [Parameter(Mandatory)][string] $RootCertificatePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $Address.IsAbsoluteUri -or $Address.Scheme -ne 'https' -or
    -not [string]::IsNullOrEmpty($Address.UserInfo) -or
    $Address.AbsolutePath -ne '/' -or
    -not [string]::IsNullOrEmpty($Address.Query) -or
    -not [string]::IsNullOrEmpty($Address.Fragment)) {
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
$curlName = if ($env:OS -eq 'Windows_NT') { 'curl.exe' } else { 'curl' }
$curl = Get-Command $curlName -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $curl) {
    throw 'curl is required for the immudb TLS probe.'
}

$nullDevice = if ($env:OS -eq 'Windows_NT') { 'NUL' } else { '/dev/null' }
# Disable user curl configuration before any other option. A HEAD request avoids
# downloading response bodies; direct transport avoids environment proxy trust.
$curlArgs = @(
    '--disable', '--silent', '--show-error', '--head', '--output', $nullDevice,
    '--write-out', '%{http_code}', '--proto', '=https', '--tlsv1.2',
    '--noproxy', '*', '--connect-timeout', '5', '--max-time', '15',
    '--max-redirs', '0', '--cacert', $root, $Address.AbsoluteUri)
try {
    $statusText = (& $curl.Source @curlArgs 2>$null | Out-String).Trim()
}
catch { throw 'The immudb TLS handshake or certificate validation failed.' }
if ($LASTEXITCODE -ne 0) { throw 'The immudb TLS handshake or certificate validation failed.' }
$status = 0
if (-not [int]::TryParse($statusText, [ref]$status) -or $status -lt 200 -or $status -ge 300) {
    throw 'The immudb TLS origin must return HTTP 2xx without a redirect.'
}
[ordered]@{
    schema = 'fleetory.immudb-tls-probe.v1'
    address = $Address.GetLeftPart([UriPartial]::Authority)
    httpStatus = $status
    # Digest of the exact supplied PEM file, not the certificate's DER fingerprint.
    rootCertificateSha256 = (Get-FileHash -LiteralPath $root -Algorithm SHA256).Hash
    verified = $true
} | ConvertTo-Json -Compress
