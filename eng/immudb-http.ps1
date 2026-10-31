# Shared, read-only transport for immudb operational verification.
Add-Type -AssemblyName System.Net.Http

function New-ImmudbHttpHandler {
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $handler.UseProxy = $false
    $handler.CheckCertificateRevocationList = $true
    $handler.SslProtocols = [Security.Authentication.SslProtocols]::Tls12
    if ([Enum]::IsDefined([Security.Authentication.SslProtocols], 'Tls13')) {
        $handler.SslProtocols = $handler.SslProtocols -bor [Security.Authentication.SslProtocols]::Tls13
    }
    return $handler
}

function Invoke-ImmudbGetJson(
    [uri] $Origin, [string] $Token, [string] $Path, [string] $FailureMessage,
    [ValidateRange(1, 20000)][int] $TimeoutMilliseconds = 20000) {
    if (-not $Origin.IsAbsoluteUri -or $Origin.Scheme -ne 'https' -or
        -not [string]::IsNullOrEmpty($Origin.UserInfo) -or $Origin.AbsolutePath -ne '/' -or
        -not [string]::IsNullOrEmpty($Origin.Query) -or
        -not [string]::IsNullOrEmpty($Origin.Fragment)) {
        throw 'immudb verification requires an HTTPS origin without credentials, path, query or fragment.'
    }
    if (-not [string]::IsNullOrEmpty($Token) -and ($Token.Length -gt 8192 -or $Token -match '\s')) {
        throw 'The immudb bearer token format is invalid.'
    }
    if (-not $Path.StartsWith('api/db/', [StringComparison]::Ordinal) -or
        $Path.IndexOfAny([char[]]@('?', '#', '\')) -ge 0 -or
        -not [uri]::IsWellFormedUriString($Path, [UriKind]::Relative)) {
        throw 'The immudb read path is invalid.'
    }
    $uri = [uri]::new($Origin, $Path)
    if (-not $uri.AbsolutePath.StartsWith('/api/db/', [StringComparison]::Ordinal)) {
        throw 'The immudb read path escaped the API.'
    }

    $handler = New-ImmudbHttpHandler
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMilliseconds)
    $deadline = [Threading.CancellationTokenSource]::new($TimeoutMilliseconds)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $request = $null
    $response = $null
    $bodyStream = $null
    $buffered = [IO.MemoryStream]::new()
    $failure = $FailureMessage
    try {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $uri)
        if (-not [string]::IsNullOrEmpty($Token)) {
            $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token)
        }
        $response = $client.SendAsync($request,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token).GetAwaiter().GetResult()
        if ([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -lt 400) {
            $failure = 'The immudb verification endpoint returned a redirect.'
            throw $failure
        }
        if (-not $response.IsSuccessStatusCode) { throw $failure }
        if ($null -ne $response.Content.Headers.ContentLength -and
            $response.Content.Headers.ContentLength -gt 16KB) {
            $failure = 'The immudb response is too large.'
            throw $failure
        }
        $bodyStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $buffer = New-Object byte[] 4096
        while ($true) {
            $remaining = $TimeoutMilliseconds - $clock.ElapsedMilliseconds
            if ($remaining -le 0) { throw $failure }
            $count = [int][Math]::Min($buffer.Length, 16KB + 1 - $buffered.Length)
            $readTask = $bodyStream.ReadAsync($buffer, 0, $count, $deadline.Token)
            # A hard wait also bounds older .NET streams that ignore cancellation.
            if (-not $readTask.Wait([int]$remaining)) { throw $failure }
            $read = $readTask.GetAwaiter().GetResult()
            if ($read -eq 0) { break }
            if ($buffered.Length + $read -gt 16KB) {
                $failure = 'The immudb response is too large.'
                throw $failure
            }
            $buffered.Write($buffer, 0, $read)
        }
        $failure = 'The immudb response is not a UTF-8 JSON object.'
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($buffered.ToArray())
        if ($json -notmatch '^\s*\{') { throw $failure }
        return $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch { throw $failure }
    finally {
        $deadline.Cancel()
        foreach ($resource in @($bodyStream, $buffered, $response, $request, $client, $handler, $deadline)) {
            if ($null -ne $resource) { $resource.Dispose() }
        }
    }
}
