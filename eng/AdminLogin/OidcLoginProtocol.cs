using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Fleetory.AdminLogin;

public sealed record LoginSettings(Uri Issuer, string ClientId, string Audience, Guid PersonId);

/// <summary>One ephemeral operator login. The caller must supply a TLS-validating,
/// redirect-disabled HttpClient without default credentials, cookies or proxies.</summary>
public sealed class OidcLoginProtocol : IDisposable
{
    public const string RedirectUriString = "http://127.0.0.1:48329/auth/callback";
    private const int JsonLimit = 65536;
    private readonly LoginSettings _settings;
    private readonly HttpClient _http;
    private string? _state;
    private string? _nonce;
    private string? _verifier;
    private Uri? _tokenEndpoint;
    private IReadOnlyCollection<SecurityKey>? _keys;
    private long _beginUnix;
    private int _begun;
    private int _completed;
    private int _disposed;

    public OidcLoginProtocol(LoginSettings settings, HttpClient http)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(http);
        if (!SafeHttps(settings.Issuer) || settings.Issuer.AbsolutePath == "/" ||
            settings.Issuer.AbsoluteUri.EndsWith('/') || settings.PersonId == Guid.Empty ||
            string.IsNullOrWhiteSpace(settings.ClientId) || settings.ClientId.Length > 256 ||
            string.IsNullOrWhiteSpace(settings.Audience) || settings.Audience.Length > 256)
            throw Failure();
        _settings = settings;
        _http = http;
    }

    public async Task<Uri> BeginAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (Interlocked.Exchange(ref _begun, 1) != 0) throw Failure();
        try
        {
            _beginUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            _state = Random(32); _nonce = Random(32); _verifier = Random(64);
            using var discovery = await SendJsonAsync(new HttpRequestMessage(HttpMethod.Get,
                _settings.Issuer.AbsoluteUri + "/.well-known/openid-configuration"), cancellationToken);
            var metadata = discovery.RootElement;
            if (Text(metadata, "issuer") != _settings.Issuer.AbsoluteUri) throw Failure();
            var authorization = Endpoint(Text(metadata, "authorization_endpoint"));
            _tokenEndpoint = Endpoint(Text(metadata, "token_endpoint"));
            var jwks = Endpoint(Text(metadata, "jwks_uri"));
            using var keys = await SendJsonAsync(new HttpRequestMessage(HttpMethod.Get, jwks), cancellationToken);
            var array = keys.RootElement.GetProperty("keys");
            if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() is < 1 or > 16) throw Failure();
            var eligible = new List<SecurityKey>();
            var kids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var key in array.EnumerateArray())
            {
                // Keycloak may also publish encryption keys and unrelated signing algorithms.
                if (Text(key, "kty") != "RSA" ||
                    key.TryGetProperty("alg", out var algorithm) && algorithm.GetString() != "RS256" ||
                    key.TryGetProperty("use", out var use) && use.GetString() != "sig") continue;
                var kid = Text(key, "kid");
                if (string.IsNullOrWhiteSpace(kid) || kid.Length > 128 || !kids.Add(kid) ||
                    new[] { "d", "p", "q", "dp", "dq", "qi", "oth" }.Any(name => key.TryGetProperty(name, out _)) ||
                    !ValidModulus(Text(key, "n")) ||
                    Base64UrlEncoder.DecodeBytes(Text(key, "e")).Length is < 1 or > 8) throw Failure();
                if (key.TryGetProperty("key_ops", out var operations) &&
                    (operations.ValueKind != JsonValueKind.Array || operations.GetArrayLength() != 1 ||
                     operations[0].ValueKind != JsonValueKind.String || operations[0].GetString() != "verify")) throw Failure();
                eligible.Add(new JsonWebKey(key.GetRawText()));
            }
            _keys = eligible;
            if (_keys.Count is < 1 or > 16) throw Failure();
            var query = new Dictionary<string, string>
            {
                ["client_id"] = _settings.ClientId, ["redirect_uri"] = RedirectUriString,
                ["response_type"] = "code", ["scope"] = "openid", ["state"] = _state,
                ["prompt"] = "login", ["max_age"] = "0",
                ["nonce"] = _nonce, ["code_challenge_method"] = "S256",
                ["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(_verifier)))
            };
            return new Uri(authorization.AbsoluteUri + "?" + string.Join('&', query.Select(
                pair => Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value))));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { Clear(); throw Failure(); }
    }

    public async Task<string> CompleteAsync(Uri callback, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (Interlocked.Exchange(ref _completed, 1) != 0) throw Failure();
        try
        {
            if (_keys is null || _state is null || _nonce is null || _verifier is null || _tokenEndpoint is null ||
                callback is null || !callback.IsAbsoluteUri || callback.Scheme != "http" ||
                callback.Host != "127.0.0.1" || callback.Port != 48329 || callback.AbsolutePath != "/auth/callback" ||
                callback.UserInfo.Length != 0 || callback.Fragment.Length != 0 || callback.AbsoluteUri.Length > 8192)
                throw Failure();
            var query = ParseQuery(callback.Query);
            if (!query.TryGetValue("state", out var state) || !FixedEquals(state, _state) ||
                !query.TryGetValue("code", out var code) || string.IsNullOrWhiteSpace(code) || code.Length > 4096 ||
                query.Keys.Any(key => key is not ("state" or "code" or "iss" or "session_state")) ||
                query.TryGetValue("iss", out var issuer) && issuer != _settings.Issuer.AbsoluteUri ||
                query.TryGetValue("session_state", out var sessionState) && sessionState.Length is < 1 or > 256) throw Failure();
            using var response = await SendJsonAsync(new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code", ["client_id"] = _settings.ClientId,
                    ["redirect_uri"] = RedirectUriString, ["code"] = code, ["code_verifier"] = _verifier
                })
            }, cancellationToken);
            var body = response.RootElement;
            if (!string.Equals(Text(body, "token_type"), "Bearer", StringComparison.OrdinalIgnoreCase) ||
                !body.GetProperty("expires_in").TryGetInt32(out var expires) || expires is < 1 or > 86400) throw Failure();
            var access = Text(body, "access_token");
            var id = Text(body, "id_token");
            using var idClaims = await ValidateAsync(id, _settings.ClientId);
            cancellationToken.ThrowIfCancellationRequested();
            using var accessClaims = await ValidateAsync(access, _settings.Audience);
            cancellationToken.ThrowIfCancellationRequested();
            ValidateIdFreshness(idClaims.RootElement);
            if (!FixedEquals(Text(idClaims.RootElement, "nonce"), _nonce) ||
                Text(accessClaims.RootElement, "azp") != _settings.ClientId ||
                !accessClaims.RootElement.GetProperty("amr").EnumerateArray().Any(
                    value => value.ValueKind == JsonValueKind.String && value.GetString() == "webauthn")) throw Failure();
            if (idClaims.RootElement.TryGetProperty("azp", out var idAzp) && idAzp.GetString() != _settings.ClientId) throw Failure();
            if (idClaims.RootElement.TryGetProperty("at_hash", out var atHash) &&
                !FixedEquals(atHash.GetString() ?? "", Base64UrlEncoder.Encode(
                    SHA256.HashData(Encoding.ASCII.GetBytes(access)).AsSpan(0, 16).ToArray()))) throw Failure();
            cancellationToken.ThrowIfCancellationRequested();
            return access;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw Failure(); }
        finally { Clear(); }
    }

    private void ValidateIdFreshness(JsonElement claims)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (!claims.GetProperty("auth_time").TryGetInt64(out var authTime) ||
            authTime < _beginUnix - 30 || authTime > now + 30 ||
            !claims.GetProperty("iat").TryGetInt64(out var issuedAt) ||
            issuedAt < _beginUnix - 30 || issuedAt > now + 30 || now - _beginUnix > 300)
            throw Failure();
        var audience = claims.GetProperty("aud");
        if (audience.ValueKind == JsonValueKind.Array && audience.GetArrayLength() > 1 &&
            (!claims.TryGetProperty("azp", out var azp) || azp.GetString() != _settings.ClientId)) throw Failure();
    }
    private async Task<JsonDocument> ValidateAsync(string token, string audience)
    {
        if (token.Length is < 1 or > 16384 || token.Any(character => character > 127)) throw Failure();
        var parts = token.Split('.');
        if (parts.Length != 3 || parts.Any(string.IsNullOrEmpty)) throw Failure();
        using var header = ParseJson(Base64UrlEncoder.DecodeBytes(parts[0]));
        if (Text(header.RootElement, "alg") != "RS256" || header.RootElement.TryGetProperty("crit", out _)) throw Failure();
        var kid = Text(header.RootElement, "kid");
        if (string.IsNullOrWhiteSpace(kid) || kid.Length > 128 || _keys is null ||
            !_keys.Any(key => key.KeyId == kid)) throw Failure();
        var claims = ParseJson(Base64UrlEncoder.DecodeBytes(parts[1]));
        try
        {
            var handler = new JsonWebTokenHandler { MaximumTokenSizeInBytes = 16384 };
            var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer = true, ValidIssuer = _settings.Issuer.AbsoluteUri,
                ValidateAudience = true, ValidAudience = audience, IgnoreTrailingSlashWhenValidatingAudience = false,
                ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true,
                ValidateIssuerSigningKey = true, IssuerSigningKeys = _keys,
                TryAllIssuerSigningKeys = false,
                IssuerSigningKeyResolver = (_, _, requestedKid, _) => _keys!.Where(key => key.KeyId == requestedKid),
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256], ClockSkew = TimeSpan.FromSeconds(30)
            });
            if (!result.IsValid || Text(claims.RootElement, "sub") != _settings.PersonId.ToString("D")) throw Failure();
            return claims;
        }
        catch { claims.Dispose(); throw; }
    }

    private async Task<JsonDocument> SendJsonAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using (request)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var expected = request.RequestUri;
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode || response.RequestMessage?.RequestUri != expected ||
                response.Content.Headers.ContentLength is > JsonLimit ||
                response.Content.Headers.ContentType?.MediaType != "application/json") throw Failure();
            await using var input = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var buffer = new MemoryStream();
            var chunk = new byte[4096];
            int read;
            while ((read = await input.ReadAsync(chunk, timeout.Token)) != 0)
            {
                if (buffer.Length + read > JsonLimit) throw Failure();
                buffer.Write(chunk, 0, read);
            }
            return ParseJson(buffer.ToArray());
        }
    }

    private Uri Endpoint(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !SafeHttps(uri) ||
            uri.Host != _settings.Issuer.Host || uri.Port != _settings.Issuer.Port ||
            !uri.AbsolutePath.StartsWith(_settings.Issuer.AbsolutePath + "/", StringComparison.Ordinal)) throw Failure();
        return uri;
    }
    private static bool ValidModulus(string encoded)
    {
        var bytes = Base64UrlEncoder.DecodeBytes(encoded);
        return bytes.Length is >= 256 and <= 1024 && bytes[0] != 0 &&
            (bytes.Length != 256 || bytes[0] >= 128);
    }
    private static bool SafeHttps(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == "https" &&
        uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0;
    private static string Random(int bytes) => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(bytes));
    private static string Text(JsonElement element, string name) => element.GetProperty(name).GetString() ?? throw Failure();
    private static bool FixedEquals(string left, string right) => CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));
    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var field in query.TrimStart('?').Split('&', StringSplitOptions.None))
        {
            var pair = field.Split('=', 2);
            if (pair.Length != 2) throw Failure();
            foreach (var part in pair)
                for (var i = 0; i < part.Length; i++)
                    if (part[i] == '%' && (i + 2 >= part.Length || !Uri.IsHexDigit(part[i + 1]) || !Uri.IsHexDigit(part[i + 2]))) throw Failure();
            var key = Uri.UnescapeDataString(pair[0].Replace('+', ' '));
            var value = Uri.UnescapeDataString(pair[1].Replace('+', ' '));
            if (!result.TryAdd(key, value)) throw Failure();
        }
        return result;
    }
    private static JsonDocument ParseJson(byte[] bytes)
    {
        if (bytes.Length > JsonLimit) throw Failure();
        var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
        try { Unique(document.RootElement); return document; }
        catch { document.Dispose(); throw; }
    }
    private static void Unique(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw Failure();
                Unique(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array) foreach (var item in element.EnumerateArray()) Unique(item);
    }
    private static InvalidOperationException Failure() => new("Operator login failed validation.");
    private void Clear() { _state = null; _nonce = null; _verifier = null; _keys = null; _tokenEndpoint = null; }
    public void Dispose() { Interlocked.Exchange(ref _disposed, 1); Clear(); }
}
