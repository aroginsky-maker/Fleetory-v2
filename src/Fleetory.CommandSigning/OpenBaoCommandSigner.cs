using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Fleetory.Core.Contracts;

namespace Fleetory.CommandSigning;

/// <summary>Low-risk command signing component for an isolated signer process, never Fleetory Server.</summary>
public sealed class OpenBaoCommandSigner : IDisposable
{
    private readonly HttpClient _client;
    private readonly string _token;
    private readonly string _keyName;
    private readonly int _keyVersion;
    private readonly string _signingKeyId;
    private readonly byte[] _publicKey;
    private readonly TimeSpan _requestTimeout;

    public OpenBaoCommandSigner(
        Uri address,
        string token,
        string keyName,
        int keyVersion,
        ReadOnlySpan<byte> publicKey,
        bool allowHttpLoopback = false)
        : this(address, token, keyName, keyVersion, publicKey, allowHttpLoopback, null)
    {
    }

    internal OpenBaoCommandSigner(
        Uri address,
        string token,
        string keyName,
        int keyVersion,
        ReadOnlySpan<byte> publicKey,
        bool allowHttpLoopback,
        HttpMessageHandler? handler,
        TimeSpan? requestTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!address.IsAbsoluteUri || !string.IsNullOrEmpty(address.UserInfo) ||
            address.AbsolutePath != "/" || !string.IsNullOrEmpty(address.Query) ||
            !string.IsNullOrEmpty(address.Fragment) ||
            !(address.Scheme == Uri.UriSchemeHttps ||
              allowHttpLoopback && address.Scheme == Uri.UriSchemeHttp && address.IsLoopback))
        {
            throw new ArgumentException("OpenBao requires an HTTPS origin or explicit lab loopback HTTP.", nameof(address));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        if (token.Length > 8192 || token.Any(character => character <= ' ' || character >= '\u007f'))
        {
            throw new ArgumentException("The Transit credential must contain at most 8192 visible ASCII characters.", nameof(token));
        }
        _requestTimeout = requestTimeout ?? TimeSpan.FromSeconds(10);
        if (_requestTimeout <= TimeSpan.Zero || _requestTimeout > TimeSpan.FromSeconds(10))
        {
            throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        }
        if (!IsIdentifier(keyName) || keyVersion < 1 || keyVersion > 999999)
        {
            throw new ArgumentException("Transit key name or version is invalid.");
        }

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
        if (bytesRead != publicKey.Length || ecdsa.KeySize != 256 ||
            ecdsa.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            throw new ArgumentException("A pinned P-256 public key is required.", nameof(publicKey));
        }

        _token = token;
        _keyName = keyName;
        _keyVersion = keyVersion;
        _signingKeyId = $"{keyName}-v{keyVersion}";
        _publicKey = publicKey.ToArray();
        _client = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false
        }, true)
        {
            BaseAddress = address,
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    public async Task<SignedCommandEnvelope> SignInventoryRefreshAsync(
        DeviceId targetDeviceId,
        CancellationToken cancellationToken = default)
    {
        if (targetDeviceId.Value == Guid.Empty)
        {
            throw new ArgumentException("A target DeviceId is required.", nameof(targetDeviceId));
        }
        cancellationToken.ThrowIfCancellationRequested();
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lifetime.CancelAfter(_requestTimeout);
        var operationToken = lifetime.Token;

        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedCommandEnvelope(
            targetDeviceId, Guid.NewGuid(), AgentCommandTypes.InventoryRefresh, [], now,
            now.AddMinutes(1), Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            _signingKeyId, []);

        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"v1/transit/sign/{_keyName}/sha2-256");
        request.Headers.Add("X-Vault-Token", _token);
        request.Content = JsonContent.Create(new
        {
            input = Convert.ToBase64String(unsigned.GetSigningBytes()),
            key_version = _keyVersion,
            marshaling_algorithm = "jws",
            prehashed = false
        });

        using var response = await _client.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, operationToken);
        if (!response.IsSuccessStatusCode)
        {
            // ReasonPhrase and response bodies are controlled by the remote peer.
            throw new HttpRequestException("Transit signing request failed.", null, response.StatusCode);
        }
        var transitSignature = await ReadTransitSignatureAsync(response.Content, operationToken);
        var prefix = $"vault:v{_keyVersion}:";
        if (transitSignature is null || !transitSignature.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new CryptographicException("Transit signed with an unexpected key version.");
        }

        byte[] signature;
        try
        {
            var encoded = transitSignature[prefix.Length..];
            signature = Convert.FromBase64String(
                encoded.Replace('-', '+').Replace('_', '/') + new string('=', (4 - encoded.Length % 4) % 4));
        }
        catch (FormatException)
        {
            throw new CryptographicException("Transit returned an invalid signature encoding.");
        }

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(_publicKey, out _);
        if (signature.Length != 64 || !ecdsa.VerifyData(
                unsigned.GetSigningBytes(), signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new CryptographicException("Transit signature failed local verification.");
        }
        operationToken.ThrowIfCancellationRequested();

        return new SignedCommandEnvelope(
            unsigned.TargetDeviceId, unsigned.CommandId, unsigned.CommandType, [],
            unsigned.IssuedAt, unsigned.ExpiresAt, unsigned.Nonce, unsigned.SigningKeyId, signature);
    }

    public void Dispose() => _client.Dispose();

    private static async Task<string> ReadTransitSignatureAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await content.LoadIntoBufferAsync(4096, cancellationToken);
        try
        {
            using var body = await JsonDocument.ParseAsync(
                await content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
            if (body.RootElement.ValueKind != JsonValueKind.Object ||
                !body.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object ||
                !data.TryGetProperty("signature", out var signature) || signature.ValueKind != JsonValueKind.String)
            {
                throw new CryptographicException("Transit returned an invalid signature response.");
            }
            return signature.GetString()!;
        }
        catch (JsonException)
        {
            throw new CryptographicException("Transit returned an invalid JSON response.");
        }
    }

    private static bool IsIdentifier(string? value) =>
        !string.IsNullOrEmpty(value) && value.Length <= 96 &&
        value.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}
