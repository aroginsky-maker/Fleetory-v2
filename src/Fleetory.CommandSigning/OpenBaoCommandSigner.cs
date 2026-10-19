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
        HttpMessageHandler? handler)
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
        _client = new HttpClient(handler ?? new SocketsHttpHandler { AllowAutoRedirect = false }, true)
        {
            BaseAddress = address,
            Timeout = TimeSpan.FromSeconds(10)
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
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        await response.Content.LoadIntoBufferAsync(4096, cancellationToken);
        using var body = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        var transitSignature = body.RootElement.GetProperty("data").GetProperty("signature").GetString();
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
        catch (FormatException exception)
        {
            throw new CryptographicException("Transit returned an invalid signature encoding.", exception);
        }

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(_publicKey, out _);
        if (signature.Length != 64 || !ecdsa.VerifyData(
                unsigned.GetSigningBytes(), signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new CryptographicException("Transit signature failed local verification.");
        }

        return new SignedCommandEnvelope(
            unsigned.TargetDeviceId, unsigned.CommandId, unsigned.CommandType, [],
            unsigned.IssuedAt, unsigned.ExpiresAt, unsigned.Nonce, unsigned.SigningKeyId, signature);
    }

    public void Dispose() => _client.Dispose();

    private static bool IsIdentifier(string? value) =>
        !string.IsNullOrEmpty(value) && value.Length <= 96 &&
        value.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}
