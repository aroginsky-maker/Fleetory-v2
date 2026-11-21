using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Fleetory.Platform.Contracts.Secrets;
using Fleetory.Security.Infrastructure;

namespace Fleetory.Platform.Secrets;

/// <summary>Reads bounded KV v2 secrets at secret/data/fleetory/{name} once per process.</summary>
public sealed class OpenBaoSecretProvider : ISecretProvider, IDisposable
{
    private const int MaximumResponseBytes = 20 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly Uri _baseAddress;
    private readonly string _token;
    private readonly HttpClient _client;
    private readonly ConcurrentDictionary<string, Lazy<string>> _cache = new(StringComparer.Ordinal);

    public OpenBaoSecretProvider(Uri address, string token, bool allowInsecureLoopback = false,
        HttpMessageHandler? handler = null)
    {
        HttpOriginPolicy.Validate(address, allowInsecureLoopback, "OpenBao");

        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        if (token.Length > 512 || token.Any(character =>
                character is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or
                    >= '0' and <= '9' or '-' or '_' or '.')))
        {
            throw new ArgumentException("OpenBao token format is invalid.", nameof(token));
        }
        _baseAddress = address;
        _token = token;
        _client = HttpOriginPolicy.CreateNonRedirectingClient(handler);
        _client.Timeout = Timeout.InfiniteTimeSpan;
    }

    public string GetRequiredSecret(string name)
    {
        SecretName.Validate(name);
        return _cache.GetOrAdd(name, key => new Lazy<string>(
            () => ReadSecretAsync(key).GetAwaiter().GetResult(),
            LazyThreadSafetyMode.ExecutionAndPublication)).Value;
    }

    private async Task<string> ReadSecretAsync(string name)
    {
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var cancellationToken = deadline.Token;
            using var request = new HttpRequestMessage(HttpMethod.Get,
                new Uri(_baseAddress, "v1/secret/data/fleetory/" + name));
            request.Headers.Add("X-Vault-Token", _token);
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException("Required OpenBao secret could not be read.");
            }

            var bytes = await BoundedHttpContentReader.ReadAsync(response.Content,
                MaximumResponseBytes, cancellationToken).ConfigureAwait(false);
            using var json = JsonDocument.Parse(StrictUtf8.GetString(bytes));
            var value = json.RootElement.GetProperty("data").GetProperty("data")
                .GetProperty("value").GetString();
            if (string.IsNullOrWhiteSpace(value) || value.Length > 16 * 1024)
            {
                throw new InvalidOperationException("OpenBao secret is empty or too large.");
            }

            return value;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or
            JsonException or DecoderFallbackException or KeyNotFoundException or OperationCanceledException)
        {
            throw new InvalidOperationException("Required OpenBao secret could not be read.");
        }
    }

    public void Dispose() => _client.Dispose();
}
