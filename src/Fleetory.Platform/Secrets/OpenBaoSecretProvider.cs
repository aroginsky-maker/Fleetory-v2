using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Fleetory.Platform.Contracts.Secrets;

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
        _client = handler is null ? new HttpClient() : new HttpClient(handler);
        _client.Timeout = TimeSpan.FromSeconds(5);
    }

    public string GetRequiredSecret(string name)
    {
        SecretName.Validate(name);
        return _cache.GetOrAdd(name, key => new Lazy<string>(
            () => ReadSecret(key), LazyThreadSafetyMode.ExecutionAndPublication)).Value;
    }

    private string ReadSecret(string name)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                new Uri(_baseAddress, "v1/secret/data/fleetory/" + name));
            request.Headers.Add("X-Vault-Token", _token);
            using var response = _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                .GetAwaiter().GetResult();
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException("Required OpenBao secret could not be read.");
            }

            using var stream = response.Content.ReadAsStream();
            using var buffer = new MemoryStream();
            var chunk = new byte[4096];
            int count;
            while ((count = stream.Read(chunk, 0, chunk.Length)) != 0)
            {
                buffer.Write(chunk, 0, count);
                if (buffer.Length > MaximumResponseBytes)
                {
                    throw new InvalidOperationException("OpenBao response is too large.");
                }
            }

            using var json = JsonDocument.Parse(StrictUtf8.GetString(buffer.ToArray()));
            var value = json.RootElement.GetProperty("data").GetProperty("data")
                .GetProperty("value").GetString();
            if (string.IsNullOrWhiteSpace(value) || value.Length > 16 * 1024)
            {
                throw new InvalidOperationException("OpenBao secret is empty or too large.");
            }

            return value;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or
            JsonException or DecoderFallbackException or KeyNotFoundException or TaskCanceledException)
        {
            throw new InvalidOperationException("Required OpenBao secret could not be read.");
        }
    }

    public void Dispose() => _client.Dispose();
}
