using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace ServerBackendProbe;

// Only the fresh fixed-origin fixture; no endpoint or file path is accepted as input.
internal sealed class FixtureAuditClient : IDisposable
{
    private readonly HttpClient _client = new(new HttpClientHandler { AllowAutoRedirect = false })
    { BaseAddress = new Uri("https://127.0.0.1:8090/"), Timeout = TimeSpan.FromSeconds(5) };

    internal static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    internal static string EventKey(Guid id) => Encode("fleetory/audit/v1/" + id.ToString("N"));

    internal static async Task<JsonDocument> ReadPacketAsync(CancellationToken cancellation)
    {
        var bytes = new byte[4097];
        var length = 0;
        var input = Console.OpenStandardInput();
        while (length < bytes.Length)
        {
            var read = await input.ReadAsync(bytes.AsMemory(length), cancellation);
            if (read == 0) { break; }
            length += read;
        }
        if (length > 4096) { throw new InvalidOperationException("Fixture packet too large."); }
        return JsonDocument.Parse(bytes.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 4 });
    }

    internal static string Secret(JsonElement packet, string name)
    {
        var value = packet.GetProperty(name).GetString();
        if (value?.Length != 64 || value.Any(character => !char.IsAsciiHexDigitLower(character)))
        { throw new InvalidOperationException("Fixture credential format refused."); }
        return value;
    }

    internal async Task LoginAsync(JsonElement packet, CancellationToken cancellation)
    {
        var login = await SendAsync(HttpMethod.Post, "api/login", new { user = Encode("immudb"), password = Encode(Secret(packet, "admin")) }, cancellation);
        SetToken(login);
    }

    internal async Task SelectDatabaseAsync(CancellationToken cancellation) =>
        SetToken(await SendAsync(HttpMethod.Get, "api/db/use/fleetoryaudit", null, cancellation));

    private void SetToken(JsonElement response)
    {
        var token = response.GetProperty("token").GetString();
        if (string.IsNullOrWhiteSpace(token) || token.Length > 8192 || token.Any(char.IsWhiteSpace))
        { throw new InvalidOperationException("Fixture token format refused."); }
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    internal async Task<JsonElement> SendAsync(HttpMethod method, string path, object? body, CancellationToken cancellation)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null) { request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"); }
        using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation);
        if (!response.IsSuccessStatusCode) { throw new InvalidOperationException("Fixture control request refused.") { Data = { ["fixtureHttpStatus"] = (int)response.StatusCode } }; }
        await using var stream = await response.Content.ReadAsStreamAsync(cancellation);
        var buffer = new byte[16385];
        var count = 0;
        while (count < buffer.Length)
        {
            var size = await stream.ReadAsync(buffer.AsMemory(count), cancellation);
            if (size == 0) { break; }
            count += size;
        }
        if (count > 16384) { throw new InvalidOperationException("Fixture response too large."); }
        using var document = JsonDocument.Parse(buffer.AsMemory(0, count));
        return document.RootElement.Clone();
    }

    public void Dispose() => _client.Dispose();
}
