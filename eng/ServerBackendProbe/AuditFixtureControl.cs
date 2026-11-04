using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace ServerBackendProbe;

// Control only the fresh network-none immudb fixture at a fixed loopback origin.
internal static class AuditFixtureControl
{
    internal static async Task ExecuteAsync(string mode, CancellationToken cancellation)
    {
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { BaseAddress = new Uri("https://127.0.0.1:8090/"), Timeout = TimeSpan.FromSeconds(5) };
        if (mode == "audit-health")
        {
            var health = await SendAsync(client, HttpMethod.Get, "api/health", null, cancellation);
            if (!health.GetProperty("status").GetBoolean()) { throw new InvalidOperationException("Fixture audit not healthy."); }
            return;
        }
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
        using var packet = JsonDocument.Parse(bytes.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 4 });
        string Secret(string name)
        {
            var value = packet.RootElement.GetProperty(name).GetString();
            if (value?.Length != 64 || value.Any(character => !char.IsAsciiHexDigitLower(character)))
            { throw new InvalidOperationException("Fixture credential format refused."); }
            return value;
        }
        var login = await SendAsync(client, HttpMethod.Post, "api/login", new { user = Encode("immudb"), password = Encode(Secret("admin")) }, cancellation);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.GetProperty("token").GetString());
        if (mode == "audit-prepare")
        {
            await SendAsync(client, HttpMethod.Post, "api/db/create/v2", new { name = "fleetoryaudit" }, cancellation);
            foreach (var item in new[] { ("fixture_writer", "writer", 2), ("fixture_reader", "reader", 1) })
            {
                await SendAsync(client, HttpMethod.Post, "api/user", new
                { user = Encode(item.Item1), password = Encode(Secret(item.Item2)), permission = item.Item3, database = "fleetoryaudit" }, cancellation);
            }
            var users = await SendAsync(client, HttpMethod.Get, "api/user/list", null, cancellation);
            foreach (var item in new[] { ("fixture_writer", 2), ("fixture_reader", 1) })
            {
                var found = users.GetProperty("users").EnumerateArray().Where(user => user.GetProperty("user").GetString() == Encode(item.Item1)).ToArray();
                if (found.Length != 1 || !found[0].GetProperty("active").GetBoolean()) { throw new InvalidOperationException("Fixture user unavailable."); }
                var permissions = found[0].GetProperty("permissions").EnumerateArray().ToArray();
                if (permissions.Length != 1 || permissions[0].GetProperty("database").GetString() != "fleetoryaudit" ||
                    permissions[0].GetProperty("permission").GetInt32() != item.Item2) { throw new InvalidOperationException("Fixture user privilege drift."); }
            }
            return;
        }
        var selected = await SendAsync(client, HttpMethod.Get, "api/db/use/fleetoryaudit", null, cancellation);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", selected.GetProperty("token").GetString());
        var key = Encode("fleetory/audit/v1/" + AuditCases.EventId.ToString("N"));
        var scan = await SendAsync(client, HttpMethod.Post, "api/db/scan", new { prefix = Encode("fleetory/audit/v1/"), limit = 2 }, cancellation);
        var entries = scan.GetProperty("entries").EnumerateArray().ToArray();
        if (entries.Length != 1 || entries[0].GetProperty("key").GetString() != key)
        { throw new InvalidOperationException("Fixture audit event count drift."); }
        var stored = await SendAsync(client, HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(key), null, cancellation);
        if (stored.GetProperty("revision").GetString() != "1" || stored.GetProperty("key").GetString() != key)
        { throw new InvalidOperationException("Fixture audit revision drift."); }
        using var value = JsonDocument.Parse(Convert.FromBase64String(stored.GetProperty("value").GetString()!));
        var entry = value.RootElement;
        if (entry.EnumerateObject().Count() != 10 || entry.GetProperty("Action").GetString() != "Fixture.Audit.Read" ||
            entry.GetProperty("eventId").GetString() != AuditCases.EventId.ToString("N") ||
            entry.GetProperty("actorSubjectId").GetString() != "fixture:operator" || entry.GetProperty("actorKind").GetInt32() != 1 ||
            entry.GetProperty("targetType").GetString() != "Fixture" || entry.GetProperty("targetId").GetString() != "generated" ||
            entry.GetProperty("correlationId").GetString() != "fixture-export" ||
            entry.GetProperty("occurredAt").GetDateTimeOffset() != DateTimeOffset.UnixEpoch ||
            entry.GetProperty("recordedAt").GetDateTimeOffset() != DateTimeOffset.UnixEpoch.AddSeconds(1) ||
            entry.GetProperty("context").GetProperty("Decision").GetString() != "Allowed")
        { throw new InvalidOperationException("Fixture audit content drift."); }
    }

    private static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private static async Task<JsonElement> SendAsync(HttpClient client, HttpMethod method, string path, object? body, CancellationToken cancellation)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null) { request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"); }
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation);
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
}
