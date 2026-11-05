using System.Text.Json;

namespace ServerBackendProbe;

internal static class PipelineFixtureControl
{
    internal static async Task ExecuteAsync(string mode, CancellationToken cancellation)
    {
        using var client = new FixtureAuditClient();
        using var packet = await FixtureAuditClient.ReadPacketAsync(cancellation);
        var expected = new List<JsonElement>();
        Guid? absent = null;
        if (mode == "worker-verify")
        {
            expected.AddRange(packet.RootElement.GetProperty("events").EnumerateArray());
            if (expected.Count is < 1 or > 6) { throw new InvalidOperationException("Fixture event count refused."); }
            if (packet.RootElement.TryGetProperty("absent", out var pending)) { absent = ReadId(pending); }
        }
        else
        {
            var item = packet.RootElement.GetProperty("expected");
            if (mode == "pipeline-verify") { expected.Add(item); }
            else { absent = ReadId(item); }
        }
        var ids = expected.Select(ReadId).ToArray();
        if (ids.Distinct().Count() != ids.Length || (absent is not null && ids.Contains(absent.Value)))
        { throw new InvalidOperationException("Fixture event identity collision."); }
        await client.LoginAsync(packet.RootElement, cancellation);
        await client.SelectDatabaseAsync(cancellation);
        var fixedKey = FixtureAuditClient.EventKey(AuditCases.EventId);
        var expectedKeys = ids.Select(FixtureAuditClient.EventKey).Append(fixedKey).ToHashSet(StringComparer.Ordinal);
        var scan = await client.SendAsync(HttpMethod.Post, "api/db/scan", new { prefix = FixtureAuditClient.Encode("fleetory/audit/v1/"), limit = 8 }, cancellation);
        var keys = scan.GetProperty("entries").EnumerateArray().Select(entry => entry.GetProperty("key").GetString()
            ?? throw new InvalidOperationException("Fixture audit key is null.")).ToArray();
        if (keys.Length != expectedKeys.Count || !expectedKeys.SetEquals(keys) ||
            (absent is not null && keys.Contains(FixtureAuditClient.EventKey(absent.Value), StringComparer.Ordinal)))
        { throw new InvalidOperationException("Fixture audit key set drift."); }
        await AuditFixtureControl.VerifyFixedEventAsync(client, cancellation);
        foreach (var item in expected) { await VerifyValueAsync(client, item, cancellation); }
    }

    private static Guid ReadId(JsonElement expected)
    {
        if (expected.EnumerateObject().Count() != 10 ||
            !Guid.TryParseExact(expected.GetProperty("eventId").GetString(), "N", out var id) || id == Guid.Empty || id == AuditCases.EventId)
        { throw new InvalidOperationException("Fixture event binding refused."); }
        return id;
    }

    private static async Task VerifyValueAsync(FixtureAuditClient client, JsonElement expected, CancellationToken cancellation)
    {
        var key = FixtureAuditClient.EventKey(ReadId(expected));
        var stored = await client.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(key), null, cancellation);
        if (stored.GetProperty("key").GetString() != key || stored.GetProperty("revision").GetString() != "1")
        { throw new InvalidOperationException("Pipeline fixture revision drift."); }
        using var value = JsonDocument.Parse(Convert.FromBase64String(stored.GetProperty("value").GetString()!));
        var actual = value.RootElement;
        if (actual.EnumerateObject().Count() != 10) { throw new InvalidOperationException("Pipeline fixture fields drifted."); }
        foreach (var field in expected.EnumerateObject())
        {
            var storedField = actual.GetProperty(field.Name);
            var matches = field.Name is "occurredAt" or "recordedAt"
                ? field.Value.GetDateTimeOffset() == storedField.GetDateTimeOffset()
                : JsonElement.DeepEquals(field.Value, storedField);
            if (!matches) { throw new InvalidOperationException("Pipeline fixture content drift."); }
        }
    }
}
