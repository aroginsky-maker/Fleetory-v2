using System.Text.Json;

namespace ServerBackendProbe;

internal static class PipelineFixtureControl
{
    internal static async Task ExecuteAsync(string mode, CancellationToken cancellation)
    {
        using var client = new FixtureAuditClient();
        using var packet = await FixtureAuditClient.ReadPacketAsync(cancellation);
        var expected = packet.RootElement.GetProperty("expected");
        if (expected.EnumerateObject().Count() != 10 ||
            !Guid.TryParseExact(expected.GetProperty("eventId").GetString(), "N", out var id) || id == Guid.Empty || id == AuditCases.EventId)
        { throw new InvalidOperationException("Pipeline fixture event binding refused."); }
        await client.LoginAsync(packet.RootElement, cancellation);
        await client.SelectDatabaseAsync(cancellation);
        var fixedKey = FixtureAuditClient.EventKey(AuditCases.EventId);
        var pipelineKey = FixtureAuditClient.EventKey(id);
        var present = mode == "pipeline-verify";
        var scan = await client.SendAsync(HttpMethod.Post, "api/db/scan", new { prefix = FixtureAuditClient.Encode("fleetory/audit/v1/"), limit = 3 }, cancellation);
        var keys = scan.GetProperty("entries").EnumerateArray().Select(entry => entry.GetProperty("key").GetString()).ToArray();
        if (keys.Length != (present ? 2 : 1) || !keys.Contains(fixedKey, StringComparer.Ordinal) ||
            keys.Contains(pipelineKey, StringComparer.Ordinal) != present)
        { throw new InvalidOperationException("Pipeline fixture audit key count drift."); }
        await AuditFixtureControl.VerifyFixedEventAsync(client, cancellation);
        if (!present) { return; }
        var stored = await client.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(pipelineKey), null, cancellation);
        if (stored.GetProperty("key").GetString() != pipelineKey || stored.GetProperty("revision").GetString() != "1")
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
