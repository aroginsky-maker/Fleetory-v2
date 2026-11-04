using System.Text.Json;
using static ServerBackendProbe.FixtureAuditClient;

namespace ServerBackendProbe;

// Control only the fresh network-none immudb fixture at a fixed loopback origin.
internal static class AuditFixtureControl
{
    internal static async Task ExecuteAsync(string mode, CancellationToken cancellation)
    {
        using var client = new FixtureAuditClient();
        if (mode == "audit-health")
        {
            var health = await client.SendAsync(HttpMethod.Get, "api/health", null, cancellation);
            if (!health.GetProperty("status").GetBoolean()) { throw new InvalidOperationException("Fixture audit not healthy."); }
            return;
        }
        using var packet = await ReadPacketAsync(cancellation);
        await client.LoginAsync(packet.RootElement, cancellation);
        if (mode == "audit-prepare")
        {
            await client.SendAsync(HttpMethod.Post, "api/db/create/v2", new { name = "fleetoryaudit" }, cancellation);
            foreach (var item in new[] { ("fixture_writer", "writer", 2), ("fixture_reader", "reader", 1) })
            {
                await client.SendAsync(HttpMethod.Post, "api/user", new
                { user = Encode(item.Item1), password = Encode(Secret(packet.RootElement, item.Item2)), permission = item.Item3, database = "fleetoryaudit" }, cancellation);
            }
            var users = await client.SendAsync(HttpMethod.Get, "api/user/list", null, cancellation);
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
        await client.SelectDatabaseAsync(cancellation);
        var key = EventKey(AuditCases.EventId);
        var scan = await client.SendAsync(HttpMethod.Post, "api/db/scan", new { prefix = Encode("fleetory/audit/v1/"), limit = 2 }, cancellation);
        var entries = scan.GetProperty("entries").EnumerateArray().ToArray();
        if (entries.Length != 1 || entries[0].GetProperty("key").GetString() != key)
        { throw new InvalidOperationException("Fixture audit event count drift."); }
        await VerifyFixedEventAsync(client, cancellation);
    }

    internal static async Task VerifyFixedEventAsync(FixtureAuditClient client, CancellationToken cancellation)
    {
        var key = EventKey(AuditCases.EventId);
        var stored = await client.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(key), null, cancellation);
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
}
