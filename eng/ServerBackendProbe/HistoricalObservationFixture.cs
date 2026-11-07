using System.Globalization;
using System.Text.Json;
using Fleetory.Platform.Audit;
using Fleetory.Platform.Contracts;
using static ServerBackendProbe.FixtureAuditClient;

namespace ServerBackendProbe;

// Generated setup only. Expected values come from a separate snapshot, never from the audit Get being checked.
internal static class HistoricalObservationFixture
{
    internal static async Task<object> SeedAsync(CancellationToken cancellation)
    {
        using var input = await ReadPacketAsync(cancellation);
        var packet = input.RootElement;
        var fixture = FreshPairModel.Fixture(packet);
        var events = FreshPairModel.Events(fixture);
        var context = JsonSerializer.Deserialize<Dictionary<string, string>>("{\"Optional\":null,\"Text\":\"generated\"}")!;
        events[0] = events[0] with { Record = events[0].Record with { Context = context } };
        var snapshot = Snapshot(events);
        var comparisons = await AuditEventExpectations.FromSnapshotAsync(snapshot, AuditObservation.Hash(snapshot), fixture.ToString("D"), true, cancellation);
        using var admin = new FixtureAuditClient();
        await admin.LoginAsync(packet, cancellation);
        await admin.SendAsync(HttpMethod.Post, "api/db/create/v2", new { name = "fleetoryaudit" }, cancellation);
        await AuditFixtureControl.CreateUsersAsync(admin, packet, cancellation);
        using var sink = new ImmudbAuditExportSink(new Uri("https://127.0.0.1:8090/"), "fixture_writer", Secret(packet, "writer"), databaseName: "fleetoryaudit");
        foreach (var item in events) { await sink.PublishAsync(item, cancellation); }
        await admin.SelectDatabaseAsync(cancellation);
        await admin.SendAsync(HttpMethod.Post, "api/db/zadd", new { set = Encode("unreviewed-historical-set"),
            key = EventKey(events[0].EventId), score = 1, atTx = "1", boundRef = true }, cancellation);
        return new { category = "observation-history-seed", comparisonExpectations = comparisons,
            state = await admin.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation),
            expectationsFromAuditGet = false, generatedOnly = true };
    }

    private static byte[] Snapshot(AuditExportEvent[] events)
    {
        var rows = events.OrderBy(item => item.EventId.ToString("D"), StringComparer.Ordinal).Select(item =>
        {
            var record = item.Record;
            return new { event_id = item.EventId, actor_subject_id = record.Actor.SubjectId, actor_kind = (int)record.Actor.Kind,
                action = record.Action, target_type = record.Target?.Type, target_id = record.Target?.Id,
                correlation_id = record.CorrelationId.Value,
                occurred_at = record.OccurredAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture),
                recorded_at = item.RecordedAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture),
                context_json = record.Context is null ? null : JsonSerializer.Serialize(record.Context) };
        });
        return JsonSerializer.SerializeToUtf8Bytes(new { schema = "fleetory.audit-snapshot.v1", pendingExportCount = 0, events = rows });
    }
}
