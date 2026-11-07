using System.Text.Json;
using Fleetory.Platform.Audit;
using static ServerBackendProbe.FixtureAuditClient;

namespace ServerBackendProbe;

// Generated setup and intentional denial probes, separate from the read-only observer.
internal static class AuditObservationFixture
{
    internal static async Task<object> ExecuteAsync(string mode, CancellationToken cancellation)
    {
        using var input = await ReadPacketAsync(cancellation);
        var packet = input.RootElement;
        var fixture = FreshPairModel.Fixture(packet);
        using var admin = new FixtureAuditClient();
        if (mode == "observation-reader-denial")
        {
            await admin.LoginUserAsync("fixture_reader", Secret(packet, "reader"), cancellation);
            await admin.SelectDatabaseAsync(cancellation);
            await admin.RequirePermissionDeniedAsync(new { KVs = new[] { new { key = Encode("forbidden"), value = Encode("must-not-write") } } }, cancellation);
            return new { category = mode, readerWriteRefused = true };
        }
        await admin.LoginAsync(packet, cancellation);
        if (mode == "observation-seed")
        {
            await admin.SendAsync(HttpMethod.Post, "api/db/create/v2", new { name = "fleetoryaudit" }, cancellation);
            await AuditFixtureControl.CreateUsersAsync(admin, packet, cancellation);
            using var sink = new ImmudbAuditExportSink(new Uri("https://127.0.0.1:8090/"), "fixture_writer", Secret(packet, "writer"), databaseName: "fleetoryaudit");
            foreach (var item in FreshPairModel.Events(fixture)) { await sink.PublishAsync(item, cancellation); }
        }
        await admin.SelectDatabaseAsync(cancellation);
        if (mode != "observation-seed") { await MutateAsync(admin, mode, fixture, cancellation); }
        var known = new List<object>();
        foreach (var item in FreshPairModel.Events(fixture))
        {
            var key = EventKey(item.EventId);
            var entry = await admin.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(key), null, cancellation);
            var bytes = Convert.FromBase64String(entry.GetProperty("value").GetString()!);
            using var value = JsonDocument.Parse(bytes);
            FreshPairModel.RequireFields(value.RootElement, FreshPairModel.Fields(item));
            known.Add(new { eventId = item.EventId, key, revision = 1, valueSha256 = AuditObservation.Hash(bytes) });
        }
        return new { category = mode, knownEvents = known, state = await admin.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation) };
    }

    private static async Task MutateAsync(FixtureAuditClient admin, string mode, Guid fixture, CancellationToken cancellation)
    {
        var key = EventKey(FreshPairModel.Events(fixture)[0].EventId);
        if (mode == "observation-zset")
        { await admin.SendAsync(HttpMethod.Post, "api/db/zadd", new { set = Encode("unreviewed-generated-set"), key, score = 1, atTx = "1", boundRef = true }, cancellation); }
        else if (mode == "observation-rewrite")
        {
            var stored = await admin.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(key), null, cancellation);
            await admin.SendAsync(HttpMethod.Post, "api/db/set", new { KVs = new[] { new { key, value = stored.GetProperty("value").GetString() } } }, cancellation);
        }
        else
        {
            var count = mode == "observation-many" ? 17 : 1;
            var values = Enumerable.Range(0, count).Select(index => new { key = Encode("unreviewed-extra-" + index), value = Encode("generated") }).ToArray();
            await admin.SendAsync(HttpMethod.Post, "api/db/set", new { KVs = values }, cancellation);
        }
    }
}
