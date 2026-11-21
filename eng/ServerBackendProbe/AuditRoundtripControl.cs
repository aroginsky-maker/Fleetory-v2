using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using static ServerBackendProbe.FixtureAuditClient;

namespace ServerBackendProbe;

// Fresh fixtures only, fixed loopback origin. No path, endpoint or original credential input.
internal static class AuditRoundtripControl
{
    private static readonly string[] Keys = Enumerable.Range(1, 4)
        .Select(number => "fleetory/audit/v1/" + number.ToString("x32")).ToArray();

    internal static async Task<object> ExecuteAsync(string mode, CancellationToken cancellation)
    {
        using var input = await ReadPacketAsync(cancellation);
        var packet = input.RootElement;
        using var client = new FixtureAuditClient();
        if (mode == "immu-wrong-password")
        {
            try { await client.LoginAsync(packet, cancellation); }
            catch (InvalidOperationException error) when (error.Data["fixtureHttpStatus"] is 500 && error.Data["fixtureAuthenticationDenied"] is true)
            { return new { category = mode, refused = true }; }
            throw new InvalidOperationException("Invalid password accepted.");
        }
        await client.LoginAsync(packet, cancellation);
        if (mode == "immu-seed")
        {
            await client.SendAsync(HttpMethod.Post, "api/db/create/v2", new { name = "fleetoryaudit" }, cancellation);
            await client.SelectDatabaseAsync(cancellation);
            for (var index = 0; index < Keys.Length; index++)
            {
                var body = new { KVs = new[] { new { key = Encode(Keys[index]), value = Encode(Value(index)) } } };
                await client.SendAsync(HttpMethod.Post, "api/db/set", body, cancellation);
            }
        }
        if (mode == "immu-reader-create")
        {
            await client.SendAsync(HttpMethod.Post, "api/user", new
            { user = Encode("fixture_reader"), password = Encode(Secret(packet, "reader")), permission = 1, database = "fleetoryaudit" }, cancellation);
            return new { category = mode, targetOnlyReaderCreated = true };
        }
        if (mode == "immu-reader") { await client.LoginUserAsync("fixture_reader", Secret(packet, "reader"), cancellation); }
        await client.SelectDatabaseAsync(cancellation);
        return await ReadbackAsync(client, mode, cancellation);
    }

    private static async Task<object> ReadbackAsync(FixtureAuditClient client, string mode, CancellationToken cancellation)
    {
        var before = await client.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation);
        var scan = await client.SendAsync(HttpMethod.Post, "api/db/scan", new { prefix = "", limit = 5 }, cancellation);
        var entries = scan.GetProperty("entries").EnumerateArray().ToArray();
        if (entries.Length != Keys.Length) { throw new InvalidOperationException("Audit roundtrip key count drift."); }
        var hashes = new List<object>();
        for (var index = 0; index < Keys.Length; index++)
        {
            var entry = entries[index];
            var stored = await client.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(Encode(Keys[index])), null, cancellation);
            var expected = Encoding.UTF8.GetBytes(Value(index));
            if (entry.GetProperty("key").GetString() != Encode(Keys[index]) ||
                stored.GetProperty("key").GetString() != Encode(Keys[index]) ||
                stored.GetProperty("revision").GetString() != "1" ||
                !Convert.FromBase64String(stored.GetProperty("value").GetString()!).AsSpan().SequenceEqual(expected) ||
                !Convert.FromBase64String(entry.GetProperty("value").GetString()!).AsSpan().SequenceEqual(expected))
            { throw new InvalidOperationException("Audit roundtrip entry drift."); }
            hashes.Add(new { key = Keys[index], revision = 1, tx = stored.GetProperty("tx").GetString(),
                sha256 = Convert.ToHexStringLower(SHA256.HashData(expected)) });
        }
        if (mode == "immu-reader")
        {
            await client.RequirePermissionDeniedAsync(new { KVs = new[] { new { key = Encode("forbidden"), value = Encode("must-not-write") } } }, cancellation);
        }
        var after = await client.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation);
        foreach (var field in new[] { "db", "txId", "txHash" })
        { if (before.GetProperty(field).GetString() != after.GetProperty(field).GetString()) { throw new InvalidOperationException("Audit tip changed during readback."); } }
        return new { category = mode, state = after, entries = hashes, keyCount = Keys.Length,
            readerWriteRefused = mode == "immu-reader", stableReadWindow = true, originalMaterialUsed = false };
    }

    private static string Value(int index) => JsonSerializer.Serialize(new
    {
        eventId = (index + 1).ToString("x32"), actorSubjectId = "fixture:roundtrip", actorKind = 1,
        Action = "Fixture.Restore." + index, targetType = "Fixture", targetId = "generated",
        correlationId = "fresh-roundtrip-" + index, occurredAt = "2026-01-01T00:00:00Z",
        recordedAt = "2026-01-01T00:00:01Z", context = new { Scope = "synthetic-not-approval" }
    });
}
