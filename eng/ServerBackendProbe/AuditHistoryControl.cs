using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fleetory.Platform.Audit;
using static ServerBackendProbe.FixtureAuditClient;

namespace ServerBackendProbe;

// Generated five-transaction history only. Fixed origin; no original endpoint/key input.
internal static class AuditHistoryControl
{
    private const string TxOptions = "?entriesSpec.kvEntriesSpec.action=RESOLVE&entriesSpec.zEntriesSpec.action=ONLY_DIGEST&entriesSpec.sqlEntriesSpec.action=ONLY_DIGEST";

    internal static async Task<object> ExecuteAsync(string mode, CancellationToken cancellation)
    {
        using var input = await ReadPacketAsync(cancellation);
        var packet = input.RootElement;
        var fixture = FreshPairModel.Fixture(packet);
        using var admin = new FixtureAuditClient();
        if (mode == "history-wrong-password")
        {
            try { await admin.LoginAsync(packet, cancellation); }
            catch (InvalidOperationException error) when (error.Data["fixtureHttpStatus"] is 500 && error.Data["fixtureAuthenticationDenied"] is true)
            { return new { category = mode, refused = true }; }
            throw new InvalidOperationException("Wrong history credential accepted.");
        }
        if (mode is "history-seed" or "history-seed-reversed" or "history-users" or "history-extra" or "history-rewrite")
        {
            await admin.LoginAsync(packet, cancellation);
            if (mode is "history-seed" or "history-seed-reversed")
            {
                await SeedAsync(admin, packet, fixture, mode == "history-seed-reversed", cancellation);
                if (mode == "history-seed-reversed") { return new { category = mode, derivedFixtureWrite = true }; }
            }
            else if (mode == "history-users")
            {
                await AuditFixtureControl.CreateUsersAsync(admin, packet, cancellation);
                return new { category = mode, targetOnlyUsersCreated = true };
            }
            else
            {
                await admin.SelectDatabaseAsync(cancellation);
                var key = mode == "history-extra" ? Encode("generated-unexpected-key") : EventKey(FreshPairModel.Events(fixture)[0].EventId);
                var value = mode == "history-extra" ? Encode("unexpected") :
                    (await admin.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(key), null, cancellation)).GetProperty("value").GetString()!;
                await admin.SendAsync(HttpMethod.Post, "api/db/set", new { KVs = new[] { new { key, value } } }, cancellation);
                return new { category = mode, derivedFixtureWrite = true };
            }
        }
        return await ReadbackAsync(packet, fixture, mode, cancellation);
    }

    private static string ControlKey(Guid fixture) => "fleetory/control/v1/" + fixture.ToString("N");
    private static string ControlValue(Guid fixture) => JsonSerializer.Serialize(new
    { schema = "fleetory.generated-control.v1", fixture, scope = "generated-not-original-approval" });

    private static async Task SeedAsync(FixtureAuditClient admin, JsonElement packet, Guid fixture, bool reversed, CancellationToken cancellation)
    {
        await admin.SendAsync(HttpMethod.Post, "api/db/create/v2", new { name = "fleetoryaudit" }, cancellation);
        await AuditFixtureControl.CreateUsersAsync(admin, packet, cancellation);
        await admin.SelectDatabaseAsync(cancellation);
        await admin.SendAsync(HttpMethod.Post, "api/db/set", new
        { KVs = new[] { new { key = Encode(ControlKey(fixture)), value = Encode(ControlValue(fixture)) } } }, cancellation);
        using var sink = new ImmudbAuditExportSink(new Uri("https://127.0.0.1:8090/"), "fixture_writer",
            Secret(packet, "writer"), databaseName: "fleetoryaudit");
        var events = FreshPairModel.Events(fixture);
        foreach (var item in reversed ? events.Reverse() : events) { await sink.PublishAsync(item, cancellation); }
    }

    private static async Task<object> ReadbackAsync(JsonElement packet, Guid fixture, string mode, CancellationToken cancellation)
    {
        using var reader = new FixtureAuditClient();
        await reader.LoginUserAsync("fixture_reader", Secret(packet, "reader"), cancellation);
        await reader.SelectDatabaseAsync(cancellation);
        var before = await reader.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation);
        var scan = await reader.SendAsync(HttpMethod.Post, "api/db/scan", new { prefix = "", limit = 6 }, cancellation);
        var entries = scan.GetProperty("entries").EnumerateArray().ToArray();
        var events = FreshPairModel.Events(fixture);
        var expected = new Dictionary<string, (int Tx, JsonElement Value)>(StringComparer.Ordinal)
        { [Encode(ControlKey(fixture))] = (1, JsonSerializer.Deserialize<JsonElement>(ControlValue(fixture))) };
        for (var index = 0; index < events.Length; index++)
        { expected.Add(EventKey(events[index].EventId), (index + 2, FreshPairModel.Fields(events[index]))); }
        if (entries.Length != 5 || !expected.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(entries.Select(item => item.GetProperty("key").GetString()!)))
        { throw new AuditHistoryKeySetException(); }
        var bindings = new List<object>();
        foreach (var entry in entries.OrderBy(item => item.GetProperty("key").GetString(), StringComparer.Ordinal))
        {
            var key = entry.GetProperty("key").GetString()!;
            bindings.Add(await InspectKeyAsync(reader, entry, key, expected[key], cancellation));
        }
        if (mode == "history-reader")
        { await reader.RequirePermissionDeniedAsync(new { KVs = new[] { new { key = Encode("forbidden"), value = Encode("must-not-write") } } }, cancellation); }
        var after = await reader.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation);
        RequireTip(before);
        RequireTip(after);
        if (before.GetProperty("txHash").GetString() != after.GetProperty("txHash").GetString())
        { throw new InvalidOperationException("History changed during readback."); }
        return new { category = mode, fixture, state = after, events = 4, keys = 5, transactions = 5,
            historySha256 = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(bindings))),
            completeKeysetVerified = true, allFiveNativeTransactionsVerified = true, singleRevisionPerKeyVerified = true,
            nativeSinkEventFieldsVerified = true, readerWriteRefused = mode == "history-reader", stableReadWindow = true,
            independentMerkleInclusionProofsVerified = false, originalInputsRead = false };
    }

    private static async Task<object> InspectKeyAsync(FixtureAuditClient reader, JsonElement scanned, string key,
        (int Tx, JsonElement Value) wanted, CancellationToken cancellation)
    {
        var stored = await reader.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(key), null, cancellation);
        if (stored.GetProperty("revision").GetString() != "1") { throw new AuditHistoryRevisionException(); }
        var txId = wanted.Tx.ToString(CultureInfo.InvariantCulture);
        if (stored.GetProperty("tx").GetString() != txId || scanned.GetProperty("tx").GetString() != txId)
        { throw new AuditHistoryTransactionException(); }
        var bytes = Convert.FromBase64String(stored.GetProperty("value").GetString()!);
        RequireEntry(stored, key, bytes);
        RequireEntry(scanned, key, bytes);
        using var document = JsonDocument.Parse(bytes);
        if (wanted.Tx == 1)
        { if (!JsonElement.DeepEquals(document.RootElement, wanted.Value)) { throw new InvalidOperationException("Control value drift."); } }
        else { FreshPairModel.RequireFields(document.RootElement, wanted.Value); }
        var history = await reader.SendAsync(HttpMethod.Post, "api/db/history", new { key, offset = 0, limit = 2, desc = false }, cancellation);
        var revisions = history.GetProperty("entries").EnumerateArray().ToArray();
        if (revisions.Length != 1 || revisions[0].GetProperty("revision").GetString() != "1" || revisions[0].GetProperty("tx").GetString() != txId)
        { throw new AuditHistoryRevisionException(); }
        RequireEntry(revisions[0], key, bytes);
        var headerHash = await TransactionHeaderHashAsync(reader, txId, key, bytes, cancellation);
        return new { key, tx = wanted.Tx, revision = 1, valueSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)), headerSha256 = headerHash };
    }

    private static async Task<string> TransactionHeaderHashAsync(FixtureAuditClient reader, string txId, string key, byte[] bytes, CancellationToken cancellation)
    {
        var transaction = await reader.SendAsync(HttpMethod.Get, "api/db/tx/" + txId + TxOptions, null, cancellation);
        var header = transaction.GetProperty("header");
        var kvs = transaction.GetProperty("kvEntries").EnumerateArray().ToArray();
        if (header.GetProperty("id").GetString() != txId || header.GetProperty("nentries").GetInt32() != 1 || kvs.Length != 1 ||
            (transaction.TryGetProperty("entries", out var raw) && raw.GetArrayLength() != 0) || (transaction.TryGetProperty("zEntries", out var sorted) && sorted.GetArrayLength() != 0))
        { throw new AuditHistoryTransactionException(); }
        RequireEntry(kvs[0], key, bytes);
        if (kvs[0].GetProperty("tx").GetString() != txId) { throw new AuditHistoryTransactionException(); }
        return Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(header)));
    }

    private static void RequireTip(JsonElement state)
    {
        if (state.GetProperty("db").GetString() != "fleetoryaudit" || state.GetProperty("txId").GetString() != "5" ||
            state.GetProperty("precommittedTxId").GetString() != "5" || state.GetProperty("precommittedTxHash").GetString() != state.GetProperty("txHash").GetString())
        { throw new InvalidOperationException("History tip profile drift."); }
    }

    private static void RequireEntry(JsonElement entry, string key, byte[] expected)
    {
        if (entry.GetProperty("key").GetString() != key || !Convert.FromBase64String(entry.GetProperty("value").GetString()!).AsSpan().SequenceEqual(expected) ||
            (entry.TryGetProperty("expired", out var expired) && expired.GetBoolean()) ||
            (entry.TryGetProperty("referencedBy", out var reference) && reference.ValueKind is not JsonValueKind.Null) ||
            (entry.TryGetProperty("metadata", out var metadata) && metadata.ValueKind is not JsonValueKind.Null && metadata.EnumerateObject().Any()))
        { throw new InvalidOperationException("History entry drift."); }
    }
}

internal sealed class AuditHistoryKeySetException : Exception { }
internal sealed class AuditHistoryRevisionException : Exception { }
internal sealed class AuditHistoryTransactionException : Exception { }
