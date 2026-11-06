using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using static ServerBackendProbe.FixtureAuditClient;

namespace ServerBackendProbe;

// Read-only fixed-origin observer. Expected metadata never authorizes a restore or host start.
internal static class AuditObservation
{
    internal const int MaximumValueBytes = 8192;
    internal static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static string JsonHash(JsonElement value) => Hash(JsonSerializer.SerializeToUtf8Bytes(value));
    internal static int Number(JsonElement value, string name) => int.Parse(value.GetProperty(name).GetString()!, CultureInfo.InvariantCulture);
    internal static JsonElement[] Array(JsonElement value, string name) => value.TryGetProperty(name, out var found)
        ? found.EnumerateArray().ToArray() : [];

    internal static async Task<object> ExecuteAsync(CancellationToken cancellation, bool historical = false)
    {
        using var input = await ReadPacketAsync(cancellation);
        var packet = input.RootElement;
        var expected = packet.GetProperty("observation");
        HistoricalObservationBinding.Validate(expected, historical);
        var fixture = FreshPairModel.Fixture(packet);
        if (expected.GetProperty("nonce").GetString() != fixture.ToString("D")) { throw new AuditObservationBindingException(); }
        var known = ReadExpected(expected);
        using var reader = new FixtureAuditClient();
        await reader.LoginUserAsync("fixture_reader", Secret(packet, "reader"), cancellation);
        await reader.SelectDatabaseAsync(cancellation);
        var before = await reader.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation);
        RequirePoint(before, expected);
        var scanned = Array(await reader.SendAsync(HttpMethod.Post, "api/db/scan", new { prefix = "", limit = 17 }, cancellation), "entries");
        if (scanned.Length is < 4 or > 16) { throw new AuditObservationBoundException(); }
        var entries = new List<object>();
        var witnessed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in scanned)
        {
            var key = entry.GetProperty("key").GetString()!;
            if (!witnessed.Add(key)) { throw new AuditObservationBindingException(); }
            entries.Add(await InspectEntryAsync(reader, entry, key, known.GetValueOrDefault(key), cancellation));
        }
        if (!known.Keys.All(witnessed.Contains)) { throw new AuditObservationBindingException(); }
        var transactions = new List<object>();
        for (var id = 1; id <= 5; id++) { transactions.Add(await InspectTransactionAsync(reader, id, cancellation)); }
        var after = await reader.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation);
        RequirePoint(after, expected);
        var result = new Dictionary<string, object?>
        {
            ["category"] = historical ? "observation-history-read" : "observation-read",
            ["schema"] = historical ? HistoricalObservationBinding.Observed : "fleetory.audit-native-observation.v1",
            ["nonce"] = fixture, ["stateBefore"] = before, ["stateAfter"] = after,
            ["scan"] = new { prefix = "", limit = 17, entries }, ["transactions"] = transactions,
            ["executionAuthorized"] = false, ["independentInclusionProofsVerified"] = false
        };
        if (historical) { result["comparison"] = expected.GetProperty("comparison").Clone(); }
        return result;
    }

    private static Dictionary<string, JsonElement> ReadExpected(JsonElement expected)
    {
        var events = expected.GetProperty("knownEvents").EnumerateArray().ToArray();
        if (events.Length != 4) { throw new AuditObservationBindingException(); }
        var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var item in events)
        {
            var text = item.GetProperty("eventId").GetString();
            var hash = item.GetProperty("valueSha256").GetString();
            if (!Guid.TryParseExact(text, "D", out var id) || id == Guid.Empty || id.ToString("D") != text ||
                item.GetProperty("key").GetString() != EventKey(id) || item.GetProperty("revision").GetInt32() != 1 ||
                hash?.Length != 64 || hash.Any(c => !char.IsAsciiHexDigitLower(c)) || !result.TryAdd(EventKey(id), item))
            { throw new AuditObservationBindingException(); }
        }
        return result;
    }

    private static void RequirePoint(JsonElement state, JsonElement expected)
    {
        var point = expected.GetProperty("point");
        if (point.GetProperty("database").GetString() != "fleetoryaudit" || point.GetProperty("tx").GetInt32() != 5 ||
            state.GetProperty("db").GetString() != "fleetoryaudit" || Number(state, "txId") != 5 || Number(state, "precommittedTxId") != 5 ||
            state.GetProperty("txHash").GetString() != point.GetProperty("txHash").GetString() ||
            state.GetProperty("precommittedTxHash").GetString() != point.GetProperty("txHash").GetString())
        { throw new AuditObservationPointException(); }
    }

    private static async Task<object> InspectEntryAsync(FixtureAuditClient reader, JsonElement scanned, string key,
        JsonElement known, CancellationToken cancellation)
    {
        var stored = await reader.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(key), null, cancellation);
        var bytes = Convert.FromBase64String(stored.GetProperty("value").GetString()!);
        if (bytes.Length > MaximumValueBytes || Convert.FromBase64String(key).Length is < 1 or > 512) { throw new AuditObservationBoundException(); }
        RequirePlain(stored, key, bytes);
        RequirePlain(scanned, key, bytes);
        var tx = Number(stored, "tx");
        var revision = Number(stored, "revision");
        if (tx is < 1 or > 5 || revision is < 1 or > 5 || Number(scanned, "tx") != tx) { throw new AuditObservationBindingException(); }
        object? witness = null;
        if (known.ValueKind != JsonValueKind.Undefined)
        {
            if (revision != 1 || Hash(bytes) != known.GetProperty("valueSha256").GetString()) { throw new AuditObservationBindingException(); }
            using var document = JsonDocument.Parse(bytes);
            if (document.RootElement.EnumerateObject().Count() != 10 || document.RootElement.GetProperty("eventId").GetString() !=
                Guid.Parse(known.GetProperty("eventId").GetString()!).ToString("N")) { throw new AuditObservationBindingException(); }
            witness = await WitnessAsync(reader, key, bytes, tx, cancellation);
        }
        var encodedValue = new byte[bytes.Length + 1];
        bytes.CopyTo(encodedValue, 1);
        return new { keySha256 = Hash(Convert.FromBase64String(key)), storageKeySha256 = Hash([0, .. Convert.FromBase64String(key)]),
            tx, revision, valueSha256 = Hash(bytes), valueBytes = bytes.Length,
            storageValueSha256 = Hash(encodedValue), witness };
    }

    private static async Task<object> WitnessAsync(FixtureAuditClient reader, string key, byte[] bytes, int tx, CancellationToken cancellation)
    {
        var history = Array(await reader.SendAsync(HttpMethod.Post, "api/db/history", new { key, offset = 0, limit = 2, desc = false }, cancellation), "entries");
        if (history.Length != 1 || Number(history[0], "revision") != 1 || Number(history[0], "tx") != tx) { throw new AuditObservationBindingException(); }
        RequirePlain(history[0], key, bytes);
        var resolved = await reader.SendAsync(HttpMethod.Get, "api/db/tx/" + tx.ToString(CultureInfo.InvariantCulture) +
            "?entriesSpec.kvEntriesSpec.action=RESOLVE&entriesSpec.zEntriesSpec.action=ONLY_DIGEST&entriesSpec.sqlEntriesSpec.action=ONLY_DIGEST", null, cancellation);
        var found = Array(resolved, "kvEntries").Where(item => item.GetProperty("key").GetString() == key).ToArray();
        if (found.Length != 1 || Number(found[0], "tx") != tx) { throw new AuditObservationBindingException(); }
        RequirePlain(found[0], key, bytes);
        return new { historyCount = 1, historyRevision = 1, historyTx = tx, historyValueSha256 = Hash(bytes),
            resolvedTx = tx, resolvedValueSha256 = Hash(bytes), headerSha256 = JsonHash(resolved.GetProperty("header")) };
    }

    private static void RequirePlain(JsonElement entry, string key, byte[] bytes)
    {
        if (entry.GetProperty("key").GetString() != key || !Convert.FromBase64String(entry.GetProperty("value").GetString()!).AsSpan().SequenceEqual(bytes))
        { throw new AuditObservationBindingException(); }
        if ((entry.TryGetProperty("expired", out var expired) && expired.GetBoolean()) ||
            (entry.TryGetProperty("referencedBy", out var reference) && reference.ValueKind is not JsonValueKind.Null) ||
            (entry.TryGetProperty("metadata", out var metadata) && metadata.ValueKind is not JsonValueKind.Null && metadata.EnumerateObject().Any()))
        { throw new AuditObservationUnsupportedException(); }
    }

    private static async Task<object> InspectTransactionAsync(FixtureAuditClient reader, int id, CancellationToken cancellation)
    {
        // No EntriesSpec filter: retain raw summaries for every native entry kind.
        var tx = await reader.SendAsync(HttpMethod.Get, "api/db/tx/" + id.ToString(CultureInfo.InvariantCulture), null, cancellation);
        var header = tx.GetProperty("header");
        var raw = Array(tx, "entries");
        if (raw.Length is < 1 or > 16) { throw new AuditObservationBoundException(); }
        if (Number(header, "id") != id || header.GetProperty("nentries").GetInt32() != raw.Length || Array(tx, "kvEntries").Length != 0 || Array(tx, "zEntries").Length != 0)
        { throw new AuditObservationBindingException(); }
        var entries = new List<object>();
        foreach (var entry in raw)
        {
            var key = Convert.FromBase64String(entry.GetProperty("key").GetString()!);
            var digest = Convert.FromBase64String(entry.GetProperty("hValue").GetString()!);
            var length = entry.TryGetProperty("vLen", out var size) ? size.GetInt32() : 0;
            if (key.Length is < 1 or > 4096 || digest.Length != 32 || length is < 0 or > 1048576) { throw new AuditObservationBoundException(); }
            entries.Add(new { prefix = (int)key[0], keySha256 = Hash(key), valueSha256 = Convert.ToHexStringLower(digest), valueBytes = length,
                metadataSha256 = entry.TryGetProperty("metadata", out var metadata) ? JsonHash(metadata) : Hash("null"u8.ToArray()) });
        }
        return new { id, headerSha256 = JsonHash(header), count = raw.Length, entries };
    }
}

internal sealed class AuditObservationBindingException : Exception;
internal sealed class AuditObservationPointException : Exception;
internal sealed class AuditObservationBoundException : Exception;
internal sealed class AuditObservationUnsupportedException : Exception;
