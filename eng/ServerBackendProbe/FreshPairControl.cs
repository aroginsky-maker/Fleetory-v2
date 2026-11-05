using System.Data;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fleetory.Platform.Audit;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Npgsql;
using static ServerBackendProbe.FixtureAuditClient;

namespace ServerBackendProbe;

internal static class FreshPairControl
{
    internal static async Task<object> ExecuteAsync(string mode, CancellationToken cancellation)
    {
        using var input = await ReadPacketAsync(cancellation);
        var packet = input.RootElement;
        var fixture = FreshPairModel.Fixture(packet);
        if (mode == "pair-seed-sql") { return new { category = mode, sql = FreshPairModel.SeedSql(fixture), fixture,
            eventIds = FreshPairModel.Events(fixture).Select(item => item.EventId.ToString("D")).ToArray() }; }
        if (mode == "pair-closed")
        {
            foreach (var port in new[] { 19580, 19581, 19582 }) { await HostCases.ProbePortAsync(port, false, cancellation); }
            return new { category = mode, closedPorts = 3 };
        }
        if (mode == "pair-users")
        {
            using var admin = new FixtureAuditClient();
            await admin.LoginAsync(packet, cancellation);
            await AuditFixtureControl.CreateUsersAsync(admin, packet, cancellation);
            return new { category = mode, targetUsersRecreated = true };
        }
        if (mode == "pair-audit-drift")
        {
            using var admin = new FixtureAuditClient();
            await admin.LoginAsync(packet, cancellation);
            await admin.SelectDatabaseAsync(cancellation);
            await admin.SendAsync(HttpMethod.Post, "api/db/set", new { KVs = new[] { new { key = Encode("extra-fixture-key"), value = Encode("drift") } } }, cancellation);
            return new { category = mode, derivedFixtureWrite = true };
        }
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1", Port = 5432, Database = "fleetory", Username = "fleetory_server",
            Password = Secret(packet, "database"), SslMode = SslMode.VerifyFull, RootCertificate = "/tmp/ca.pem",
            GssEncryptionMode = GssEncryptionMode.Disable, Pooling = false, Timeout = 5, CommandTimeout = 5
        }.ConnectionString);
        var events = await ReadDatabaseAsync(connection, fixture, cancellation);
        if (mode == "pair-publish")
        {
            using var sink = new ImmudbAuditExportSink(new Uri("https://127.0.0.1:8090/"), "fixture_writer",
                Secret(packet, "writer"), databaseName: "fleetoryaudit");
            foreach (var item in events) { await sink.PublishAsync(item, cancellation); }
        }
        return await InspectAuditAsync(mode, packet, events, cancellation);
    }

    internal static async Task<object> InspectAsync(string mode, JsonElement packet, DbConnection connection, CancellationToken cancellation)
    {
        var events = await ReadDatabaseAsync(connection, FreshPairModel.Fixture(packet), cancellation);
        return await InspectAuditAsync(mode, packet, events, cancellation);
    }

    private static async Task<AuditExportEvent[]> ReadDatabaseAsync(DbConnection connection, Guid fixture, CancellationToken cancellation)
    {
        if (connection.State != ConnectionState.Open) { await connection.OpenAsync(cancellation); }
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellation);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandTimeout = 5;
        command.CommandText = "SET TRANSACTION READ ONLY;SET LOCAL timezone='UTC';SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s';";
        await command.ExecuteNonQueryAsync(cancellation);
        command.CommandText = "SELECT current_user='fleetory_server' AND session_user=current_user AND current_database()='fleetory' AND ssl AND version IN ('TLSv1.2','TLSv1.3') FROM pg_stat_ssl WHERE pid=pg_backend_pid();";
        if (await command.ExecuteScalarAsync(cancellation) is not true) { throw new InvalidOperationException("Fresh pair runtime identity/TLS drift."); }
        command.CommandText = "SELECT (SELECT count(*) FROM core.devices)=2 AND (SELECT count(*) FROM platform.person_projections)=2 AND (SELECT count(*) FROM platform.audit_events)=4 AND (SELECT count(*) FROM platform.audit_export_queue)=0;";
        if (await command.ExecuteScalarAsync(cancellation) is not true) { throw new InvalidOperationException("Fresh pair row count drift."); }
        command.CommandText = "SELECT event_id,actor_subject_id,actor_kind,action,target_type,target_id,correlation_id,occurred_at,recorded_at,context_json::text FROM platform.audit_events ORDER BY event_id;";
        var expected = FreshPairModel.Events(fixture).ToDictionary(item => item.EventId);
        var result = new List<AuditExportEvent>();
        await using (var rows = await command.ExecuteReaderAsync(cancellation))
        {
            while (await rows.ReadAsync(cancellation))
            {
                var id = rows.GetGuid(0);
                if (!expected.Remove(id, out var model)) { throw new InvalidOperationException("Fresh pair event identity drift."); }
                if (rows.IsDBNull(4) != rows.IsDBNull(5)) { throw new InvalidOperationException("Fresh pair field drift."); }
                var record = new AuditRecord(new ActorReference(rows.GetString(1), (ActorKind)rows.GetInt32(2)), rows.GetString(3),
                    rows.IsDBNull(4) && rows.IsDBNull(5) ? null : new AuditTarget(rows.GetString(4), rows.GetString(5)),
                    new CorrelationId(rows.GetString(6)), rows.GetFieldValue<DateTimeOffset>(7),
                    rows.IsDBNull(9) ? null : JsonSerializer.Deserialize<Dictionary<string, string>>(rows.GetString(9)));
                var item = new AuditExportEvent(id, record, rows.GetFieldValue<DateTimeOffset>(8));
                FreshPairModel.RequireFields(FreshPairModel.Fields(item), FreshPairModel.Fields(model));
                result.Add(item);
            }
        }
        if (expected.Count != 0 || result.Count != 4) { throw new InvalidOperationException("Fresh pair missing event."); }
        await transaction.CommitAsync(cancellation);
        return result.ToArray();
    }

    private static async Task<object> InspectAuditAsync(string mode, JsonElement packet, AuditExportEvent[] events, CancellationToken cancellation)
    {
        using var reader = new FixtureAuditClient();
        await reader.LoginUserAsync("fixture_reader", Secret(packet, "reader"), cancellation);
        await reader.SelectDatabaseAsync(cancellation);
        var before = await reader.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation);
        var scan = await reader.SendAsync(HttpMethod.Post, "api/db/scan", new { prefix = "", limit = 5 }, cancellation);
        var entries = scan.GetProperty("entries").EnumerateArray().ToArray();
        var expectedKeys = events.Select(item => EventKey(item.EventId)).ToHashSet(StringComparer.Ordinal);
        if (entries.Length != 4 || !expectedKeys.SetEquals(entries.Select(item => item.GetProperty("key").GetString()!)))
        { throw new InvalidOperationException("Fresh pair audit key set drift."); }
        var hashes = new List<object>();
        foreach (var item in events.OrderBy(item => item.EventId.ToString("N"), StringComparer.Ordinal))
        {
            var key = EventKey(item.EventId);
            var stored = await reader.SendAsync(HttpMethod.Get, "api/db/get/" + Uri.EscapeDataString(key), null, cancellation);
            if (stored.GetProperty("key").GetString() != key || stored.GetProperty("revision").GetString() != "1")
            { throw new InvalidOperationException("Fresh pair audit revision drift."); }
            var bytes = Convert.FromBase64String(stored.GetProperty("value").GetString()!);
            using var value = JsonDocument.Parse(bytes);
            FreshPairModel.RequireFields(value.RootElement, FreshPairModel.Fields(item));
            hashes.Add(new { eventId = item.EventId.ToString("N"), tx = stored.GetProperty("tx").GetString(),
                revision = 1, valueSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)) });
        }
        var after = await reader.SendAsync(HttpMethod.Get, "api/db/state", null, cancellation);
        foreach (var name in new[] { "db", "txId", "txHash" })
        { if (before.GetProperty(name).GetString() != after.GetProperty(name).GetString()) { throw new InvalidOperationException("Fresh pair audit changed during readback."); } }
        return new { category = mode, fixture = FreshPairModel.Fixture(packet), state = after, eventCount = 4, fieldsPerEvent = 10,
            eventsSha256 = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(hashes))),
            queueRows = 0, postgresRuntimeTlsVerified = true, nativeSinkSerializationVerified = true };
    }
}
