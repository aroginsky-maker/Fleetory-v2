using System.Data;
using System.Globalization;
using System.Text.Json;
using Fleetory.Platform.Persistence;
using Fleetory.Security.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;

namespace ServerBackendProbe;

// Fixed read-only retained-data admission. No fixture-derived event/device/person identities.
internal static class RetainedHostControl
{
    private const int MaximumBody = 192 * 1024;

    internal static async Task<object> ExecuteAsync(WebApplication app, PlatformDbContext platform, CancellationToken cancellation)
    {
        NativeHostLifecycle.RequireUnstarted(app);
        using var input = await ReadAsync(cancellation);
        var packet = input.RootElement;
        AuditExpectationSnapshot.Object(packet, "fixture", "snapshotBase64", "snapshotSha256", "profile", "observation");
        var nonce = AuditExpectationSnapshot.Identity(packet.GetProperty("fixture").GetString());
        var encoded = packet.GetProperty("snapshotBase64").GetString()!;
        var snapshot = Convert.FromBase64String(encoded);
        AuditExpectationSnapshot.Require(snapshot.Length is > 0 and <= AuditExpectationSnapshot.MaximumBytes && Convert.ToBase64String(snapshot) == encoded);
        AuditExpectationSnapshot.Require(AuditObservation.Hash(snapshot) == packet.GetProperty("snapshotSha256").GetString());
        var historical = packet.GetProperty("profile").GetString() switch
        {
            "strict-readonly" => false,
            "historical-one-null-readonly" => true,
            _ => throw new AuditExpectationInputException()
        };
        var expected = AuditExpectationSnapshot.Parse(snapshot, historical ? AuditExpectationProfile.HistoricalReadOnly : AuditExpectationProfile.StrictWriter);
        var nulls = expected.Sum(AuditExpectationSnapshot.NullContextMembers);
        AuditExpectationSnapshot.Require(historical ? nulls == 1 : nulls == 0);
        var derived = JsonSerializer.SerializeToElement(await AuditEventExpectations.FromSnapshotAsync(snapshot,
            packet.GetProperty("snapshotSha256").GetString()!, nonce.ToString("D"), historical, cancellation));
        AuditExpectationSnapshot.Require(JsonElement.DeepEquals(derived.GetProperty("knownEvents"), packet.GetProperty("observation").GetProperty("knownEvents")));
        using var expectedDocument = JsonDocument.Parse(snapshot);
        var before = await InspectAsync(packet, expectedDocument.RootElement, platform, historical, cancellation);
        var stopMilliseconds = await NativeHostLifecycle.ExecuteAsync(app, cancellation);
        var after = await InspectAsync(packet, expectedDocument.RootElement, platform, historical, cancellation);
        foreach (var name in new[] { "scan", "transactions" })
        { AuditExpectationSnapshot.Require(JsonElement.DeepEquals(before.GetProperty(name), after.GetProperty(name))); }
        foreach (var name in new[] { "db", "txId", "txHash" })
        { AuditExpectationSnapshot.Require(JsonElement.DeepEquals(before.GetProperty("stateAfter").GetProperty(name), after.GetProperty("stateAfter").GetProperty(name))); }
        return new { category = "retained-readonly-host", nonce, applicationStarts = 1, applicationStops = 1,
            readiness = "Healthy", healthBodies = 2, publicPrivatePathRefusals = 2, listeningPorts = 3,
            initialClosedPorts = 3, finalClosedPorts = 3, workerStopped = true, stopMilliseconds,
            postgresSnapshotMatched = true, knownEvents = 4, nativeTransactions = 5,
            readOnlyAuditCredentialUsed = true, writerAdmissionVerified = false, historicalNullMembersPreserved = nulls,
            fixtureDerivedIdentityAdmissionUsed = false, nonemptyDataUnchanged = true, issuerActivated = false,
            stateBefore = before.GetProperty("stateBefore"), stateAfter = after.GetProperty("stateAfter"),
            humanLoginVerified = false, sourceOriginAuthenticated = false, fullSystemRecoveryVerified = false, phase7Complete = false };
    }

    private static async Task<JsonDocument> ReadAsync(CancellationToken cancellation)
    {
        var bytes = new byte[MaximumBody + 1];
        var length = 0;
        var source = Console.OpenStandardInput();
        while (length < bytes.Length)
        {
            var count = await source.ReadAsync(bytes.AsMemory(length), cancellation);
            if (count == 0) { break; }
            length += count;
        }
        AuditExpectationSnapshot.Require(length is > 0 and <= MaximumBody);
        return JsonDocument.Parse(bytes.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 12 });
    }

    private static async Task<JsonElement> InspectAsync(JsonElement packet, JsonElement expected, PlatformDbContext platform,
        bool historical, CancellationToken cancellation)
    {
        await CompareDatabaseAsync(expected, platform, cancellation);
        var files = new FileSecretProvider(Program.PrivateDirectory);
        var observation = JsonSerializer.SerializeToUtf8Bytes(new { fixture = packet.GetProperty("fixture"),
            reader = files.GetRequiredSecret("audit-immudb-password"), observation = packet.GetProperty("observation") });
        AuditExpectationSnapshot.Require(observation.Length <= 4096);
        using var stream = new MemoryStream(observation, writable: false);
        var result = await AuditObservation.ExecuteAsync(cancellation, historical, stream);
        return JsonSerializer.SerializeToElement(result);
    }

    private static async Task CompareDatabaseAsync(JsonElement expected, PlatformDbContext platform, CancellationToken cancellation)
    {
        var connection = platform.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open) { await connection.OpenAsync(cancellation); }
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellation);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SET TRANSACTION READ ONLY;";
        await command.ExecuteNonQueryAsync(cancellation);
        command.CommandText = "SELECT (SELECT count(*) FROM platform.audit_events)=4 AND (SELECT count(*) FROM platform.audit_export_queue)=0;";
        AuditExpectationSnapshot.Require(await command.ExecuteScalarAsync(cancellation) is true);
        command.CommandText = "SELECT event_id,actor_subject_id,actor_kind,action,target_type,target_id,correlation_id,occurred_at,recorded_at,context_json::text FROM platform.audit_events ORDER BY event_id LIMIT 5;";
        var rows = new List<object>();
        await using (var reader = await command.ExecuteReaderAsync(cancellation))
        {
            while (await reader.ReadAsync(cancellation))
            {
                rows.Add(new { event_id = reader.GetGuid(0).ToString("D"), actor_subject_id = reader.GetString(1),
                    actor_kind = reader.GetInt32(2), action = reader.GetString(3), target_type = reader.IsDBNull(4) ? null : reader.GetString(4),
                    target_id = reader.IsDBNull(5) ? null : reader.GetString(5), correlation_id = reader.GetString(6),
                    occurred_at = Format(reader.GetFieldValue<DateTimeOffset>(7)), recorded_at = Format(reader.GetFieldValue<DateTimeOffset>(8)),
                    context_json = reader.IsDBNull(9) ? null : reader.GetString(9) });
            }
        }
        AuditExpectationSnapshot.Require(rows.Count == 4);
        var actual = JsonSerializer.SerializeToElement(new { schema = "fleetory.audit-snapshot.v1", pendingExportCount = 0, events = rows });
        AuditExpectationSnapshot.Require(JsonElement.DeepEquals(expected, actual));
        await transaction.CommitAsync(cancellation);
    }

    private static string Format(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}
