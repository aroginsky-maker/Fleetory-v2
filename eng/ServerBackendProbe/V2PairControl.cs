using System.Data.Common;
using System.Text.Json;
using static ServerBackendProbe.FixtureAuditClient;

namespace ServerBackendProbe;

// Only the generated 24-row/five-transaction profile; full v2 inventories are
// independently checked by the owning coordinator before it invokes the host.
internal static class V2PairControl
{
    internal static async Task<object> ExecuteAsync(string mode, CancellationToken cancellation)
    {
        using var input = await ReadPacketAsync(cancellation);
        var packet = input.RootElement;
        var fixture = FreshPairModel.Fixture(packet);
        if (mode == "v2pair-seed-sql")
        { return new { category = mode, sql = FreshPairModel.ReplaceAuditSql(fixture), fixture,
            eventIds = FreshPairModel.Events(fixture).Select(item => item.EventId.ToString("D")).ToArray() }; }
        await using var connection = FreshPairControl.OpenRuntimeConnection(packet);
        if (mode == "v2pair-publish")
        {
            var events = await FreshPairControl.ReadDatabaseAsync(connection, fixture, cancellation, v2: true);
            var byId = events.ToDictionary(item => item.EventId);
            var ordered = FreshPairModel.Events(fixture).Select(item => byId[item.EventId]).ToArray();
            using var admin = new FixtureAuditClient();
            await admin.LoginAsync(packet, cancellation);
            await AuditHistoryControl.SeedAsync(admin, packet, fixture, false, cancellation, ordered);
        }
        return await InspectAsync(mode, packet, connection, cancellation);
    }

    internal static async Task<object> InspectAsync(string mode, JsonElement packet, DbConnection connection, CancellationToken cancellation)
    {
        try
        {
            var fixture = FreshPairModel.Fixture(packet);
            await FreshPairControl.ReadDatabaseAsync(connection, fixture, cancellation, v2: true);
            return await AuditHistoryControl.ReadbackAsync(packet, fixture, mode, cancellation);
        }
        catch (Exception error) when (error is AuditHistoryKeySetException or AuditHistoryRevisionException or AuditHistoryTransactionException ||
            error is InvalidOperationException && error.Message is "Fresh pair field count drift." or "Fresh pair field drift." or
                "Fresh pair event identity drift." or "Fresh pair missing event." or "Fresh pair row count drift.")
        { throw new FreshPairPreflightException(); }
    }
}
