using Fleetory.Platform.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace ServerBackendProbe;

internal static class PumpCases
{
    internal static async Task<string> ExecuteAsync(string mode, IServiceProvider services,
        PlatformDbContext platform, CancellationToken cancellation)
    {
        await platform.Database.OpenConnectionAsync(cancellation);
        await using var proof = platform.Database.GetDbConnection().CreateCommand();
        proof.CommandText = "SELECT current_user='fleetory_server' AND session_user=current_user AND current_database()='fleetory' " +
            "AND ssl AND version IN ('TLSv1.2','TLSv1.3') FROM pg_stat_ssl WHERE pid=pg_backend_pid();";
        if (await proof.ExecuteScalarAsync(cancellation) is not true)
        { throw new InvalidOperationException("Pump fixture identity failed."); }
        var type = typeof(PlatformDbContext).Assembly.GetType("Fleetory.Platform.Audit.PostgreSqlAuditExportPump", throwOnError: true)!;
        var method = type.GetMethod("ExportNextBatchAsync", [typeof(int), typeof(CancellationToken)])
            ?? throw new InvalidOperationException("Native pump entry point unavailable.");
        try
        {
            var task = method.Invoke(services.GetRequiredService(type), [1, cancellation]) as Task<int>
                ?? throw new InvalidOperationException("Native pump result unavailable.");
            var delivered = await task;
            return (mode, delivered) switch
            {
                ("pump-auth", 0) => "pump-retained",
                ("pump-lostack", 0) => "pump-retained",
                ("pump-deliver", 1) => "pump-delivered",
                ("pump-empty", 0) => "pump-empty",
                _ => "unexpected-pump-result"
            };
        }
        catch (PostgresException exception) when (mode == "pump-update" && exception.SqlState == PostgresErrorCodes.InsufficientPrivilege)
        { return "pump-privilege"; }
    }
}
