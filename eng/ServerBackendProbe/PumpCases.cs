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
        await DatabaseCases.VerifyAsync(platform, "platform.person_projections", cancellation);
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
