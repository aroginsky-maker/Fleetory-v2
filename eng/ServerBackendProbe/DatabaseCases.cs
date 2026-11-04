using System.Security.Authentication;
using Fleetory.Core.Persistence;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Fleetory.SharedKernel;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace ServerBackendProbe;

internal static class DatabaseCases
{
    private static readonly Dictionary<string, string> Forbidden = new(StringComparer.Ordinal)
    {
        ["db-update"] = "UPDATE platform.audit_events SET action=action WHERE FALSE;",
        ["db-delete"] = "DELETE FROM platform.audit_events WHERE FALSE;",
        ["db-queue-delete"] = "DELETE FROM platform.audit_export_queue WHERE FALSE;",
        ["db-schema"] = "CREATE SCHEMA forbidden_fixture;",
        ["db-temp"] = "CREATE TEMP TABLE forbidden_fixture(id integer);",
        ["db-owner"] = "SET ROLE fleetory_owner;"
    };

    internal static async Task<string> ExecuteAsync(string mode, IServiceProvider root, IServiceProvider scoped,
        PlatformDbContext platform, CoreDbContext core, CancellationToken cancellation)
    {
        try
        {
            await platform.Database.OpenConnectionAsync(cancellation);
            if (mode is "db-password" or "db-tls" or "db-plaintext") { return "unexpected-acceptance"; }
            await core.Database.OpenConnectionAsync(cancellation);
            await VerifyAsync(platform, "platform.person_projections", cancellation);
            await VerifyAsync(core, "core.devices", cancellation);
            if (Forbidden.TryGetValue(mode, out var sql))
            {
                await platform.Database.ExecuteSqlRawAsync(sql, cancellation);
                return "unexpected-acceptance";
            }
            if (mode == "db-ready")
            {
                var health = await root.GetRequiredService<HealthCheckService>().CheckHealthAsync(
                    registration => registration.Name == "postgresql", cancellation);
                if (health.Status != HealthStatus.Healthy || health.Entries.Count != 1)
                { throw new InvalidOperationException("Native database health failed."); }
                return "db-ready";
            }
            var writer = scoped.GetRequiredService<IAuditWriter>();
            var record = new AuditRecord(new ActorReference("fixture:operator", ActorKind.Person), "Fixture.Database.Read",
                new AuditTarget("Fixture", "generated"), new CorrelationId("fixture-server"), DateTimeOffset.UnixEpoch,
                new Dictionary<string, string> { ["Decision"] = "Allowed" });
            if (mode == "db-rollback")
            {
                await using var transaction = await platform.Database.BeginTransactionAsync(cancellation);
                await writer.WriteInTransactionAsync(record, transaction.GetDbTransaction(), cancellation);
                await transaction.RollbackAsync(cancellation);
                return "db-rollback";
            }
            await writer.WriteAsync(record, cancellation);
            return mode == "db-atomic" ? "unexpected-acceptance" : "db-write";
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.InvalidPassword && mode == "db-password")
        { return "db-authentication"; }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.InvalidAuthorizationSpecification && mode == "db-plaintext")
        { return "db-plaintext"; }
        catch (NpgsqlException exception) when (exception.InnerException is AuthenticationException && mode == "db-tls")
        { return "db-tls"; }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.InsufficientPrivilege &&
            (mode == "db-atomic" || Forbidden.ContainsKey(mode)))
        { return "db-privilege"; }
    }

    private static async Task VerifyAsync(DbContext context, string table, CancellationToken cancellation)
    {
        await using var proof = context.Database.GetDbConnection().CreateCommand();
        proof.CommandText = "SELECT current_user='fleetory_server' AND session_user=current_user AND current_database()='fleetory' " +
            "AND ssl AND version IN ('TLSv1.2','TLSv1.3') FROM pg_stat_ssl WHERE pid=pg_backend_pid();";
        if (await proof.ExecuteScalarAsync(cancellation) is not true)
        { throw new InvalidOperationException("Native transport identity failed."); }
        // Table choices are fixed by the two typed callers above.
        proof.CommandText = table == "core.devices" ? "SELECT count(*) FROM core.devices;" : "SELECT count(*) FROM platform.person_projections;";
        if (await proof.ExecuteScalarAsync(cancellation) is not long count || count != 0)
        { throw new InvalidOperationException("Native fixture table state drifted."); }
    }
}
