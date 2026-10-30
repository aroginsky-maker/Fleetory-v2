using Npgsql;

namespace Fleetory.Persistence.Tests;

internal static class PostgreSqlLockWait
{
    public static async Task ForReaderAsync(NpgsqlConnection blocker, NpgsqlTransaction transaction,
        string relation, CancellationToken cancellationToken)
    {
        await using var probe = new NpgsqlCommand("""
            SELECT EXISTS (SELECT 1 FROM pg_locks
                           WHERE relation = @relation::regclass
                             AND mode = 'AccessShareLock' AND NOT granted AND pid <> pg_backend_pid())
            """, blocker, transaction);
        probe.Parameters.AddWithValue("relation", relation);
        await UntilBlockedAsync(probe, cancellationToken);
    }

    public static async Task ForBackendAsync(NpgsqlConnection blocker, NpgsqlTransaction transaction,
        int backend, string lockType, CancellationToken cancellationToken)
    {
        await using var probe = new NpgsqlCommand("""
            SELECT EXISTS (SELECT 1 FROM pg_locks
                           WHERE pid = @backend AND locktype = @lock_type AND NOT granted)
            """, blocker, transaction);
        probe.Parameters.AddWithValue("backend", backend);
        probe.Parameters.AddWithValue("lock_type", lockType);
        await UntilBlockedAsync(probe, cancellationToken);
    }

    private static async Task UntilBlockedAsync(NpgsqlCommand probe, CancellationToken cancellationToken)
    {
        while (await probe.ExecuteScalarAsync(cancellationToken) is not true)
        {
            await Task.Delay(20, cancellationToken);
        }
    }
}
