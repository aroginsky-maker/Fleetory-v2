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
        while (await probe.ExecuteScalarAsync(cancellationToken) is not true)
        {
            await Task.Delay(20, cancellationToken);
        }
    }
}
