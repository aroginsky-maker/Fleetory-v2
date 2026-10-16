using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace Fleetory.Platform.Persistence;

internal sealed class PostgreSqlReadinessHealthCheck(
    PostgreSqlConnectionSettings settings) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        await using var command = new NpgsqlCommand("SELECT 1", connection);
        await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);

        return HealthCheckResult.Healthy("PostgreSQL is reachable.");
    }
}
