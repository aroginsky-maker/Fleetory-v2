using Fleetory.Platform.Persistence;
using Fleetory.SharedKernel;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace Fleetory.Platform.Audit;

internal sealed class AuditExportBacklogHealthCheck(
    PostgreSqlConnectionSettings settings,
    IClock clock) : IHealthCheck
{
    private static readonly TimeSpan MaximumLag = TimeSpan.FromMinutes(5);

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT MIN(enqueued_at) FROM platform.audit_export_queue", connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        if (reader.IsDBNull(0))
        {
            return HealthCheckResult.Healthy("Audit export queue is empty.");
        }

        var oldest = reader.GetFieldValue<DateTimeOffset>(0);
        return clock.UtcNow.ToUniversalTime() - oldest > MaximumLag
            ? HealthCheckResult.Degraded("Audit export backlog exceeds five minutes.")
            : HealthCheckResult.Healthy("Audit export backlog is within five minutes.");
    }
}
