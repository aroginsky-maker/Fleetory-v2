using System.Text.Json;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Fleetory.SharedKernel;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;

namespace Fleetory.Platform.Audit;

/// <summary>Claims due audit entries across nodes and delivers them at least once.</summary>
internal sealed class PostgreSqlAuditExportPump(
    PostgreSqlConnectionSettings settings,
    IAuditExportSink sink,
    IClock clock,
    ILogger<PostgreSqlAuditExportPump> logger)
{
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan DeliveryTimeout = TimeSpan.FromSeconds(30);

    private const string ClaimSql = """
        WITH candidate AS (
            SELECT queue.audit_event_id
            FROM platform.audit_export_queue AS queue
            WHERE queue.next_attempt_at <= @now
              AND (queue.leased_until IS NULL OR queue.leased_until <= @now)
            ORDER BY queue.enqueued_at, queue.audit_event_id
            FOR UPDATE SKIP LOCKED
            LIMIT @batch_size
        ), claimed AS (
            UPDATE platform.audit_export_queue AS queue
            SET lease_id = @lease_id,
                leased_until = @leased_until,
                attempt_count = queue.attempt_count + 1
            FROM candidate
            WHERE queue.audit_event_id = candidate.audit_event_id
            RETURNING queue.audit_event_id, queue.attempt_count
        )
        SELECT claimed.audit_event_id, claimed.attempt_count,
               event.actor_subject_id, event.actor_kind, event.action,
               event.target_type, event.target_id, event.correlation_id,
               event.occurred_at, event.recorded_at, event.context_json::text
        FROM claimed
        JOIN platform.audit_events AS event ON event.event_id = claimed.audit_event_id
        ORDER BY event.recorded_at, claimed.audit_event_id
        """;

    public async Task<int> ExportNextBatchAsync(
        int batchSize = 3,
        CancellationToken cancellationToken = default)
    {
        if (batchSize is < 1 or > 3)
        {
            throw new ArgumentOutOfRangeException(nameof(batchSize));
        }

        var leaseId = Guid.NewGuid();
        var claimed = await ClaimAsync(leaseId, batchSize, cancellationToken);
        var delivered = 0;

        foreach (var entry in claimed)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var deliveryCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                deliveryCancellation.CancelAfter(DeliveryTimeout);
                await sink.PublishAsync(entry.Event, deliveryCancellation.Token);
                await CompleteAsync(entry.Event.EventId, leaseId, cancellationToken);
                delivered++;
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                logger.LogWarning(
                    "Audit export delivery needs retry for event {EventId}, attempt {AttemptCount}.",
                    entry.Event.EventId,
                    entry.AttemptCount);
                await RescheduleAsync(entry.Event.EventId, leaseId, entry.AttemptCount, cancellationToken);
            }
        }

        return delivered;
    }

    private async Task<IReadOnlyList<ClaimedAuditEvent>> ClaimAsync(
        Guid leaseId,
        int batchSize,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow.ToUniversalTime();
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(ClaimSql, connection);
        command.Parameters.AddWithValue("now", NpgsqlDbType.TimestampTz, now);
        command.Parameters.AddWithValue("lease_id", NpgsqlDbType.Uuid, leaseId);
        command.Parameters.AddWithValue("leased_until", NpgsqlDbType.TimestampTz, now + LeaseDuration);
        command.Parameters.AddWithValue("batch_size", NpgsqlDbType.Integer, batchSize);

        var events = new List<ClaimedAuditEvent>(batchSize);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var targetType = reader.IsDBNull(5) ? null : reader.GetString(5);
            var targetId = reader.IsDBNull(6) ? null : reader.GetString(6);
            if ((targetType is null) != (targetId is null))
            {
                throw new InvalidOperationException("Stored audit target is incomplete.");
            }

            var context = reader.IsDBNull(10)
                ? null
                : JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(10))
                    ?? throw new InvalidOperationException("Stored audit context is invalid.");
            var record = new AuditRecord(
                new ActorReference(reader.GetString(2), (ActorKind)reader.GetInt32(3)),
                reader.GetString(4),
                targetType is null ? null : new AuditTarget(targetType, targetId!),
                new CorrelationId(reader.GetString(7)),
                reader.GetFieldValue<DateTimeOffset>(8),
                context);
            var auditEvent = new AuditExportEvent(
                reader.GetGuid(0), record, reader.GetFieldValue<DateTimeOffset>(9));
            events.Add(new ClaimedAuditEvent(auditEvent, reader.GetInt32(1)));
        }

        return events;
    }

    private async Task CompleteAsync(Guid eventId, Guid leaseId, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            DELETE FROM platform.audit_export_queue
            WHERE audit_event_id = @event_id AND lease_id = @lease_id
            """, connection);
        command.Parameters.AddWithValue("event_id", NpgsqlDbType.Uuid, eventId);
        command.Parameters.AddWithValue("lease_id", NpgsqlDbType.Uuid, leaseId);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("Audit export lease was lost before acknowledgement.");
        }
    }

    private async Task RescheduleAsync(
        Guid eventId,
        Guid leaseId,
        int attemptCount,
        CancellationToken cancellationToken)
    {
        var delaySeconds = Math.Min(3600, 1 << Math.Min(attemptCount, 12));
        var nextAttempt = clock.UtcNow.ToUniversalTime().AddSeconds(delaySeconds);
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            UPDATE platform.audit_export_queue
            SET lease_id = NULL, leased_until = NULL, next_attempt_at = @next_attempt_at
            WHERE audit_event_id = @event_id AND lease_id = @lease_id
            """, connection);
        command.Parameters.AddWithValue("next_attempt_at", NpgsqlDbType.TimestampTz, nextAttempt);
        command.Parameters.AddWithValue("event_id", NpgsqlDbType.Uuid, eventId);
        command.Parameters.AddWithValue("lease_id", NpgsqlDbType.Uuid, leaseId);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("Audit export lease was lost before retry scheduling.");
        }
    }

    private sealed record ClaimedAuditEvent(AuditExportEvent Event, int AttemptCount);
}
