using System.Text;
using System.Text.Json;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Fleetory.SharedKernel;
using Npgsql;
using NpgsqlTypes;

namespace Fleetory.Platform.Audit;

/// <summary>Appends an audit event and its export outbox entry in one PostgreSQL transaction.</summary>
internal sealed class PostgreSqlAuditWriter(
    PostgreSqlConnectionSettings settings,
    IClock clock) : IAuditWriter
{
    private static readonly string[] ForbiddenContextKeyParts =
    [
        "password", "secret", "token", "credential", "private", "session", "cookie", "authorization", "apikey"
    ];

    public async ValueTask WriteAsync(
        AuditRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        Validate(record);

        var contextJson = record.Context is null ? null : JsonSerializer.Serialize(record.Context);
        if (contextJson is not null && Encoding.UTF8.GetByteCount(contextJson) > 16 * 1024)
        {
            throw new ArgumentException("Audit context exceeds the 16 KiB limit.", nameof(record));
        }

        var eventId = Guid.CreateVersion7();
        var recordedAt = clock.UtcNow.ToUniversalTime();

        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using (var insertEvent = connection.CreateCommand())
        {
            insertEvent.Transaction = transaction;
            insertEvent.CommandText = """
                INSERT INTO platform.audit_events
                    (event_id, actor_subject_id, actor_kind, action, target_type, target_id,
                     correlation_id, occurred_at, recorded_at, context_json)
                VALUES
                    (@event_id, @actor_subject_id, @actor_kind, @action, @target_type, @target_id,
                     @correlation_id, @occurred_at, @recorded_at, @context_json)
                """;
            insertEvent.Parameters.AddWithValue("event_id", NpgsqlDbType.Uuid, eventId);
            insertEvent.Parameters.AddWithValue("actor_subject_id", NpgsqlDbType.Varchar, record.Actor.SubjectId);
            insertEvent.Parameters.AddWithValue("actor_kind", NpgsqlDbType.Integer, (int)record.Actor.Kind);
            insertEvent.Parameters.AddWithValue("action", NpgsqlDbType.Varchar, record.Action);
            insertEvent.Parameters.AddWithValue("target_type", NpgsqlDbType.Varchar,
                (object?)record.Target?.Type ?? DBNull.Value);
            insertEvent.Parameters.AddWithValue("target_id", NpgsqlDbType.Varchar,
                (object?)record.Target?.Id ?? DBNull.Value);
            insertEvent.Parameters.AddWithValue("correlation_id", NpgsqlDbType.Varchar, record.CorrelationId.Value);
            insertEvent.Parameters.AddWithValue("occurred_at", NpgsqlDbType.TimestampTz,
                record.OccurredAt.ToUniversalTime());
            insertEvent.Parameters.AddWithValue("recorded_at", NpgsqlDbType.TimestampTz, recordedAt);
            insertEvent.Parameters.AddWithValue("context_json", NpgsqlDbType.Jsonb,
                (object?)contextJson ?? DBNull.Value);
            await insertEvent.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var enqueueExport = connection.CreateCommand())
        {
            enqueueExport.Transaction = transaction;
            enqueueExport.CommandText = """
                INSERT INTO platform.audit_export_queue (audit_event_id, enqueued_at)
                VALUES (@audit_event_id, @enqueued_at)
                """;
            enqueueExport.Parameters.AddWithValue("audit_event_id", NpgsqlDbType.Uuid, eventId);
            enqueueExport.Parameters.AddWithValue("enqueued_at", NpgsqlDbType.TimestampTz, recordedAt);
            await enqueueExport.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static void Validate(AuditRecord record)
    {
        if (record.Actor is null || !Enum.IsDefined(record.Actor.Kind))
        {
            throw new ArgumentException("Audit actor is invalid.", nameof(record));
        }

        ValidateText(record.Actor.SubjectId, 128, nameof(record.Actor.SubjectId));
        ValidateText(record.Action, 128, nameof(record.Action));
        ValidateText(record.CorrelationId.Value, 128, nameof(record.CorrelationId));

        if (record.Target is not null)
        {
            ValidateText(record.Target.Type, 64, nameof(record.Target.Type));
            ValidateText(record.Target.Id, 128, nameof(record.Target.Id));
        }

        if (record.Context is null)
        {
            return;
        }

        if (record.Context.Count > 16)
        {
            throw new ArgumentException("Audit context has too many entries.", nameof(record));
        }

        foreach (var (key, value) in record.Context)
        {
            ValidateText(key, 64, nameof(record.Context));
            if (ForbiddenContextKeyParts.Any(part => key.Contains(part, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException("Audit context contains a sensitive key.", nameof(record));
            }

            if (value is null || value.Length > 1024)
            {
                throw new ArgumentException("Audit context value is invalid.", nameof(record));
            }
        }
    }

    private static void ValidateText(string? value, int maximumLength, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
        {
            throw new ArgumentException($"Audit field '{name}' is invalid.", name);
        }
    }
}
