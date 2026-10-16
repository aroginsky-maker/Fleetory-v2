using Fleetory.Platform.Contracts;
using Fleetory.Platform.Audit;
using Fleetory.Platform.Persistence;
using Fleetory.SharedKernel;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class PostgreSqlAuditTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task Audit_event_and_export_queue_entry_are_persisted_together()
    {
        var correlationId = CorrelationId.New();
        var record = new AuditRecord(
            new ActorReference("person:operator-1", ActorKind.Person),
            "Core.Device.Read",
            new AuditTarget("Device", "device-42"),
            correlationId,
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Decision"] = "Allowed"
            });

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var writer = scope.ServiceProvider.GetRequiredService<IAuditWriter>();
            await writer.WriteAsync(record);
        }

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT event.actor_subject_id, event.action, event.target_type, event.target_id,
                   event.context_json::text, queue.audit_event_id
            FROM platform.audit_events AS event
            JOIN platform.audit_export_queue AS queue ON queue.audit_event_id = event.event_id
            WHERE event.correlation_id = @correlation_id
            """, connection);
        command.Parameters.AddWithValue("correlation_id", correlationId.Value);
        await using var reader = await command.ExecuteReaderAsync();

        Assert.True(await reader.ReadAsync());
        Assert.Equal("person:operator-1", reader.GetString(0));
        Assert.Equal("Core.Device.Read", reader.GetString(1));
        Assert.Equal("Device", reader.GetString(2));
        Assert.Equal("device-42", reader.GetString(3));
        Assert.Contains("Allowed", reader.GetString(4), StringComparison.Ordinal);
        Assert.NotEqual(Guid.Empty, reader.GetGuid(5));
        Assert.False(await reader.ReadAsync());
    }

    [Fact]
    public async Task Optional_target_and_context_are_written_as_null_without_losing_outbox_entry()
    {
        var correlationId = CorrelationId.New();
        var record = new AuditRecord(
            new ActorReference("system:audit-test", ActorKind.System),
            "Platform.Session.Expired",
            null,
            correlationId,
            DateTimeOffset.UtcNow);

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IAuditWriter>().WriteAsync(record);
        }

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT event.target_type IS NULL AND event.target_id IS NULL AND event.context_json IS NULL
            FROM platform.audit_events AS event
            JOIN platform.audit_export_queue AS queue ON queue.audit_event_id = event.event_id
            WHERE event.correlation_id = @correlation_id
            """, connection);
        command.Parameters.AddWithValue("correlation_id", correlationId.Value);

        Assert.True((bool?)await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task Sensitive_context_key_is_rejected_before_database_write()
    {
        var correlationId = CorrelationId.New();
        var record = new AuditRecord(
            new ActorReference("person:operator-2", ActorKind.Person),
            "Platform.Login.Failed",
            null,
            correlationId,
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Password"] = "must-never-be-stored"
            });

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var writer = scope.ServiceProvider.GetRequiredService<IAuditWriter>();
            await Assert.ThrowsAsync<ArgumentException>(async () => await writer.WriteAsync(record));
        }

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT COUNT(*) FROM platform.audit_events WHERE correlation_id = @correlation_id", connection);
        command.Parameters.AddWithValue("correlation_id", correlationId.Value);
        Assert.Equal(0L, Convert.ToInt64(await command.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task Audit_write_fails_closed_when_postgresql_is_unavailable()
    {
        var writer = new PostgreSqlAuditWriter(
            new PostgreSqlConnectionSettings(
                "Host=127.0.0.1;Port=1;Database=fleetory_audit_unavailable;Username=fleetory;Timeout=1;Pooling=false"),
            new SystemClock());
        var record = new AuditRecord(
            new ActorReference("system:audit-test", ActorKind.System),
            "Platform.Security.Denied",
            null,
            CorrelationId.New(),
            DateTimeOffset.UtcNow);

        await Assert.ThrowsAsync<NpgsqlException>(async () => await writer.WriteAsync(record));
    }
}
