using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class BootstrapFirstAdminTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task First_admin_bootstrap_is_atomic_audited_and_one_time()
    {
        var adminId = Guid.NewGuid();
        var expectedSubject = $"person:{adminId:N}";
        var bootstrapSql = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "bootstrap-first-admin.sql"));
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();

        await using (var removeExisting = new NpgsqlCommand("""
            DELETE FROM platform.authorization_assignments AS assignment
            USING platform.authorization_role_permissions AS permission
            WHERE permission.role_id = assignment.role_id
              AND permission.permission = 'platform.authorization.manage'
              AND assignment.scope_id IS NULL
            """, connection, transaction))
        {
            await removeExisting.ExecuteNonQueryAsync();
        }

        await using (var configure = new NpgsqlCommand("""
            SELECT set_config('fleetory.bootstrap.admin_person_id', @person_id, true)
            """, connection, transaction))
        {
            configure.Parameters.AddWithValue("person_id", adminId.ToString("D"));
            await configure.ExecuteNonQueryAsync();
        }

        await using (var bootstrap = new NpgsqlCommand(bootstrapSql, connection, transaction))
        {
            await bootstrap.ExecuteNonQueryAsync();
        }

        await using (var verify = new NpgsqlCommand("""
            SELECT COUNT(*)
            FROM platform.authorization_assignments AS assignment
            JOIN platform.authorization_role_permissions AS permission
              ON permission.role_id = assignment.role_id
            WHERE assignment.actor_subject_id = @subject
              AND assignment.actor_kind = 1
              AND assignment.scope_id IS NULL
              AND permission.permission = 'platform.authorization.manage'
            """, connection, transaction))
        {
            verify.Parameters.AddWithValue("subject", expectedSubject);
            Assert.Equal(1L, (long)(await verify.ExecuteScalarAsync())!);
        }

        await using (var verifyAudit = new NpgsqlCommand("""
            SELECT COUNT(*)
            FROM platform.audit_events AS event
            JOIN platform.audit_export_queue AS queue
              ON queue.audit_event_id = event.event_id
            WHERE event.action = 'platform.authorization.bootstrap_created'
              AND event.context_json ->> 'subject_id' = @subject
            """, connection, transaction))
        {
            verifyAudit.Parameters.AddWithValue("subject", expectedSubject);
            Assert.Equal(1L, (long)(await verifyAudit.ExecuteScalarAsync())!);
        }

        await using (var version = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.authorization_assignments AS assignment
            JOIN platform.authorization_role_versions AS version
              ON version.role_id = assignment.role_id
            WHERE assignment.actor_subject_id = @subject
              AND version.permissions = ARRAY['platform.authorization.manage']
              AND version.predecessor_role_id IS NULL
            """, connection, transaction))
        {
            version.Parameters.AddWithValue("subject", expectedSubject);
            Assert.Equal(1L, (long)(await version.ExecuteScalarAsync())!);
        }

        await using (var repeat = new NpgsqlCommand(bootstrapSql, connection, transaction))
        {
            var error = await Assert.ThrowsAsync<PostgresException>(
                () => repeat.ExecuteNonQueryAsync());
            Assert.Contains("already exists", error.MessageText, StringComparison.Ordinal);
        }

        await transaction.RollbackAsync();
    }
}
