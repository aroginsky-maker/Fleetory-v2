using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class RecoverAdminAccessTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task Recovery_grants_a_replacement_identity_and_enqueues_an_audit_event()
    {
        var replacementId = Guid.NewGuid();
        var replacementSubject = $"person:{replacementId:N}";
        const string incidentId = "INC-2026-0042";
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();

        await EnsureExistingManagerAsync(connection, transaction);
        await SetRecoveryInputsAsync(connection, transaction, replacementId, incidentId);
        var recoverySql = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "recover-admin-access.sql"));
        await using (var recover = new NpgsqlCommand(recoverySql, connection, transaction))
        {
            await recover.ExecuteNonQueryAsync();
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
            verify.Parameters.AddWithValue("subject", replacementSubject);
            Assert.Equal(1L, (long)(await verify.ExecuteScalarAsync())!);
        }

        await using (var verifyAudit = new NpgsqlCommand("""
            SELECT COUNT(*)
            FROM platform.audit_events AS event
            JOIN platform.audit_export_queue AS queue
              ON queue.audit_event_id = event.event_id
            WHERE event.action = 'platform.authorization.recovery_created'
              AND event.context_json ->> 'subject_id' = @subject
              AND event.context_json ->> 'incident_id' = @incident_id
              AND event.context_json ->> 'database_operator' = session_user
            """, connection, transaction))
        {
            verifyAudit.Parameters.AddWithValue("subject", replacementSubject);
            verifyAudit.Parameters.AddWithValue("incident_id", incidentId);
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
            version.Parameters.AddWithValue("subject", replacementSubject);
            Assert.Equal(1L, (long)(await version.ExecuteScalarAsync())!);
        }

        await using (var repeat = new NpgsqlCommand(recoverySql, connection, transaction))
        {
            var error = await Assert.ThrowsAsync<PostgresException>(
                () => repeat.ExecuteNonQueryAsync());
            Assert.Contains("already has", error.MessageText, StringComparison.Ordinal);
        }
        await transaction.RollbackAsync();
    }

    [Fact]
    public async Task Recovery_refuses_to_act_without_an_existing_manager()
    {
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

        await SetRecoveryInputsAsync(connection, transaction, Guid.NewGuid(), "INC-2026-0043");
        var recoverySql = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "recover-admin-access.sql"));
        await using var recover = new NpgsqlCommand(recoverySql, connection, transaction);
        var error = await Assert.ThrowsAsync<PostgresException>(
            () => recover.ExecuteNonQueryAsync());
        Assert.Contains("No existing global administrator", error.MessageText,
            StringComparison.Ordinal);
        await transaction.RollbackAsync();
    }

    private static async Task EnsureExistingManagerAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction)
    {
        await using var seed = new NpgsqlCommand("""
            WITH role AS (
                INSERT INTO platform.authorization_roles (role_id, name)
                VALUES (gen_random_uuid(), 'Existing administrator fixture')
                RETURNING role_id
            ), permission AS (
                INSERT INTO platform.authorization_role_permissions (role_id, permission)
                SELECT role_id, 'platform.authorization.manage' FROM role
            )
            INSERT INTO platform.authorization_assignments
                (assignment_id, actor_subject_id, actor_kind, role_id, scope_id)
            SELECT gen_random_uuid(), 'person:11111111111141118111111111111111',
                   1, role_id, NULL
            FROM role
            """, connection, transaction);
        await seed.ExecuteNonQueryAsync();
    }

    private static async Task SetRecoveryInputsAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        Guid replacementId, string incidentId)
    {
        await using var configure = new NpgsqlCommand("""
            SELECT set_config('fleetory.recovery.admin_person_id', @person_id, true),
                   set_config('fleetory.recovery.incident_id', @incident_id, true)
            """, connection, transaction);
        configure.Parameters.AddWithValue("person_id", replacementId.ToString("D"));
        configure.Parameters.AddWithValue("incident_id", incidentId);
        await configure.ExecuteNonQueryAsync();
    }
}
