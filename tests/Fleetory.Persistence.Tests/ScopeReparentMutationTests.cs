using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class ScopeReparentMutationTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task Mutation_commits_parent_version_and_audit_atomically()
    {
        var oldParent = Guid.NewGuid();
        var newParent = Guid.NewGuid();
        var moved = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand("""
            INSERT INTO platform.authorization_scopes (scope_id, parent_scope_id, name)
            VALUES (@old_parent, NULL, 'old parent'), (@new_parent, NULL, 'new parent'),
                   (@moved, @old_parent, 'moved scope');
            INSERT INTO platform.authorization_scope_versions
                (scope_id, revision, parent_scope_id, name, recorded_at)
            VALUES (@moved, 1, @old_parent, 'moved scope', now());
            """, connection))
        {
            setup.Parameters.AddWithValue("old_parent", oldParent);
            setup.Parameters.AddWithValue("new_parent", newParent);
            setup.Parameters.AddWithValue("moved", moved);
            await setup.ExecuteNonQueryAsync();
        }

        await ExecuteMutationAsync(connection, moved, newParent, 1,
            "INC-SCOPE-REParent-0001", "operator-a", "approver-b");

        await using (var verify = new NpgsqlCommand("""
            SELECT scope.parent_scope_id, version.revision, version.parent_scope_id,
                   event.action, event.context_json ->> 'approver_reference'
            FROM platform.authorization_scopes AS scope
            JOIN platform.authorization_scope_versions AS version
              ON version.scope_id = scope.scope_id AND version.revision = 2
            JOIN platform.audit_events AS event ON event.target_id = scope.scope_id::text
            JOIN platform.audit_export_queue AS queue ON queue.audit_event_id = event.event_id
            WHERE scope.scope_id = @moved AND event.action = 'platform.authorization.scope_reparented'
            """, connection))
        {
            verify.Parameters.AddWithValue("moved", moved);
            await using var reader = await verify.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(newParent, reader.GetGuid(0));
            Assert.Equal(2, reader.GetInt32(1));
            Assert.Equal(newParent, reader.GetGuid(2));
            Assert.Equal("platform.authorization.scope_reparented", reader.GetString(3));
            Assert.Equal("approver-b", reader.GetString(4));
        }

        await using var staleTransaction = await connection.BeginTransactionAsync();
        await using (var stale = new NpgsqlCommand("""
            SELECT set_config('fleetory.scope_reparent.scope_id', @scope_id, true),
                   set_config('fleetory.scope_reparent.new_parent_id', '', true),
                   set_config('fleetory.scope_reparent.expected_revision', '1', true),
                   set_config('fleetory.scope_reparent.incident_reference', 'INC-SCOPE-REParent-0002', true),
                   set_config('fleetory.scope_reparent.operator_reference', 'operator-a', true),
                   set_config('fleetory.scope_reparent.approver_reference', 'approver-b', true)
            """, connection, staleTransaction))
        {
            stale.Parameters.AddWithValue("scope_id", moved.ToString("D"));
            await stale.ExecuteNonQueryAsync();
        }
        var script = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "reparent-scope.sql"));
        await using var staleMutation = new NpgsqlCommand(script, connection, staleTransaction);
        var error = await Assert.ThrowsAsync<PostgresException>(
            () => staleMutation.ExecuteNonQueryAsync());
        Assert.Contains("stale", error.MessageText, StringComparison.OrdinalIgnoreCase);
        await staleTransaction.RollbackAsync();

        await using (var unchanged = new NpgsqlCommand("""
            SELECT scope.parent_scope_id,
                   (SELECT max(revision) FROM platform.authorization_scope_versions
                    WHERE scope_id = scope.scope_id),
                   (SELECT count(*) FROM platform.audit_events
                    WHERE target_id = scope.scope_id::text
                      AND action = 'platform.authorization.scope_reparented')
            FROM platform.authorization_scopes AS scope
            WHERE scope.scope_id = @moved
            """, connection))
        {
            unchanged.Parameters.AddWithValue("moved", moved);
            await using var reader = await unchanged.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(newParent, reader.GetGuid(0));
            Assert.Equal(2, reader.GetInt32(1));
            Assert.Equal(1, reader.GetInt64(2));
        }
    }

    private static async Task ExecuteMutationAsync(NpgsqlConnection connection,
        Guid moved, Guid newParent, int revision, string incident, string operatorId,
        string approverId)
    {
        await using var transaction = await connection.BeginTransactionAsync();
        await using var configure = new NpgsqlCommand("""
            SELECT set_config('fleetory.scope_reparent.scope_id', @scope_id, true),
                   set_config('fleetory.scope_reparent.new_parent_id', @parent_id, true),
                   set_config('fleetory.scope_reparent.expected_revision', @revision, true),
                   set_config('fleetory.scope_reparent.incident_reference', @incident, true),
                   set_config('fleetory.scope_reparent.operator_reference', @operator_id, true),
                   set_config('fleetory.scope_reparent.approver_reference', @approver_id, true)
            """, connection, transaction);
        configure.Parameters.AddWithValue("scope_id", moved.ToString("D"));
        configure.Parameters.AddWithValue("parent_id", newParent.ToString("D"));
        configure.Parameters.AddWithValue("revision", revision.ToString());
        configure.Parameters.AddWithValue("incident", incident);
        configure.Parameters.AddWithValue("operator_id", operatorId);
        configure.Parameters.AddWithValue("approver_id", approverId);
        await configure.ExecuteNonQueryAsync();
        var script = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "reparent-scope.sql"));
        await using var mutation = new NpgsqlCommand(script, connection, transaction);
        await mutation.ExecuteNonQueryAsync();
        await transaction.CommitAsync();
    }
}
