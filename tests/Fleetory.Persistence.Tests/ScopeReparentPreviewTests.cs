using System.Text.Json;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class ScopeReparentPreviewTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task Preview_lists_changed_ancestor_grants_without_writing_scope_tree()
    {
        var oldRoot = Guid.NewGuid();
        var newRoot = Guid.NewGuid();
        var moved = Guid.NewGuid();
        var child = Guid.NewGuid();
        var oldRole = Guid.NewGuid();
        var newRole = Guid.NewGuid();
        var globalRole = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();

        await using (var setup = new NpgsqlCommand("""
            INSERT INTO platform.authorization_scopes (scope_id, parent_scope_id, name)
            VALUES (@old, NULL, 'old'), (@new, NULL, 'new'),
                   (@moved, @old, 'moved'), (@child, @moved, 'child');
            INSERT INTO platform.authorization_roles (role_id, name)
            VALUES (@old_role, 'old role'), (@new_role, 'new role'),
                   (@global_role, 'global role');
            INSERT INTO platform.authorization_role_permissions (role_id, permission)
            VALUES (@old_role, 'assets.read'), (@new_role, 'assets.write'),
                   (@global_role, 'platform.authorization.manage');
            INSERT INTO platform.authorization_assignments
                (assignment_id, actor_subject_id, actor_kind, role_id, scope_id)
            VALUES (gen_random_uuid(), 'person:old', 1, @old_role, @old),
                   (gen_random_uuid(), 'person:new', 1, @new_role, @new),
                   (gen_random_uuid(), 'person:global', 1, @global_role, NULL);
            """, connection, transaction))
        {
            setup.Parameters.AddWithValue("old", oldRoot);
            setup.Parameters.AddWithValue("new", newRoot);
            setup.Parameters.AddWithValue("moved", moved);
            setup.Parameters.AddWithValue("child", child);
            setup.Parameters.AddWithValue("old_role", oldRole);
            setup.Parameters.AddWithValue("new_role", newRole);
            setup.Parameters.AddWithValue("global_role", globalRole);
            await setup.ExecuteNonQueryAsync();
        }

        using var valid = await PreviewAsync(connection, transaction, moved, newRoot);
        var report = valid.RootElement;
        Assert.Equal("valid", report.GetProperty("status").GetString());
        Assert.Equal(2, report.GetProperty("subtree_scope_count").GetInt32());
        var grants = report.GetProperty("candidate_access_changes").EnumerateArray()
            .Select(item => (item.GetProperty("effect").GetString(),
                item.GetProperty("actor_subject_id").GetString(),
                item.GetProperty("permission").GetString()))
            .ToArray();
        Assert.Contains(("lost", "person:old", "assets.read"), grants);
        Assert.Contains(("gained", "person:new", "assets.write"), grants);
        Assert.Equal(2, grants.Length);

        using var cycle = await PreviewAsync(connection, transaction, moved, child);
        Assert.Equal("cycle", cycle.RootElement.GetProperty("status").GetString());
        Assert.Empty(cycle.RootElement.GetProperty("candidate_access_changes").EnumerateArray());

        using var missing = await PreviewAsync(connection, transaction, moved, Guid.NewGuid());
        Assert.Equal("missing_parent", missing.RootElement.GetProperty("status").GetString());
        Assert.Empty(missing.RootElement.GetProperty("candidate_access_changes").EnumerateArray());

        using var unchanged = await PreviewAsync(connection, transaction, moved, oldRoot);
        Assert.Equal("no_change", unchanged.RootElement.GetProperty("status").GetString());

        using var toRoot = await PreviewAsync(connection, transaction, moved, null);
        Assert.Equal("valid", toRoot.RootElement.GetProperty("status").GetString());
        Assert.Single(toRoot.RootElement.GetProperty("candidate_access_changes").EnumerateArray());

        using var missingScope = await PreviewAsync(connection, transaction, Guid.NewGuid(), newRoot);
        Assert.Equal("missing_scope", missingScope.RootElement.GetProperty("status").GetString());

        await using var current = new NpgsqlCommand("""
            SELECT parent_scope_id FROM platform.authorization_scopes WHERE scope_id = @moved
            """, connection, transaction);
        current.Parameters.AddWithValue("moved", moved);
        Assert.Equal(oldRoot, (Guid)(await current.ExecuteScalarAsync())!);
        await transaction.RollbackAsync();
    }

    private static async Task<JsonDocument> PreviewAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        Guid scopeId, Guid? newParent)
    {
        await using (var configure = new NpgsqlCommand("""
            SELECT set_config('fleetory.scope_preview.scope_id', @scope_id, true),
                   set_config('fleetory.scope_preview.new_parent_id', @new_parent, true)
            """, connection, transaction))
        {
            configure.Parameters.AddWithValue("scope_id", scopeId.ToString("D"));
            configure.Parameters.AddWithValue("new_parent", newParent?.ToString("D") ?? string.Empty);
            await configure.ExecuteNonQueryAsync();
        }

        var sql = await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "preview-scope-reparent.sql"));
        await using var preview = new NpgsqlCommand(sql, connection, transaction);
        return JsonDocument.Parse((string)(await preview.ExecuteScalarAsync())!);
    }
}
