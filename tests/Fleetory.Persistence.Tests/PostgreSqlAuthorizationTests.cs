using Fleetory.Platform.Authorization;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Fleetory.SharedKernel;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class PostgreSqlAuthorizationTests(PostgreSqlTestFixture fixture)
{
    private const string ReadPermission = "Core.Device.Read";
    private const string WritePermission = "Core.Device.Write";

    [Fact]
    public async Task Grants_apply_to_assigned_scope_and_descendants_only()
    {
        var root = Guid.NewGuid();
        var child = Guid.NewGuid();
        var sibling = Guid.NewGuid();
        var actorId = $"person:{Guid.NewGuid():N}";
        await InsertScopeAsync(root);
        await InsertScopeAsync(child, root);
        await InsertScopeAsync(sibling);
        await InsertGrantAsync(actorId, ActorKind.Person, ReadPermission, root);

        await using var scope = fixture.Services.CreateAsyncScope();
        var authorizer = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var actor = new ActorReference(actorId, ActorKind.Person);

        Assert.True((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, ReadPermission, new ScopeId(root)))).IsAllowed);
        Assert.True((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, ReadPermission, new ScopeId(child)))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, ReadPermission, new ScopeId(sibling)))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, ReadPermission))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, WritePermission, new ScopeId(child)))).IsAllowed);
    }

    [Fact]
    public async Task Global_grant_requires_a_real_requested_scope_and_exact_actor_kind()
    {
        var knownScope = Guid.NewGuid();
        var actorId = $"person:{Guid.NewGuid():N}";
        await InsertScopeAsync(knownScope);
        await InsertGrantAsync(actorId, ActorKind.Person, ReadPermission);

        await using var scope = fixture.Services.CreateAsyncScope();
        var authorizer = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var actor = new ActorReference(actorId, ActorKind.Person);

        Assert.True((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, ReadPermission))).IsAllowed);
        Assert.True((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, ReadPermission, new ScopeId(knownScope)))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, ReadPermission, new ScopeId(Guid.NewGuid())))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(new ActorReference(actorId, ActorKind.Service), ReadPermission))).IsAllowed);
    }

    [Fact]
    public async Task No_grant_anonymous_actor_and_malformed_permissions_are_denied()
    {
        await using var scope = fixture.Services.CreateAsyncScope();
        var authorizer = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var actor = new ActorReference($"person:{Guid.NewGuid():N}", ActorKind.Person);

        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, ReadPermission))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(new ActorReference(actor.SubjectId, ActorKind.Anonymous), ReadPermission))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, "Core.Device.*"))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, "Core..Read"))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(actor, ReadPermission, new ScopeId(Guid.Empty)))).IsAllowed);
    }

    [Fact]
    public async Task Removed_grant_takes_effect_on_next_decision()
    {
        var actorId = $"person:{Guid.NewGuid():N}";
        var assignmentId = await InsertGrantAsync(actorId, ActorKind.Person, ReadPermission);
        await using var scope = fixture.Services.CreateAsyncScope();
        var authorizer = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var request = new AuthorizationRequest(new ActorReference(actorId, ActorKind.Person), ReadPermission);

        Assert.True((await authorizer.AuthorizeAsync(request)).IsAllowed);

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "DELETE FROM platform.authorization_assignments WHERE assignment_id = @id", connection);
        command.Parameters.AddWithValue("id", assignmentId);
        Assert.Equal(1, await command.ExecuteNonQueryAsync());

        Assert.False((await authorizer.AuthorizeAsync(request)).IsAllowed);
    }

    [Fact]
    public async Task Database_failure_never_returns_allow()
    {
        var authorizer = new PostgreSqlAuthorizationService(new PostgreSqlConnectionSettings(
            "Host=127.0.0.1;Port=1;Database=fleetory_auth_unavailable;Username=fleetory;Timeout=1;Pooling=false"));
        var request = new AuthorizationRequest(
            new ActorReference("person:operator", ActorKind.Person), ReadPermission);

        await Assert.ThrowsAsync<NpgsqlException>(
            async () => await authorizer.AuthorizeAsync(request));
    }

    [Fact]
    public async Task Audited_administration_creates_scoped_grant_and_revokes_it()
    {
        var administratorId = $"person:{Guid.NewGuid():N}";
        await InsertGrantAsync(administratorId, ActorKind.Person,
            PostgreSqlAuthorizationAdministration.Permission);
        var administrator = new ActorReference(administratorId, ActorKind.Person);
        var target = new ActorReference($"person:{Guid.NewGuid():N}", ActorKind.Person);
        var correlation = new CorrelationId(Guid.NewGuid().ToString("N"));
        await using var scope = fixture.Services.CreateAsyncScope();
        var administration = scope.ServiceProvider.GetRequiredService<PostgreSqlAuthorizationAdministration>();
        var authorizer = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();

        var root = await administration.CreateScopeAsync(administrator, "Security test root", null,
            correlation);
        var child = await administration.CreateScopeAsync(administrator, "Security test child",
            new ScopeId(root), correlation);
        var roleId = await administration.CreateRoleAsync(administrator, "Security test reader",
            [ReadPermission], correlation);
        var assignmentId = await administration.AssignRoleAsync(administrator, target, roleId,
            new ScopeId(root), correlation);

        Assert.True((await authorizer.AuthorizeAsync(new AuthorizationRequest(
            target, ReadPermission, new ScopeId(child)))).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(new AuthorizationRequest(
            target, ReadPermission))).IsAllowed);
        Assert.True(await administration.RevokeAssignmentAsync(administrator, assignmentId, correlation));
        Assert.False(await administration.RevokeAssignmentAsync(administrator, assignmentId, correlation));
        Assert.False((await authorizer.AuthorizeAsync(new AuthorizationRequest(
            target, ReadPermission, new ScopeId(child)))).IsAllowed);

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.audit_events AS event
            JOIN platform.audit_export_queue AS queue ON queue.audit_event_id = event.event_id
            WHERE event.correlation_id = @correlation
            """, connection);
        command.Parameters.AddWithValue("correlation", correlation.Value);
        Assert.Equal(6L, (long)(await command.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Administration_denial_is_audited_and_failed_audit_rolls_back_role()
    {
        var deniedActor = new ActorReference($"person:{Guid.NewGuid():N}", ActorKind.Person);
        var deniedCorrelation = new CorrelationId(Guid.NewGuid().ToString("N"));
        await using var scope = fixture.Services.CreateAsyncScope();
        var administration = scope.ServiceProvider.GetRequiredService<PostgreSqlAuthorizationAdministration>();

        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await administration.CreateRoleAsync(deniedActor, "Denied security test role",
                [ReadPermission], deniedCorrelation));

        var administratorId = $"person:{Guid.NewGuid():N}";
        await InsertGrantAsync(administratorId, ActorKind.Person,
            PostgreSqlAuthorizationAdministration.Permission);
        var administrator = new ActorReference(administratorId, ActorKind.Person);
        var roleName = $"Rollback {Guid.NewGuid():N}";
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await administration.CreateRoleAsync(administrator, roleName, [ReadPermission],
                new CorrelationId(string.Empty)));

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var deniedAudit = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.audit_events
            WHERE correlation_id = @correlation AND action = 'platform.authorization.manage_denied'
            """, connection);
        deniedAudit.Parameters.AddWithValue("correlation", deniedCorrelation.Value);
        Assert.Equal(1L, (long)(await deniedAudit.ExecuteScalarAsync())!);
        await using var missingRole = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.authorization_roles WHERE name = @name
            """, connection);
        missingRole.Parameters.AddWithValue("name", roleName);
        Assert.Equal(0L, (long)(await missingRole.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Last_global_administrator_cannot_be_revoked()
    {
        await using (var connection = new NpgsqlConnection(fixture.ConnectionString))
        {
            await connection.OpenAsync();
            await using var clear = new NpgsqlCommand("""
                DELETE FROM platform.authorization_assignments AS assignment
                USING platform.authorization_role_permissions AS permission
                WHERE permission.role_id = assignment.role_id
                  AND permission.permission = 'platform.authorization.manage'
                  AND assignment.scope_id IS NULL
                """, connection);
            await clear.ExecuteNonQueryAsync();
        }

        var firstId = $"person:{Guid.NewGuid():N}";
        var firstAssignment = await InsertGrantAsync(firstId, ActorKind.Person,
            PostgreSqlAuthorizationAdministration.Permission);
        var firstActor = new ActorReference(firstId, ActorKind.Person);
        var correlation = new CorrelationId(Guid.NewGuid().ToString("N"));
        await using var scope = fixture.Services.CreateAsyncScope();
        var administration = scope.ServiceProvider.GetRequiredService<PostgreSqlAuthorizationAdministration>();
        var authorizer = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await administration.RevokeAssignmentAsync(firstActor, firstAssignment, correlation));
        Assert.True((await authorizer.AuthorizeAsync(new AuthorizationRequest(
            firstActor, PostgreSqlAuthorizationAdministration.Permission))).IsAllowed);

        await using (var connection = new NpgsqlConnection(fixture.ConnectionString))
        {
            await connection.OpenAsync();
            await using var audit = new NpgsqlCommand("""
                SELECT COUNT(*) FROM platform.audit_events
                WHERE correlation_id = @correlation
                  AND action = 'platform.authorization.assignment_revocation_blocked'
                """, connection);
            audit.Parameters.AddWithValue("correlation", correlation.Value);
            Assert.Equal(1L, (long)(await audit.ExecuteScalarAsync())!);
        }

        var secondId = $"person:{Guid.NewGuid():N}";
        await InsertGrantAsync(secondId, ActorKind.Person,
            PostgreSqlAuthorizationAdministration.Permission);
        Assert.True(await administration.RevokeAssignmentAsync(firstActor,
            firstAssignment, correlation));
        Assert.False((await authorizer.AuthorizeAsync(new AuthorizationRequest(
            firstActor, PostgreSqlAuthorizationAdministration.Permission))).IsAllowed);
        Assert.True((await authorizer.AuthorizeAsync(new AuthorizationRequest(
            new ActorReference(secondId, ActorKind.Person),
            PostgreSqlAuthorizationAdministration.Permission))).IsAllowed);
    }

    private async Task InsertScopeAsync(Guid scopeId, Guid? parentScopeId = null)
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.authorization_scopes (scope_id, parent_scope_id, name)
            VALUES (@scope_id, @parent_scope_id, @name)
            """, connection);
        command.Parameters.AddWithValue("scope_id", scopeId);
        command.Parameters.AddWithValue("parent_scope_id", (object?)parentScopeId ?? DBNull.Value);
        command.Parameters.AddWithValue("name", $"Scope {scopeId:N}");
        await command.ExecuteNonQueryAsync();
    }

    private async Task<Guid> InsertGrantAsync(
        string actorId,
        ActorKind actorKind,
        string permission,
        Guid? scopeId = null)
    {
        var roleId = Guid.NewGuid();
        var assignmentId = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.authorization_roles (role_id, name)
            VALUES (@role_id, @name);
            INSERT INTO platform.authorization_role_permissions (role_id, permission)
            VALUES (@role_id, @permission);
            INSERT INTO platform.authorization_assignments
                (assignment_id, actor_subject_id, actor_kind, role_id, scope_id)
            VALUES (@assignment_id, @actor_subject_id, @actor_kind, @role_id, @scope_id);
            """, connection, transaction);
        command.Parameters.AddWithValue("role_id", roleId);
        command.Parameters.AddWithValue("name", $"Role {roleId:N}");
        command.Parameters.AddWithValue("permission", permission);
        command.Parameters.AddWithValue("assignment_id", assignmentId);
        command.Parameters.AddWithValue("actor_subject_id", actorId);
        command.Parameters.AddWithValue("actor_kind", (int)actorKind);
        command.Parameters.AddWithValue("scope_id", (object?)scopeId ?? DBNull.Value);
        await command.ExecuteNonQueryAsync();
        await transaction.CommitAsync();
        return assignmentId;
    }
}
