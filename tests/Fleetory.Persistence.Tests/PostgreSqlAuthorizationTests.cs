using Fleetory.Platform.Authorization;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
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
