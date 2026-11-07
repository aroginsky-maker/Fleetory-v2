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
    public async Task Role_replacement_moves_assignments_atomically_and_preserves_scope()
    {
        var administratorId = $"person:{Guid.NewGuid():N}";
        await InsertGrantAsync(administratorId, ActorKind.Person,
            PostgreSqlAuthorizationAdministration.Permission);
        var administrator = new ActorReference(administratorId, ActorKind.Person);
        var target = new ActorReference($"person:{Guid.NewGuid():N}", ActorKind.Person);
        var correlation = CorrelationId.New();
        await using var scope = fixture.Services.CreateAsyncScope();
        var administration = scope.ServiceProvider.GetRequiredService<PostgreSqlAuthorizationAdministration>();
        var authorizer = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var scopeId = await administration.CreateScopeAsync(administrator, "Replacement scope",
            null, correlation);
        var oldRoleId = await administration.CreateRoleAsync(administrator,
            "Reader version", [ReadPermission], correlation);
        var assignmentId = await administration.AssignRoleAsync(administrator, target,
            oldRoleId, new ScopeId(scopeId), correlation);
        var read = new AuthorizationRequest(target, ReadPermission, new ScopeId(scopeId));
        var write = new AuthorizationRequest(target, WritePermission, new ScopeId(scopeId));
        Assert.True((await authorizer.AuthorizeAsync(read)).IsAllowed);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await administration.ReplaceRoleAsync(administrator, oldRoleId,
                "Writer version", [WritePermission], new CorrelationId(string.Empty)));
        Assert.True((await authorizer.AuthorizeAsync(read)).IsAllowed);
        await using (var rollbackConnection = new NpgsqlConnection(fixture.ConnectionString))
        {
            await rollbackConnection.OpenAsync();
            await using var rollback = new NpgsqlCommand("""
                SELECT COUNT(*) FROM platform.authorization_role_versions
                WHERE predecessor_role_id = @old_role_id
                """, rollbackConnection);
            rollback.Parameters.AddWithValue("old_role_id", oldRoleId);
            Assert.Equal(0L, (long)(await rollback.ExecuteScalarAsync())!);
        }

        var newRoleId = await administration.ReplaceRoleAsync(administrator, oldRoleId,
            "Writer version", [WritePermission], correlation);
        Assert.NotNull(newRoleId);
        Assert.NotEqual(oldRoleId, newRoleId.Value);
        Assert.False((await authorizer.AuthorizeAsync(read)).IsAllowed);
        Assert.True((await authorizer.AuthorizeAsync(write)).IsAllowed);
        Assert.False((await authorizer.AuthorizeAsync(
            new AuthorizationRequest(target, WritePermission))).IsAllowed);
        Assert.Null(await administration.ReplaceRoleAsync(administrator, oldRoleId,
            "Missing version", [ReadPermission], correlation));
        var versions = await administration.GetRoleVersionsAsync(administrator,
            newRoleId.Value, correlation);
        Assert.Equal(2, versions.Length);
        Assert.Equal(newRoleId.Value, versions[0].RoleId);
        Assert.Equal(oldRoleId, versions[0].PredecessorRoleId);
        Assert.Equal([WritePermission], versions[0].Permissions);
        Assert.Equal(oldRoleId, versions[1].RoleId);
        Assert.Null(versions[1].PredecessorRoleId);
        Assert.Equal([ReadPermission], versions[1].Permissions);
        var retiredVersion = await administration.GetRoleVersionsAsync(administrator,
            oldRoleId, correlation);
        Assert.Single(retiredVersion);
        Assert.Equal(oldRoleId, retiredVersion[0].RoleId);
        Assert.Empty(await administration.GetRoleVersionsAsync(administrator,
            Guid.NewGuid(), correlation));

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var moved = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.authorization_assignments
            WHERE assignment_id = @assignment_id AND role_id = @new_role_id
            """, connection);
        moved.Parameters.AddWithValue("assignment_id", assignmentId);
        moved.Parameters.AddWithValue("new_role_id", newRoleId.Value);
        Assert.Equal(1L, (long)(await moved.ExecuteScalarAsync())!);
        await using var retired = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.authorization_roles WHERE role_id = @old_role_id
            """, connection);
        retired.Parameters.AddWithValue("old_role_id", oldRoleId);
        Assert.Equal(0L, (long)(await retired.ExecuteScalarAsync())!);
        await using var oldVersion = new NpgsqlCommand("""
            SELECT predecessor_role_id, permissions
            FROM platform.authorization_role_versions WHERE role_id = @role_id
            """, connection);
        oldVersion.Parameters.AddWithValue("role_id", oldRoleId);
        await using (var oldReader = await oldVersion.ExecuteReaderAsync())
        {
            Assert.True(await oldReader.ReadAsync());
            Assert.True(await oldReader.IsDBNullAsync(0));
            Assert.Equal([ReadPermission], oldReader.GetFieldValue<string[]>(1));
        }
        await using var newVersion = new NpgsqlCommand("""
            SELECT predecessor_role_id, permissions
            FROM platform.authorization_role_versions WHERE role_id = @role_id
            """, connection);
        newVersion.Parameters.AddWithValue("role_id", newRoleId.Value);
        await using (var newReader = await newVersion.ExecuteReaderAsync())
        {
            Assert.True(await newReader.ReadAsync());
            Assert.Equal(oldRoleId, newReader.GetGuid(0));
            Assert.Equal([WritePermission], newReader.GetFieldValue<string[]>(1));
        }
        await using var audits = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.audit_events AS event
            JOIN platform.audit_export_queue AS queue ON queue.audit_event_id = event.event_id
            WHERE event.correlation_id = @correlation
              AND event.action IN ('platform.authorization.role_replaced',
                                   'platform.authorization.role_unchanged')
            """, connection);
        audits.Parameters.AddWithValue("correlation", correlation.Value);
        Assert.Equal(2L, (long)(await audits.ExecuteScalarAsync())!);
        await using var readAudit = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.audit_events
            WHERE correlation_id = @correlation
              AND action IN ('platform.authorization.role_versions_read',
                             'platform.authorization.role_versions_missing')
            """, connection);
        readAudit.Parameters.AddWithValue("correlation", correlation.Value);
        Assert.Equal(3L, (long)(await readAudit.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Role_replacement_cannot_remove_last_global_manager_permission()
    {
        await using (var resetConnection = new NpgsqlConnection(fixture.ConnectionString))
        {
            await resetConnection.OpenAsync();
            await using var clear = new NpgsqlCommand("""
                DELETE FROM platform.authorization_assignments AS assignment
                USING platform.authorization_role_permissions AS permission
                WHERE permission.role_id = assignment.role_id
                  AND permission.permission = 'platform.authorization.manage'
                  AND assignment.scope_id IS NULL
                """, resetConnection);
            await clear.ExecuteNonQueryAsync();
        }

        var administratorId = $"person:{Guid.NewGuid():N}";
        var assignmentId = await InsertGrantAsync(administratorId, ActorKind.Person,
            PostgreSqlAuthorizationAdministration.Permission);
        var administrator = new ActorReference(administratorId, ActorKind.Person);
        var correlation = CorrelationId.New();
        await using var scope = fixture.Services.CreateAsyncScope();
        var administration = scope.ServiceProvider.GetRequiredService<PostgreSqlAuthorizationAdministration>();
        var authorizer = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var role = new NpgsqlCommand("""
            SELECT role_id FROM platform.authorization_assignments
            WHERE assignment_id = @assignment_id
            """, connection);
        role.Parameters.AddWithValue("assignment_id", assignmentId);
        var oldRoleId = (Guid)(await role.ExecuteScalarAsync())!;

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await administration.ReplaceRoleAsync(administrator, oldRoleId,
                "Reader without management", [ReadPermission], correlation));
        Assert.True((await authorizer.AuthorizeAsync(new AuthorizationRequest(
            administrator, PostgreSqlAuthorizationAdministration.Permission))).IsAllowed);

        var newRoleId = await administration.ReplaceRoleAsync(administrator, oldRoleId,
            "Manager and reader", [PostgreSqlAuthorizationAdministration.Permission,
                ReadPermission], correlation);
        Assert.NotNull(newRoleId);
        Assert.True((await authorizer.AuthorizeAsync(new AuthorizationRequest(
            administrator, PostgreSqlAuthorizationAdministration.Permission))).IsAllowed);
        await using var history = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.authorization_role_versions
            WHERE role_id = @old_role_id OR
                  (role_id = @new_role_id AND predecessor_role_id = @old_role_id)
            """, connection);
        history.Parameters.AddWithValue("old_role_id", oldRoleId);
        history.Parameters.AddWithValue("new_role_id", newRoleId.Value);
        Assert.Equal(2L, (long)(await history.ExecuteScalarAsync())!);
        await using var blockedAudit = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.audit_events
            WHERE correlation_id = @correlation
              AND action = 'platform.authorization.role_replacement_blocked'
            """, connection);
        blockedAudit.Parameters.AddWithValue("correlation", correlation.Value);
        Assert.Equal(1L, (long)(await blockedAudit.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Scope_revision_preserves_identity_assignments_and_child_access()
    {
        var administratorId = $"person:{Guid.NewGuid():N}";
        await InsertGrantAsync(administratorId, ActorKind.Person,
            PostgreSqlAuthorizationAdministration.Permission);
        var administrator = new ActorReference(administratorId, ActorKind.Person);
        var target = new ActorReference($"person:{Guid.NewGuid():N}", ActorKind.Person);
        var correlation = CorrelationId.New();
        await using var serviceScope = fixture.Services.CreateAsyncScope();
        var administration = serviceScope.ServiceProvider
            .GetRequiredService<PostgreSqlAuthorizationAdministration>();
        var authorizer = serviceScope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var rootId = await administration.CreateScopeAsync(administrator,
            "Original scope", null, correlation);
        var childId = await administration.CreateScopeAsync(administrator,
            "Child scope", new ScopeId(rootId), correlation);
        var roleId = await administration.CreateRoleAsync(administrator,
            "Scoped reader", [ReadPermission], correlation);
        var assignmentId = await administration.AssignRoleAsync(administrator,
            target, roleId, new ScopeId(rootId), correlation);
        var access = new AuthorizationRequest(target, ReadPermission, new ScopeId(childId));
        Assert.True((await authorizer.AuthorizeAsync(access)).IsAllowed);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await administration.ReplaceScopeAsync(administrator, rootId,
                "New scope", 1, new CorrelationId(string.Empty)));
        var initial = await administration.GetScopeVersionsAsync(administrator,
            rootId, correlation);
        Assert.Single(initial);
        Assert.Equal("Original scope", initial[0].Name);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await administration.ReplaceScopeAsync(administrator, rootId,
                "Stale scope", 2, correlation));
        Assert.Equal(2, await administration.ReplaceScopeAsync(administrator,
            rootId, "New scope", 1, correlation));
        Assert.True((await authorizer.AuthorizeAsync(access)).IsAllowed);
        var versions = await administration.GetScopeVersionsAsync(administrator,
            rootId, correlation);
        Assert.Equal(2, versions.Length);
        Assert.Equal((2, "New scope"), (versions[0].Revision, versions[0].Name));
        Assert.Equal((1, "Original scope"), (versions[1].Revision, versions[1].Name));
        Assert.Null(versions[0].ParentScopeId);
        Assert.Null(await administration.ReplaceScopeAsync(administrator,
            Guid.NewGuid(), "Missing scope", 1, correlation));
        Assert.Empty(await administration.GetScopeVersionsAsync(administrator,
            Guid.NewGuid(), correlation));

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var relationships = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.authorization_assignments AS assignment
            JOIN platform.authorization_scopes AS child
              ON child.parent_scope_id = assignment.scope_id
            WHERE assignment.assignment_id = @assignment_id
              AND assignment.scope_id = @root_id
              AND child.scope_id = @child_id
            """, connection);
        relationships.Parameters.AddWithValue("assignment_id", assignmentId);
        relationships.Parameters.AddWithValue("root_id", rootId);
        relationships.Parameters.AddWithValue("child_id", childId);
        Assert.Equal(1L, (long)(await relationships.ExecuteScalarAsync())!);
        await using var blocked = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.audit_events
            WHERE correlation_id = @correlation
              AND action = 'platform.authorization.scope_replacement_blocked'
            """, connection);
        blocked.Parameters.AddWithValue("correlation", correlation.Value);
        Assert.Equal(1L, (long)(await blocked.ExecuteScalarAsync())!);
        await using var missingAudit = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.audit_events
            WHERE correlation_id = @correlation
              AND action IN ('platform.authorization.scope_unchanged',
                             'platform.authorization.scope_versions_missing')
            """, connection);
        missingAudit.Parameters.AddWithValue("correlation", correlation.Value);
        Assert.Equal(2L, (long)(await missingAudit.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Legacy_scope_gets_a_starting_snapshot_before_revision()
    {
        var administratorId = $"person:{Guid.NewGuid():N}";
        await InsertGrantAsync(administratorId, ActorKind.Person,
            PostgreSqlAuthorizationAdministration.Permission);
        var scopeId = Guid.NewGuid();
        await InsertScopeAsync(scopeId);
        await using var serviceScope = fixture.Services.CreateAsyncScope();
        var administration = serviceScope.ServiceProvider
            .GetRequiredService<PostgreSqlAuthorizationAdministration>();
        var administrator = new ActorReference(administratorId, ActorKind.Person);
        Assert.Equal(2, await administration.ReplaceScopeAsync(administrator,
            scopeId, "Renamed legacy scope", 1, CorrelationId.New()));
        var versions = await administration.GetScopeVersionsAsync(administrator,
            scopeId, CorrelationId.New());
        Assert.Equal(2, versions.Length);
        Assert.Equal($"Scope {scopeId:N}", versions[1].Name);
    }

    [Fact]
    public async Task Roles_and_scopes_retire_only_after_assignments_and_children_are_removed()
    {
        var administratorId = $"person:{Guid.NewGuid():N}";
        await InsertGrantAsync(administratorId, ActorKind.Person,
            PostgreSqlAuthorizationAdministration.Permission);
        var administrator = new ActorReference(administratorId, ActorKind.Person);
        var target = new ActorReference($"person:{Guid.NewGuid():N}", ActorKind.Person);
        var correlation = new CorrelationId(Guid.NewGuid().ToString("N"));
        await using var scope = fixture.Services.CreateAsyncScope();
        var administration = scope.ServiceProvider.GetRequiredService<PostgreSqlAuthorizationAdministration>();

        var roleId = await administration.CreateRoleAsync(administrator, "Retire test role",
            [ReadPermission], correlation);
        var root = await administration.CreateScopeAsync(administrator, "Retire test root",
            null, correlation);
        var child = await administration.CreateScopeAsync(administrator, "Retire test child",
            new ScopeId(root), correlation);
        var assignmentId = await administration.AssignRoleAsync(administrator, target, roleId,
            new ScopeId(child), correlation);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await administration.RetireRoleAsync(administrator, roleId, correlation));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await administration.RetireScopeAsync(administrator, child, correlation));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await administration.RetireScopeAsync(administrator, root, correlation));

        await using (var connection = new NpgsqlConnection(fixture.ConnectionString))
        {
            await connection.OpenAsync();
            await using var unsafeDelete = new NpgsqlCommand(
                "DELETE FROM platform.authorization_roles WHERE role_id = @id", connection);
            unsafeDelete.Parameters.AddWithValue("id", roleId);
            var foreignKey = await Assert.ThrowsAsync<PostgresException>(async () =>
                await unsafeDelete.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.RestrictViolation, foreignKey.SqlState);
        }

        Assert.True(await administration.RevokeAssignmentAsync(administrator, assignmentId, correlation));
        Assert.True(await administration.RetireScopeAsync(administrator, child, correlation));
        Assert.False(await administration.RetireScopeAsync(administrator, child, correlation));
        Assert.True(await administration.RetireScopeAsync(administrator, root, correlation));
        Assert.True(await administration.RetireRoleAsync(administrator, roleId, correlation));

        await using var auditConnection = new NpgsqlConnection(fixture.ConnectionString);
        await auditConnection.OpenAsync();
        await using var audit = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.audit_events AS event
            JOIN platform.audit_export_queue AS queue ON queue.audit_event_id = event.event_id
            WHERE event.correlation_id = @correlation
            """, auditConnection);
        audit.Parameters.AddWithValue("correlation", correlation.Value);
        Assert.Equal(12L, (long)(await audit.ExecuteScalarAsync())!);
        await using var blocked = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.audit_events
            WHERE correlation_id = @correlation
              AND action IN (
                  'platform.authorization.role_retirement_blocked',
                  'platform.authorization.scope_retirement_blocked')
            """, auditConnection);
        blocked.Parameters.AddWithValue("correlation", correlation.Value);
        Assert.Equal(3L, (long)(await blocked.ExecuteScalarAsync())!);
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
