using System.Data;
using Fleetory.Platform.Audit;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Fleetory.SharedKernel;
using Npgsql;
using NpgsqlTypes;

namespace Fleetory.Platform.Authorization;

/// <summary>Platform-owned, audited writes to the local authorization model.</summary>
internal sealed class PostgreSqlAuthorizationAdministration(
    PostgreSqlConnectionSettings settings,
    PostgreSqlAuditWriter audit,
    IClock clock)
{
    internal const string Permission = "platform.authorization.manage";

    public ValueTask<Guid> CreateRoleAsync(
        ActorReference actor,
        string name,
        IReadOnlyCollection<string> permissions,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        ValidateRole(name, permissions);
        var permissionSet = permissions.ToArray();

        var roleId = Guid.CreateVersion7();
        return ExecuteAuthorizedAsync(actor, "platform.authorization.role_created",
            new AuditTarget("role", roleId.ToString("D")), correlationId,
            new Dictionary<string, string>
            {
                ["name"] = name,
                ["permission_count"] = permissionSet.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)
            },
            async (connection, transaction, token) =>
            {
                await InsertRoleAsync(connection, transaction, roleId, name, permissionSet, token);
                return roleId;
            }, cancellationToken);
    }

    public async ValueTask<Guid?> ReplaceRoleAsync(
        ActorReference actor,
        Guid oldRoleId,
        string name,
        IReadOnlyCollection<string> permissions,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (oldRoleId == Guid.Empty)
        {
            throw new ArgumentException("Role ID is invalid.", nameof(oldRoleId));
        }

        ValidateRole(name, permissions);
        var permissionSet = permissions.ToArray();
        var newRoleId = Guid.CreateVersion7();
        var outcome = await ExecuteAuthorizedAsync(actor,
            "platform.authorization.role_replaced",
            new AuditTarget("role", oldRoleId.ToString("D")), correlationId,
            new Dictionary<string, string>
            {
                ["replacement_role_id"] = newRoleId.ToString("D"),
                ["name"] = name,
                ["permission_count"] = permissionSet.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)
            },
            async (connection, transaction, token) =>
            {
                await using (var oldRole = new NpgsqlCommand("""
                    SELECT role_id FROM platform.authorization_roles
                    WHERE role_id = @old_role_id FOR UPDATE
                    """, connection, transaction))
                {
                    oldRole.Parameters.AddWithValue("old_role_id", NpgsqlDbType.Uuid, oldRoleId);
                    if (await oldRole.ExecuteScalarAsync(token) is null)
                    {
                        return RoleReplacementOutcome.Missing;
                    }
                }

                if (!permissionSet.Contains(Permission, StringComparer.Ordinal))
                {
                    await using var lastManager = new NpgsqlCommand("""
                        SELECT EXISTS (
                            SELECT 1 FROM platform.authorization_role_permissions
                            WHERE role_id = @old_role_id AND permission = @permission
                        ) AND EXISTS (
                            SELECT 1 FROM platform.authorization_assignments
                            WHERE role_id = @old_role_id AND scope_id IS NULL
                        ) AND NOT EXISTS (
                            SELECT 1 FROM platform.authorization_assignments AS assignment
                            JOIN platform.authorization_role_permissions AS permission
                              ON permission.role_id = assignment.role_id
                            WHERE assignment.role_id <> @old_role_id
                              AND assignment.scope_id IS NULL
                              AND permission.permission = @permission
                        )
                        """, connection, transaction);
                    lastManager.Parameters.AddWithValue("old_role_id", NpgsqlDbType.Uuid, oldRoleId);
                    lastManager.Parameters.AddWithValue("permission", NpgsqlDbType.Varchar, Permission);
                    if ((bool)(await lastManager.ExecuteScalarAsync(token))!)
                    {
                        return RoleReplacementOutcome.LastManagerProtected;
                    }
                }

                await InsertRoleAsync(connection, transaction, newRoleId, name, permissionSet, token);
                await using (var moveAssignments = new NpgsqlCommand("""
                    UPDATE platform.authorization_assignments
                    SET role_id = @new_role_id WHERE role_id = @old_role_id
                    """, connection, transaction))
                {
                    moveAssignments.Parameters.AddWithValue("new_role_id", NpgsqlDbType.Uuid, newRoleId);
                    moveAssignments.Parameters.AddWithValue("old_role_id", NpgsqlDbType.Uuid, oldRoleId);
                    await moveAssignments.ExecuteNonQueryAsync(token);
                }

                await using var retireOld = new NpgsqlCommand("""
                    DELETE FROM platform.authorization_roles WHERE role_id = @old_role_id
                    """, connection, transaction);
                retireOld.Parameters.AddWithValue("old_role_id", NpgsqlDbType.Uuid, oldRoleId);
                await retireOld.ExecuteNonQueryAsync(token);
                return RoleReplacementOutcome.Replaced;
            }, cancellationToken,
            result => result switch
            {
                RoleReplacementOutcome.Missing => "platform.authorization.role_unchanged",
                RoleReplacementOutcome.LastManagerProtected =>
                    "platform.authorization.role_replacement_blocked",
                _ => "platform.authorization.role_replaced"
            });

        if (outcome == RoleReplacementOutcome.LastManagerProtected)
        {
            throw new InvalidOperationException(
                "The last global authorization administrator cannot be removed.");
        }

        return outcome == RoleReplacementOutcome.Replaced ? newRoleId : null;
    }

    public ValueTask<Guid> CreateScopeAsync(
        ActorReference actor,
        string name,
        ScopeId? parentScopeId,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        ValidateName(name);
        if (parentScopeId?.Value == Guid.Empty)
        {
            throw new ArgumentException("Parent scope is invalid.", nameof(parentScopeId));
        }

        var scopeId = Guid.CreateVersion7();
        return ExecuteAuthorizedAsync(actor, "platform.authorization.scope_created",
            new AuditTarget("scope", scopeId.ToString("D")), correlationId,
            new Dictionary<string, string>
            {
                ["name"] = name,
                ["parent_scope_id"] = parentScopeId?.Value.ToString("D") ?? string.Empty
            },
            async (connection, transaction, token) =>
            {
                await using var command = new NpgsqlCommand("""
                    INSERT INTO platform.authorization_scopes (scope_id, parent_scope_id, name)
                    VALUES (@scope_id, @parent_scope_id, @name)
                    """, connection, transaction);
                command.Parameters.AddWithValue("scope_id", NpgsqlDbType.Uuid, scopeId);
                command.Parameters.AddWithValue("parent_scope_id", NpgsqlDbType.Uuid,
                    (object?)parentScopeId?.Value ?? DBNull.Value);
                command.Parameters.AddWithValue("name", NpgsqlDbType.Varchar, name);
                await command.ExecuteNonQueryAsync(token);
                return scopeId;
            }, cancellationToken);
    }

    public ValueTask<Guid> AssignRoleAsync(
        ActorReference actor,
        ActorReference targetActor,
        Guid roleId,
        ScopeId? scopeId,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (targetActor is null || targetActor.Kind is ActorKind.Anonymous ||
            !Enum.IsDefined(targetActor.Kind) ||
            string.IsNullOrWhiteSpace(targetActor.SubjectId) ||
            targetActor.SubjectId.Length > 128 || roleId == Guid.Empty ||
            scopeId?.Value == Guid.Empty)
        {
            throw new ArgumentException("Role assignment is invalid.");
        }

        var assignmentId = Guid.CreateVersion7();
        return ExecuteAuthorizedAsync(actor, "platform.authorization.role_assigned",
            new AuditTarget("assignment", assignmentId.ToString("D")), correlationId,
            new Dictionary<string, string>
            {
                ["role_id"] = roleId.ToString("D"),
                ["scope_id"] = scopeId?.Value.ToString("D") ?? string.Empty,
                ["subject_id"] = targetActor.SubjectId,
                ["actor_kind"] = targetActor.Kind.ToString()
            },
            async (connection, transaction, token) =>
            {
                await using var command = new NpgsqlCommand("""
                    INSERT INTO platform.authorization_assignments
                        (assignment_id, actor_subject_id, actor_kind, role_id, scope_id)
                    VALUES (@assignment_id, @actor_subject_id, @actor_kind, @role_id, @scope_id)
                    """, connection, transaction);
                command.Parameters.AddWithValue("assignment_id", NpgsqlDbType.Uuid, assignmentId);
                command.Parameters.AddWithValue("actor_subject_id", NpgsqlDbType.Varchar,
                    targetActor.SubjectId);
                command.Parameters.AddWithValue("actor_kind", NpgsqlDbType.Integer,
                    (int)targetActor.Kind);
                command.Parameters.AddWithValue("role_id", NpgsqlDbType.Uuid, roleId);
                command.Parameters.AddWithValue("scope_id", NpgsqlDbType.Uuid,
                    (object?)scopeId?.Value ?? DBNull.Value);
                await command.ExecuteNonQueryAsync(token);
                return assignmentId;
            }, cancellationToken);
    }

    public async ValueTask<bool> RevokeAssignmentAsync(
        ActorReference actor,
        Guid assignmentId,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (assignmentId == Guid.Empty)
        {
            throw new ArgumentException("Assignment is invalid.", nameof(assignmentId));
        }

        var outcome = await ExecuteAuthorizedAsync(actor,
            "platform.authorization.assignment_revoked",
            new AuditTarget("assignment", assignmentId.ToString("D")), correlationId,
            null,
            async (connection, transaction, token) =>
            {
                await using (var lastManager = new NpgsqlCommand("""
                    SELECT EXISTS (
                        SELECT 1 FROM platform.authorization_assignments AS assignment
                        JOIN platform.authorization_role_permissions AS permission
                          ON permission.role_id = assignment.role_id
                        WHERE assignment.assignment_id = @assignment_id
                          AND assignment.scope_id IS NULL
                          AND permission.permission = @permission
                    ) AND (
                        SELECT COUNT(*) FROM platform.authorization_assignments AS assignment
                        JOIN platform.authorization_role_permissions AS permission
                          ON permission.role_id = assignment.role_id
                        WHERE assignment.scope_id IS NULL
                          AND permission.permission = @permission
                    ) = 1
                    """, connection, transaction))
                {
                    lastManager.Parameters.AddWithValue("assignment_id", NpgsqlDbType.Uuid,
                        assignmentId);
                    lastManager.Parameters.AddWithValue("permission", NpgsqlDbType.Varchar,
                        Permission);
                    if ((bool)(await lastManager.ExecuteScalarAsync(token))!)
                    {
                        return AssignmentRevocationOutcome.LastManagerProtected;
                    }
                }

                await using var command = new NpgsqlCommand("""
                    DELETE FROM platform.authorization_assignments
                    WHERE assignment_id = @assignment_id
                    """, connection, transaction);
                command.Parameters.AddWithValue("assignment_id", NpgsqlDbType.Uuid, assignmentId);
                return await command.ExecuteNonQueryAsync(token) == 1
                    ? AssignmentRevocationOutcome.Revoked
                    : AssignmentRevocationOutcome.Unchanged;
            }, cancellationToken,
            result => result switch
            {
                AssignmentRevocationOutcome.Revoked => "platform.authorization.assignment_revoked",
                AssignmentRevocationOutcome.Unchanged => "platform.authorization.assignment_unchanged",
                _ => "platform.authorization.assignment_revocation_blocked"
            });
        if (outcome == AssignmentRevocationOutcome.LastManagerProtected)
        {
            throw new InvalidOperationException(
                "The last global authorization administrator cannot be revoked.");
        }

        return outcome == AssignmentRevocationOutcome.Revoked;
    }

    public ValueTask<bool> RetireRoleAsync(
        ActorReference actor,
        Guid roleId,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default) =>
        RetireUnusedAsync(actor, roleId, AuthorizationObject.Role, correlationId, cancellationToken);

    public ValueTask<bool> RetireScopeAsync(
        ActorReference actor,
        Guid scopeId,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default) =>
        RetireUnusedAsync(actor, scopeId, AuthorizationObject.Scope, correlationId, cancellationToken);

    private async ValueTask<bool> RetireUnusedAsync(
        ActorReference actor,
        Guid id,
        AuthorizationObject kind,
        CorrelationId correlationId,
        CancellationToken cancellationToken)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Authorization object ID is invalid.", nameof(id));
        }

        var isRole = kind == AuthorizationObject.Role;
        var noun = isRole ? "role" : "scope";
        var outcome = await ExecuteAuthorizedAsync(actor,
            $"platform.authorization.{noun}_retired",
            new AuditTarget(noun, id.ToString("D")), correlationId, null,
            async (connection, transaction, token) =>
            {
                var deleteSql = isRole ? """
                    DELETE FROM platform.authorization_roles AS object
                    WHERE object.role_id = @id
                      AND NOT EXISTS (
                          SELECT 1 FROM platform.authorization_assignments AS assignment
                          WHERE assignment.role_id = object.role_id)
                    """ : """
                    DELETE FROM platform.authorization_scopes AS object
                    WHERE object.scope_id = @id
                      AND NOT EXISTS (
                          SELECT 1 FROM platform.authorization_assignments AS assignment
                          WHERE assignment.scope_id = object.scope_id)
                      AND NOT EXISTS (
                          SELECT 1 FROM platform.authorization_scopes AS child
                          WHERE child.parent_scope_id = object.scope_id)
                    """;
                await using (var command = new NpgsqlCommand(deleteSql, connection, transaction))
                {
                    command.Parameters.AddWithValue("id", NpgsqlDbType.Uuid, id);
                    if (await command.ExecuteNonQueryAsync(token) == 1)
                    {
                        return RetirementOutcome.Retired;
                    }
                }

                var existsSql = isRole ?
                    "SELECT EXISTS (SELECT 1 FROM platform.authorization_roles WHERE role_id = @id)" :
                    "SELECT EXISTS (SELECT 1 FROM platform.authorization_scopes WHERE scope_id = @id)";
                await using var exists = new NpgsqlCommand(existsSql, connection, transaction);
                exists.Parameters.AddWithValue("id", NpgsqlDbType.Uuid, id);
                return (bool)(await exists.ExecuteScalarAsync(token))!
                    ? RetirementOutcome.InUse : RetirementOutcome.Missing;
            }, cancellationToken,
            result => result switch
            {
                RetirementOutcome.Retired => $"platform.authorization.{noun}_retired",
                RetirementOutcome.InUse => $"platform.authorization.{noun}_retirement_blocked",
                _ => $"platform.authorization.{noun}_unchanged"
            });
        if (outcome == RetirementOutcome.InUse)
        {
            throw new InvalidOperationException("Authorization object is still in use.");
        }

        return outcome == RetirementOutcome.Retired;
    }

    private async ValueTask<T> ExecuteAuthorizedAsync<T>(
        ActorReference actor,
        string action,
        AuditTarget target,
        CorrelationId correlationId,
        IReadOnlyDictionary<string, string>? context,
        Func<NpgsqlConnection, NpgsqlTransaction, CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken,
        Func<T, string>? actionForResult = null)
    {
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        var decision = await PostgreSqlAuthorizationService.AuthorizeInTransactionAsync(
            new AuthorizationRequest(actor, Permission), connection, transaction, cancellationToken);
        if (!decision.IsAllowed)
        {
            await audit.WriteInTransactionAsync(new AuditRecord(
                actor, "platform.authorization.manage_denied", target,
                correlationId, clock.UtcNow, context), connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            throw new UnauthorizedAccessException("Authorization administration is not permitted.");
        }

        var result = await operation(connection, transaction, cancellationToken);
        await audit.WriteInTransactionAsync(new AuditRecord(
            actor, actionForResult?.Invoke(result) ?? action, target,
            correlationId, clock.UtcNow, context),
            connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private static async Task InsertRoleAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid roleId,
        string name,
        IReadOnlyCollection<string> permissions,
        CancellationToken cancellationToken)
    {
        await using (var role = new NpgsqlCommand("""
            INSERT INTO platform.authorization_roles (role_id, name)
            VALUES (@role_id, @name)
            """, connection, transaction))
        {
            role.Parameters.AddWithValue("role_id", NpgsqlDbType.Uuid, roleId);
            role.Parameters.AddWithValue("name", NpgsqlDbType.Varchar, name);
            await role.ExecuteNonQueryAsync(cancellationToken);
        }

        foreach (var permission in permissions)
        {
            await using var grant = new NpgsqlCommand("""
                INSERT INTO platform.authorization_role_permissions (role_id, permission)
                VALUES (@role_id, @permission)
                """, connection, transaction);
            grant.Parameters.AddWithValue("role_id", NpgsqlDbType.Uuid, roleId);
            grant.Parameters.AddWithValue("permission", NpgsqlDbType.Varchar, permission);
            await grant.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static void ValidateRole(string name, IReadOnlyCollection<string> permissions)
    {
        ValidateName(name);
        if (permissions is null || permissions.Count is < 1 or > 32 ||
            permissions.Any(permission => !PostgreSqlAuthorizationService.IsValidPermission(permission)) ||
            permissions.Count != permissions.Distinct(StringComparer.Ordinal).Count())
        {
            throw new ArgumentException("Role permissions are invalid.", nameof(permissions));
        }
    }

    private static void ValidateName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 128 || name != name.Trim())
        {
            throw new ArgumentException("Authorization name is invalid.", nameof(name));
        }
    }

    private enum AssignmentRevocationOutcome
    {
        Revoked,
        Unchanged,
        LastManagerProtected
    }

    private enum AuthorizationObject { Role, Scope }

    private enum RetirementOutcome { Retired, InUse, Missing }

    private enum RoleReplacementOutcome { Replaced, Missing, LastManagerProtected }
}
