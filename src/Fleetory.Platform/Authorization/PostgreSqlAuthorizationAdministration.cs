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
        ValidateName(name);
        if (permissions is null || permissions.Count is < 1 or > 32 ||
            permissions.Any(permission => !PostgreSqlAuthorizationService.IsValidPermission(permission)) ||
            permissions.Count != permissions.Distinct(StringComparer.Ordinal).Count())
        {
            throw new ArgumentException("Role permissions are invalid.", nameof(permissions));
        }

        var roleId = Guid.CreateVersion7();
        return ExecuteAuthorizedAsync(actor, "platform.authorization.role_created",
            new AuditTarget("role", roleId.ToString("D")), correlationId,
            new Dictionary<string, string>
            {
                ["name"] = name,
                ["permission_count"] = permissions.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)
            },
            async (connection, transaction, token) =>
            {
                await using (var role = new NpgsqlCommand("""
                    INSERT INTO platform.authorization_roles (role_id, name)
                    VALUES (@role_id, @name)
                    """, connection, transaction))
                {
                    role.Parameters.AddWithValue("role_id", NpgsqlDbType.Uuid, roleId);
                    role.Parameters.AddWithValue("name", NpgsqlDbType.Varchar, name);
                    await role.ExecuteNonQueryAsync(token);
                }

                foreach (var permission in permissions)
                {
                    await using var grant = new NpgsqlCommand("""
                        INSERT INTO platform.authorization_role_permissions (role_id, permission)
                        VALUES (@role_id, @permission)
                        """, connection, transaction);
                    grant.Parameters.AddWithValue("role_id", NpgsqlDbType.Uuid, roleId);
                    grant.Parameters.AddWithValue("permission", NpgsqlDbType.Varchar, permission);
                    await grant.ExecuteNonQueryAsync(token);
                }

                return roleId;
            }, cancellationToken);
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

    public ValueTask<bool> RevokeAssignmentAsync(
        ActorReference actor,
        Guid assignmentId,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (assignmentId == Guid.Empty)
        {
            throw new ArgumentException("Assignment is invalid.", nameof(assignmentId));
        }

        return ExecuteAuthorizedAsync(actor, "platform.authorization.assignment_revoked",
            new AuditTarget("assignment", assignmentId.ToString("D")), correlationId,
            null,
            async (connection, transaction, token) =>
            {
                await using var command = new NpgsqlCommand("""
                    DELETE FROM platform.authorization_assignments
                    WHERE assignment_id = @assignment_id
                    """, connection, transaction);
                command.Parameters.AddWithValue("assignment_id", NpgsqlDbType.Uuid, assignmentId);
                return await command.ExecuteNonQueryAsync(token) == 1;
            }, cancellationToken);
    }

    private async ValueTask<T> ExecuteAuthorizedAsync<T>(
        ActorReference actor,
        string action,
        AuditTarget target,
        CorrelationId correlationId,
        IReadOnlyDictionary<string, string>? context,
        Func<NpgsqlConnection, NpgsqlTransaction, CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
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
            actor, action, target, correlationId, clock.UtcNow, context),
            connection, transaction, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private static void ValidateName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 128 || name != name.Trim())
        {
            throw new ArgumentException("Authorization name is invalid.", nameof(name));
        }
    }
}
