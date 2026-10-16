using Fleetory.Platform.Contracts;
using Fleetory.Platform.Persistence;
using Npgsql;
using NpgsqlTypes;

namespace Fleetory.Platform.Authorization;

/// <summary>Evaluates Fleetory-owned grants without consulting an external identity provider.</summary>
internal sealed class PostgreSqlAuthorizationService(
    PostgreSqlConnectionSettings settings) : IAuthorizationService
{
    private const string InvalidRequest = "Invalid authorization request.";
    private const string PermissionNotGranted = "Permission not granted.";

    private const string Query = """
        WITH RECURSIVE ancestors(scope_id, parent_scope_id, path) AS (
            SELECT scope_id, parent_scope_id, ARRAY[scope_id]
            FROM platform.authorization_scopes
            WHERE scope_id = @requested_scope
            UNION ALL
            SELECT parent.scope_id, parent.parent_scope_id, ancestor.path || parent.scope_id
            FROM platform.authorization_scopes AS parent
            JOIN ancestors AS ancestor ON parent.scope_id = ancestor.parent_scope_id
            WHERE NOT parent.scope_id = ANY(ancestor.path)
        )
        SELECT EXISTS (
            SELECT 1
            FROM platform.authorization_assignments AS assignment
            JOIN platform.authorization_role_permissions AS role_permission
              ON role_permission.role_id = assignment.role_id
            WHERE assignment.actor_subject_id = @actor_subject_id
              AND assignment.actor_kind = @actor_kind
              AND role_permission.permission = @permission
              AND (
                    (@requested_scope IS NULL AND assignment.scope_id IS NULL)
                    OR
                    (@requested_scope IS NOT NULL
                     AND EXISTS (SELECT 1 FROM ancestors)
                     AND (assignment.scope_id IS NULL
                          OR assignment.scope_id IN (SELECT scope_id FROM ancestors)))
                  )
        )
        """;

    public async ValueTask<AuthorizationDecision> AuthorizeAsync(
        AuthorizationRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request is null || request.Actor is null ||
            request.Actor.Kind is ActorKind.Anonymous ||
            !Enum.IsDefined(request.Actor.Kind) ||
            string.IsNullOrWhiteSpace(request.Actor.SubjectId) ||
            request.Actor.SubjectId.Length > 128 ||
            !IsValidPermission(request.Permission) ||
            request.ScopeId?.Value == Guid.Empty)
        {
            return AuthorizationDecision.Deny(InvalidRequest);
        }

        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(Query, connection);
        command.Parameters.AddWithValue("requested_scope", NpgsqlDbType.Uuid,
            (object?)request.ScopeId?.Value ?? DBNull.Value);
        command.Parameters.AddWithValue("actor_subject_id", NpgsqlDbType.Varchar,
            request.Actor.SubjectId);
        command.Parameters.AddWithValue("actor_kind", NpgsqlDbType.Integer,
            (int)request.Actor.Kind);
        command.Parameters.AddWithValue("permission", NpgsqlDbType.Varchar,
            request.Permission);

        var allowed = (bool?)await command.ExecuteScalarAsync(cancellationToken) == true;
        return allowed ? AuthorizationDecision.Allow() : AuthorizationDecision.Deny(PermissionNotGranted);
    }

    private static bool IsValidPermission(string? permission)
    {
        if (string.IsNullOrWhiteSpace(permission) || permission.Length > 128 ||
            permission[0] == '.' || permission[^1] == '.')
        {
            return false;
        }

        var hasSeparator = false;
        var previousWasSeparator = false;
        foreach (var character in permission)
        {
            if (character == '.')
            {
                if (previousWasSeparator)
                {
                    return false;
                }

                hasSeparator = true;
                previousWasSeparator = true;
                continue;
            }

            if (!char.IsAsciiLetterOrDigit(character) && character != '_')
            {
                return false;
            }

            previousWasSeparator = false;
        }

        return hasSeparator;
    }
}
