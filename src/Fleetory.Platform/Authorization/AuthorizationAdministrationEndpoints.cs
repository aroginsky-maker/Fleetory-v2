using Fleetory.ModuleAbstractions;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.AspNetCore.Http;
using Npgsql;

namespace Fleetory.Platform.Authorization;

internal static class AuthorizationAdministrationEndpoints
{
    private const long MaximumBodyBytes = 4096;

    public static async Task<IResult> CreateRoleAsync(
        HttpContext context,
        PostgreSqlAuthorizationAdministration administration)
    {
        var actor = await ReadActorAsync(context);
        if (actor is null) { return Results.StatusCode(StatusCodes.Status403Forbidden); }
        var request = await BoundedJsonRequestReader.ReadAsync<CreateRoleRequest>(
            context, MaximumBodyBytes);
        if (request is null) { return Results.BadRequest(); }

        try
        {
            var roleId = await administration.CreateRoleAsync(actor, request.Name,
                request.Permissions, Correlation(context), context.RequestAborted);
            return Results.Json(new IdResponse(roleId), statusCode: StatusCodes.Status201Created);
        }
        catch (Exception exception) when (exception is ArgumentException or PostgresException
            { SqlState: PostgresErrorCodes.ForeignKeyViolation })
        {
            return Results.BadRequest();
        }
        catch (UnauthorizedAccessException)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
    }

    public static async Task<IResult> CreateScopeAsync(
        HttpContext context,
        PostgreSqlAuthorizationAdministration administration)
    {
        var actor = await ReadActorAsync(context);
        if (actor is null) { return Results.StatusCode(StatusCodes.Status403Forbidden); }
        var request = await BoundedJsonRequestReader.ReadAsync<CreateScopeRequest>(
            context, MaximumBodyBytes);
        if (request is null) { return Results.BadRequest(); }

        try
        {
            var scopeId = await administration.CreateScopeAsync(actor, request.Name,
                request.ParentScopeId is { } parent ? new ScopeId(parent) : null,
                Correlation(context), context.RequestAborted);
            return Results.Json(new IdResponse(scopeId), statusCode: StatusCodes.Status201Created);
        }
        catch (Exception exception) when (exception is ArgumentException or PostgresException
            { SqlState: PostgresErrorCodes.ForeignKeyViolation })
        {
            return Results.BadRequest();
        }
        catch (UnauthorizedAccessException)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
    }

    public static async Task<IResult> AssignRoleAsync(
        HttpContext context,
        Guid roleId,
        PostgreSqlAuthorizationAdministration administration)
    {
        var actor = await ReadActorAsync(context);
        if (actor is null) { return Results.StatusCode(StatusCodes.Status403Forbidden); }
        var request = await BoundedJsonRequestReader.ReadAsync<AssignRoleRequest>(
            context, MaximumBodyBytes);
        if (request is null) { return Results.BadRequest(); }

        try
        {
            var target = new ActorReference(request.SubjectId, request.Kind);
            var assignmentId = await administration.AssignRoleAsync(actor, target, roleId,
                request.ScopeId is { } scope ? new ScopeId(scope) : null,
                Correlation(context), context.RequestAborted);
            return Results.Json(new IdResponse(assignmentId), statusCode: StatusCodes.Status201Created);
        }
        catch (Exception exception) when (exception is ArgumentException or PostgresException
            { SqlState: PostgresErrorCodes.ForeignKeyViolation })
        {
            return Results.BadRequest();
        }
        catch (UnauthorizedAccessException)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
    }

    public static async Task<IResult> RevokeAssignmentAsync(
        HttpContext context,
        Guid assignmentId,
        PostgreSqlAuthorizationAdministration administration)
    {
        var actor = await ReadActorAsync(context);
        if (actor is null) { return Results.StatusCode(StatusCodes.Status403Forbidden); }

        try
        {
            await administration.RevokeAssignmentAsync(actor, assignmentId,
                Correlation(context), context.RequestAborted);
            return Results.NoContent();
        }
        catch (ArgumentException)
        {
            return Results.BadRequest();
        }
        catch (InvalidOperationException)
        {
            return Results.Conflict();
        }
        catch (UnauthorizedAccessException)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
    }

    private static async Task<ActorReference?> ReadActorAsync(HttpContext context)
    {
        var certificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
        return certificate is not null &&
            AdminCertificateIdentity.TryReadActor(certificate, out var actor) ? actor : null;
    }

    private static CorrelationId Correlation(HttpContext context) =>
        new(context.TraceIdentifier);

    private sealed record CreateRoleRequest(string Name, string[] Permissions);
    private sealed record CreateScopeRequest(string Name, Guid? ParentScopeId);
    private sealed record AssignRoleRequest(string SubjectId, ActorKind Kind, Guid? ScopeId);
    private sealed record IdResponse(Guid Id);
}
