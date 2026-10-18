using Fleetory.Core.Contracts;
using Fleetory.ModuleAbstractions;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.AspNetCore.Http;

namespace Fleetory.Core.Security;

internal static class AgentEnrollmentEndpoints
{
    private const long MaximumBodyBytes = 1024;

    public static async Task<IResult> CreateGrantAsync(
        HttpContext context,
        Guid deviceId,
        AgentEnrollmentService service)
    {
        var certificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
        if (certificate is null ||
            !AdminCertificateIdentity.TryReadActor(certificate, out var actor) ||
            actor is null)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var request = await BoundedJsonRequestReader.ReadAsync<CreateGrantRequest>(
            context, MaximumBodyBytes);
        if (request is null)
        {
            return Results.BadRequest();
        }

        try
        {
            var token = await service.CreateGrantAsync(
                actor, new DeviceId(deviceId), request.DisplayName,
                new CorrelationId(context.TraceIdentifier), context.RequestAborted,
                request.ExpectedCertificateSha256);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Json(new GrantResponse(token));
        }
        catch (ArgumentException)
        {
            return Results.BadRequest();
        }
        catch (UnauthorizedAccessException)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
        catch (AgentEnrollmentConflictException)
        {
            return Results.Conflict();
        }
    }

    public static async Task<IResult> EnrollAsync(
        HttpContext context,
        AgentEnrollmentService service)
    {
        var certificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
        if (certificate is null ||
            !AgentCertificateIdentity.TryReadDeviceId(certificate, out var deviceId))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var request = await BoundedJsonRequestReader.ReadAsync<EnrollRequest>(
            context, MaximumBodyBytes);
        if (request is null)
        {
            return Results.BadRequest();
        }

        try
        {
            await service.EnrollAsync(deviceId, certificate, request.Token,
                new CorrelationId(context.TraceIdentifier), context.RequestAborted);
            return Results.NoContent();
        }
        catch (UnauthorizedAccessException)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
    }

    private sealed record CreateGrantRequest(string DisplayName, string? ExpectedCertificateSha256 = null);
    private sealed record EnrollRequest(string Token);
    private sealed record GrantResponse(string Token);
}
