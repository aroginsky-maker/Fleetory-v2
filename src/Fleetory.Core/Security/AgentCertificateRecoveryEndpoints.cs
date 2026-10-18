using Fleetory.Core.Contracts;
using Fleetory.ModuleAbstractions;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.AspNetCore.Http;

namespace Fleetory.Core.Security;

internal static class AgentCertificateRecoveryEndpoints
{
    private const long MaximumBodyBytes = 1024;

    public static async Task<IResult> RequestAsync(HttpContext context,
        Guid deviceId, AgentCertificateRecoveryService service)
    {
        var input = await ReadAdminRequestAsync<RecoveryRequest>(context);
        if (input.Error is not null)
        {
            return input.Error;
        }

        return await ExecuteAsync(async () =>
        {
            var recoveryId = await service.RequestAsync(input.Actor!, new DeviceId(deviceId),
                input.Request!.ExpectedCertificateSha256,
                input.Request.ReplacementCertificateSha256, input.Request.EvidenceSha256,
                input.Request.IncidentReference, new CorrelationId(context.TraceIdentifier),
                context.RequestAborted);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Json(new RecoveryResponse(recoveryId));
        });
    }

    public static async Task<IResult> ApproveAsync(HttpContext context,
        Guid deviceId, Guid recoveryId, AgentCertificateRecoveryService service)
    {
        var input = await ReadAdminRequestAsync<ApprovalRequest>(context);
        if (input.Error is not null)
        {
            return input.Error;
        }

        return await ExecuteAsync(async () =>
        {
            var token = await service.ApproveAsync(input.Actor!, new DeviceId(deviceId),
                recoveryId, input.Request!.ReplacementCertificateSha256,
                input.Request.EvidenceSha256, input.Request.IncidentReference,
                new CorrelationId(context.TraceIdentifier), context.RequestAborted);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Json(new GrantResponse(token));
        });
    }

    private static async ValueTask<(ActorReference? Actor, T? Request, IResult? Error)>
        ReadAdminRequestAsync<T>(HttpContext context) where T : class
    {
        var certificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
        if (certificate is null ||
            !AdminCertificateIdentity.TryReadActor(certificate, out var actor) ||
            actor is null)
        {
            return (null, null, Results.StatusCode(StatusCodes.Status403Forbidden));
        }

        var request = await BoundedJsonRequestReader.ReadAsync<T>(
            context, MaximumBodyBytes);
        return request is null ? (null, null, Results.BadRequest()) :
            (actor, request, null);
    }

    private static async Task<IResult> ExecuteAsync(Func<Task<IResult>> operation)
    {
        try
        {
            return await operation();
        }
        catch (ArgumentException)
        {
            return Results.BadRequest();
        }
        catch (UnauthorizedAccessException)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
        catch (AgentRecoveryConflictException)
        {
            return Results.Conflict();
        }
    }

    private sealed record RecoveryRequest(string ExpectedCertificateSha256,
        string ReplacementCertificateSha256, string EvidenceSha256,
        string IncidentReference);
    private sealed record ApprovalRequest(string ReplacementCertificateSha256,
        string EvidenceSha256, string IncidentReference);
    private sealed record RecoveryResponse(Guid RecoveryId);
    private sealed record GrantResponse(string Token);
}
