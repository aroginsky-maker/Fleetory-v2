using Fleetory.Core.Contracts;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.AspNetCore.Http;

namespace Fleetory.Core.Security;

internal static class AdminCertificateEndpoints
{
    public static async Task<IResult> RevokeAsync(
        HttpContext context,
        Guid deviceId,
        string fingerprint,
        AgentCertificateRevocationService service)
    {
        var certificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
        if (certificate is null ||
            !AdminCertificateIdentity.TryReadActor(certificate, out var actor) ||
            actor is null)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        try
        {
            await service.RevokeAsync(
                actor, new DeviceId(deviceId), fingerprint,
                new CorrelationId(context.TraceIdentifier), context.RequestAborted);
            return Results.NoContent();
        }
        catch (ArgumentException)
        {
            return Results.BadRequest();
        }
        catch (UnauthorizedAccessException)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
    }
}
