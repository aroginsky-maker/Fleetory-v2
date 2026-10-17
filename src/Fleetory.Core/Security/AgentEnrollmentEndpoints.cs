using System.Text.Json;
using Fleetory.Core.Contracts;
using Fleetory.SharedKernel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

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

        var request = await ReadRequestAsync<CreateGrantRequest>(context);
        if (request is null)
        {
            return Results.BadRequest();
        }

        try
        {
            var token = await service.CreateGrantAsync(
                actor, new DeviceId(deviceId), request.DisplayName,
                new CorrelationId(context.TraceIdentifier), context.RequestAborted);
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

        var request = await ReadRequestAsync<EnrollRequest>(context);
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

    private static async Task<T?> ReadRequestAsync<T>(HttpContext context)
    {
        if (context.Request.ContentLength is > MaximumBodyBytes)
        {
            return default;
        }

        var sizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (sizeFeature is { IsReadOnly: false })
        {
            sizeFeature.MaxRequestBodySize = MaximumBodyBytes;
        }

        try
        {
            return await context.Request.ReadFromJsonAsync<T>(context.RequestAborted);
        }
        catch (Exception exception) when (exception is JsonException or BadHttpRequestException or InvalidOperationException)
        {
            return default;
        }
    }

    private sealed record CreateGrantRequest(string DisplayName);
    private sealed record EnrollRequest(string Token);
    private sealed record GrantResponse(string Token);
}
