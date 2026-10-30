using System.Security.Cryptography.X509Certificates;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Server.Infrastructure;

/// <summary>Rechecks the Admin leaf for each request, including reused TLS connections.</summary>
public static class AdminCertificateRequestGuard
{
    public static async Task<bool> CheckAsync(HttpContext context, X509Certificate2 certificate,
        ActorReference actor, string fingerprint)
    {
        context.RequestAborted.ThrowIfCancellationRequested();
        var now = context.RequestServices.GetRequiredService<IClock>().UtcNow;
        if (CertificateValidity.IsCurrent(certificate, now)) { return true; }

        await context.RequestServices.GetRequiredService<IAuditWriter>()
            .WriteAsync(new AuditRecord(actor, "admin.certificate.validity_denied",
                new AuditTarget("admin_certificate", fingerprint),
                new CorrelationId(context.TraceIdentifier), now), context.RequestAborted);
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return false;
    }
}
