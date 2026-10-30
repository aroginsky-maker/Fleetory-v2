using System.Security.Cryptography.X509Certificates;
using Fleetory.Platform.Authorization;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Server.Infrastructure;

/// <summary>Rechecks the Admin leaf and captured registration deadline before request dispatch.</summary>
public static class AdminCertificateRequestGuard
{
    public static async Task<bool> CheckAsync(HttpContext context, X509Certificate2 certificate,
        ActorReference actor, string fingerprint, AdminCertificateAccessResult? registration = null)
    {
        context.RequestAborted.ThrowIfCancellationRequested();
        var now = context.RequestServices.GetRequiredService<IClock>().UtcNow;
        var action = !CertificateValidity.IsCurrent(certificate, now)
            ? "admin.certificate.validity_denied"
            : registration?.GetStatusAt(now) switch
            {
                null or AdminCertificateAccess.Accepted => null,
                AdminCertificateAccess.Revoked => "admin.certificate.revoked_denied",
                _ => "admin.certificate.unregistered_denied"
            };
        if (action is null) { return true; }

        await context.RequestServices.GetRequiredService<IAuditWriter>()
            .WriteAsync(new AuditRecord(actor, action,
                new AuditTarget("admin_certificate", fingerprint),
                new CorrelationId(context.TraceIdentifier), now), context.RequestAborted);
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return false;
    }
}
