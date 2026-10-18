using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Fleetory.Core.Security;

/// <summary>
/// Internal administration boundary. A future endpoint must authenticate the actor before calling it.
/// </summary>
public sealed class AgentCertificateRevocationService(
    IAuthorizationService authorization,
    IAuditWriter audit,
    CoreDbContext database,
    IClock clock)
{
    public const string Permission = "core.agent_certificate.revoke";
    private const string AuditAction = "core.agent_certificate.revoke_requested";
    private const string CompletedAction = "core.agent_certificate.revoke_completed";

    public async ValueTask<bool> RevokeAsync(
        ActorReference actor,
        DeviceId deviceId,
        string certificateSha256,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (deviceId.Value == Guid.Empty || !AgentCertificateFingerprint.IsValid(certificateSha256))
        {
            throw new ArgumentException("Agent certificate identity is invalid.");
        }

        var decision = await authorization.AuthorizeAsync(
            new AuthorizationRequest(actor, Permission), cancellationToken);
        var action = decision.IsAllowed
            ? AuditAction
            : "core.agent_certificate.revoke_denied";
        await audit.WriteAsync(new AuditRecord(
            actor,
            action,
            new AuditTarget("agent_certificate", certificateSha256),
            correlationId,
            clock.UtcNow,
            new Dictionary<string, string> { ["device_id"] = deviceId.Value.ToString("D") }),
            cancellationToken);

        if (!decision.IsAllowed)
        {
            throw new UnauthorizedAccessException("Agent certificate revocation is not authorized.");
        }

        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        var changed = await database.AgentCertificates
            .Where(row => row.CertificateSha256 == certificateSha256 &&
                row.DeviceId == deviceId && row.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.RevokedAt, clock.UtcNow.ToUniversalTime()),
                cancellationToken);

        await audit.WriteInTransactionAsync(new AuditRecord(
            actor,
            CompletedAction,
            new AuditTarget("agent_certificate", certificateSha256),
            correlationId,
            clock.UtcNow,
            new Dictionary<string, string>
            {
                ["device_id"] = deviceId.Value.ToString("D"),
                ["outcome"] = changed == 1 ? "revoked" : "unchanged"
            }), transaction.GetDbTransaction(), cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return changed == 1;
    }
}
