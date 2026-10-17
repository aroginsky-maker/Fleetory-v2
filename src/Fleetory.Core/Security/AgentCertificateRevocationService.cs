using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.EntityFrameworkCore;

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

    public async ValueTask<bool> RevokeAsync(
        ActorReference actor,
        DeviceId deviceId,
        string certificateSha256,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (deviceId.Value == Guid.Empty || !IsFingerprint(certificateSha256))
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

        // Persist the authorized intent before changing Core state. An unavailable audit store
        // must not permit an unaudited revocation.

        var changed = await database.AgentCertificates
            .Where(row => row.CertificateSha256 == certificateSha256 &&
                row.DeviceId == deviceId && row.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.RevokedAt, clock.UtcNow.ToUniversalTime()),
                cancellationToken);
        return changed == 1;
    }

    private static bool IsFingerprint(string? value) =>
        value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
}
