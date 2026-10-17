using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.EntityFrameworkCore;

namespace Fleetory.Core.Security;

public sealed class AgentEnrollmentService(
    IAuthorizationService authorization,
    IAuditWriter audit,
    IAgentCertificateBindingVerifier verifier,
    CoreDbContext database,
    IClock clock)
{
    public const string Permission = "core.agent_certificate.enroll";
    private static readonly TimeSpan GrantLifetime = TimeSpan.FromMinutes(5);

    public async ValueTask<string> CreateGrantAsync(
        ActorReference actor,
        DeviceId deviceId,
        string displayName,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (deviceId.Value == Guid.Empty || string.IsNullOrWhiteSpace(displayName) ||
            displayName.Length > 256)
        {
            throw new ArgumentException("Agent enrollment target is invalid.");
        }

        var decision = await authorization.AuthorizeAsync(
            new AuthorizationRequest(actor, Permission), cancellationToken);
        var now = clock.UtcNow.ToUniversalTime();
        await WriteAuditAsync(actor,
            decision.IsAllowed ? "core.agent_enrollment.grant_requested" :
                "core.agent_enrollment.grant_denied",
            deviceId, correlationId, now, cancellationToken);
        if (!decision.IsAllowed)
        {
            throw new UnauthorizedAccessException("Agent enrollment grant is not authorized.");
        }

        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var tokenHash = HashToken(token);
        await using (var transaction = await database.Database.BeginTransactionAsync(cancellationToken))
        {
            await database.AgentEnrollmentGrants
                .Where(row => row.ExpiresAt <= now)
                .ExecuteDeleteAsync(cancellationToken);
            await database.Database.ExecuteSqlInterpolatedAsync(
                $"""
                    INSERT INTO core.devices (device_id, display_name, updated_at, revision)
                    VALUES ({deviceId.Value}, {displayName}, {now}, 1)
                    ON CONFLICT (device_id) DO NOTHING
                    """, cancellationToken);
            database.AgentEnrollmentGrants.Add(AgentEnrollmentGrantRecord.Create(
                tokenHash, deviceId, now.Add(GrantLifetime)));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        await WriteAuditAsync(actor, "core.agent_enrollment.grant_created",
            deviceId, correlationId, clock.UtcNow, cancellationToken);
        return token;
    }

    public async ValueTask EnrollAsync(
        DeviceId deviceId,
        X509Certificate2 certificate,
        string token,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var actor = new ActorReference($"device:{deviceId.Value:N}", ActorKind.Service);
        var now = clock.UtcNow.ToUniversalTime();
        var status = await verifier.VerifyAsync(deviceId, certificate, cancellationToken);
        if (!AgentCertificateIdentity.TryReadDeviceId(certificate, out var certificateDeviceId) ||
            certificateDeviceId != deviceId ||
            !IsToken(token) || status is not (AgentCertificateStatus.UnknownCertificate or
            AgentCertificateStatus.Accepted))
        {
            await WriteAuditAsync(actor, "core.agent_enrollment.denied",
                deviceId, correlationId, now, cancellationToken);
            throw new UnauthorizedAccessException("Agent enrollment is denied.");
        }

        var tokenHash = HashToken(token);
        var grantExists = await database.AgentEnrollmentGrants.AsNoTracking().AnyAsync(
            row => row.TokenSha256 == tokenHash && row.DeviceId == deviceId &&
                row.ConsumedAt == null && row.ExpiresAt > now, cancellationToken);
        if (!grantExists)
        {
            await WriteAuditAsync(actor, "core.agent_enrollment.denied",
                deviceId, correlationId, now, cancellationToken);
            throw new UnauthorizedAccessException("Agent enrollment is denied.");
        }

        await WriteAuditAsync(actor, "core.agent_enrollment.requested",
            deviceId, correlationId, now, cancellationToken);
        await using (var transaction = await database.Database.BeginTransactionAsync(cancellationToken))
        {
            var consumed = await database.AgentEnrollmentGrants
                .Where(row => row.TokenSha256 == tokenHash && row.DeviceId == deviceId &&
                    row.ConsumedAt == null && row.ExpiresAt > now)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(row => row.ConsumedAt, now), cancellationToken);
            if (consumed != 1)
            {
                throw new UnauthorizedAccessException("Agent enrollment is denied.");
            }

            if (status == AgentCertificateStatus.UnknownCertificate)
            {
                database.AgentCertificates.Add(AgentCertificateRecord.Create(
                    deviceId,
                    Convert.ToHexString(SHA256.HashData(certificate.RawData)),
                    certificate.NotBefore.ToUniversalTime(),
                    certificate.NotAfter.ToUniversalTime()));
                await database.SaveChangesAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }

        await WriteAuditAsync(actor, "core.agent_enrollment.completed",
            deviceId, correlationId, clock.UtcNow, cancellationToken);
    }

    private async ValueTask WriteAuditAsync(
        ActorReference actor,
        string action,
        DeviceId deviceId,
        CorrelationId correlationId,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken) =>
        await audit.WriteAsync(new AuditRecord(
            actor, action,
            new AuditTarget("device", deviceId.Value.ToString("D")),
            correlationId, occurredAt), cancellationToken);

    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token)));

    private static bool IsToken(string? token) =>
        token is { Length: 64 } &&
        token.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
}
