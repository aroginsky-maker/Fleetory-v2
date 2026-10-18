using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Fleetory.Core.Security;

public sealed class AgentEnrollmentService(
    IAuthorizationService authorization,
    IAuditWriter audit,
    IAgentCertificateBindingVerifier verifier,
    CoreDbContext database,
    IClock clock)
{
    public const string Permission = "core.agent_certificate.enroll";
    public const string RotationPermission = "core.agent_certificate.rotate";
    private static readonly TimeSpan GrantLifetime = TimeSpan.FromMinutes(5);

    public async ValueTask<Guid> CreateRotationIntentAsync(
        DeviceId deviceId,
        X509Certificate2 currentCertificate,
        string replacementCertificateSha256,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentCertificate);
        if (deviceId.Value == Guid.Empty ||
            !AgentCertificateFingerprint.IsValid(replacementCertificateSha256))
        {
            throw new ArgumentException("Agent rotation target is invalid.");
        }

        var actor = new ActorReference($"device:{deviceId.Value:N}", ActorKind.Service);
        var currentFingerprint = CertificateFingerprint(currentCertificate);
        var now = clock.UtcNow.ToUniversalTime();
        if (currentFingerprint == replacementCertificateSha256 ||
            !AgentCertificateIdentity.TryReadDeviceId(currentCertificate, out var certificateDeviceId) ||
            certificateDeviceId != deviceId ||
            await verifier.VerifyAsync(deviceId, currentCertificate, cancellationToken) !=
                AgentCertificateStatus.Accepted)
        {
            await WriteAuditAsync(actor, "core.agent_enrollment.rotation_intent_denied",
                deviceId, correlationId, now, cancellationToken);
            throw new UnauthorizedAccessException("Agent rotation intent is denied.");
        }

        await WriteAuditAsync(actor, "core.agent_enrollment.rotation_intent_requested",
            deviceId, correlationId, now, cancellationToken);
        var intentId = Guid.NewGuid();
        await using (var transaction = await database.Database.BeginTransactionAsync(cancellationToken))
        {
            await LockDeviceAsync(deviceId, cancellationToken);
            if (!await ActiveBindingExistsAsync(deviceId, currentFingerprint, now, cancellationToken))
            {
                await WriteAuditInTransactionAsync(actor,
                    "core.agent_enrollment.rotation_intent_denied", deviceId,
                    correlationId, clock.UtcNow, transaction, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                throw new UnauthorizedAccessException("Agent rotation intent is denied.");
            }

            await database.AgentRotationIntents
                .Where(row => row.DeviceId == deviceId || row.ExpiresAt <= now)
                .ExecuteDeleteAsync(cancellationToken);
            database.AgentRotationIntents.Add(AgentRotationIntentRecord.Create(
                intentId, deviceId, currentFingerprint, replacementCertificateSha256,
                now.Add(GrantLifetime)));
            await database.SaveChangesAsync(cancellationToken);
            await WriteAuditInTransactionAsync(actor,
                "core.agent_enrollment.rotation_intent_created", deviceId,
                correlationId, clock.UtcNow, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        return intentId;
    }

    public async ValueTask<string> CreateGrantAsync(
        ActorReference actor,
        DeviceId deviceId,
        string displayName,
        CorrelationId correlationId,
        CancellationToken cancellationToken = default,
        string? expectedCertificateSha256 = null,
        Guid? rotationIntentId = null,
        string? initialCertificateSha256 = null)
    {
        if (deviceId.Value == Guid.Empty || string.IsNullOrWhiteSpace(displayName) ||
            displayName.Length > 256 ||
            expectedCertificateSha256 is not null &&
            !AgentCertificateFingerprint.IsValid(expectedCertificateSha256) ||
            expectedCertificateSha256 is null &&
            (rotationIntentId is not null ||
                !AgentCertificateFingerprint.IsValid(initialCertificateSha256)) ||
            expectedCertificateSha256 is not null && initialCertificateSha256 is not null)
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

        var token = AgentEnrollmentToken.Create();
        var tokenHash = AgentEnrollmentToken.Hash(token);
        try
        {
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
                await LockDeviceAsync(deviceId, cancellationToken);
                if (!await MatchesExpectedBindingAsync(
                        deviceId, expectedCertificateSha256, cancellationToken))
                {
                    throw new AgentEnrollmentConflictException();
                }

                if (expectedCertificateSha256 is not null &&
                    !(await authorization.AuthorizeAsync(
                        new AuthorizationRequest(actor, RotationPermission), cancellationToken)).IsAllowed)
                {
                    throw new UnauthorizedAccessException(
                        "Agent certificate rotation is not authorized.");
                }

                var replacementCertificateSha256 = initialCertificateSha256;
                if (expectedCertificateSha256 is not null)
                {
                    var intent = rotationIntentId is null ? null :
                        await database.AgentRotationIntents.AsNoTracking().SingleOrDefaultAsync(
                            row => row.IntentId == rotationIntentId.Value &&
                                row.DeviceId == deviceId && row.ClaimedAt == null &&
                                row.ExpiresAt > now &&
                                row.CurrentCertificateSha256 == expectedCertificateSha256,
                            cancellationToken);
                    if (intent is null ||
                        !await ActiveBindingExistsAsync(
                            deviceId, expectedCertificateSha256, now, cancellationToken))
                    {
                        throw new AgentRotationIntentException();
                    }

                    var claimed = await database.AgentRotationIntents
                        .Where(row => row.IntentId == intent.IntentId &&
                            row.ClaimedAt == null && row.ExpiresAt > now)
                        .ExecuteUpdateAsync(setters => setters
                            .SetProperty(row => row.ClaimedAt, now), cancellationToken);
                    if (claimed != 1)
                    {
                        throw new AgentRotationIntentException();
                    }

                    replacementCertificateSha256 = intent.ReplacementCertificateSha256;
                }

                database.AgentEnrollmentGrants.Add(AgentEnrollmentGrantRecord.Create(
                    tokenHash, deviceId, now.Add(GrantLifetime),
                    expectedCertificateSha256, replacementCertificateSha256));
                await database.SaveChangesAsync(cancellationToken);
                await WriteAuditInTransactionAsync(actor, "core.agent_enrollment.grant_created",
                    deviceId, correlationId, clock.UtcNow, transaction, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
        }
        catch (AgentEnrollmentConflictException)
        {
            await WriteAuditAsync(actor, "core.agent_enrollment.grant_collision",
                deviceId, correlationId, clock.UtcNow, cancellationToken);
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            await WriteAuditAsync(actor, "core.agent_enrollment.grant_rotation_denied",
                deviceId, correlationId, clock.UtcNow, cancellationToken);
            throw;
        }
        catch (AgentRotationIntentException)
        {
            await WriteAuditAsync(actor, "core.agent_enrollment.grant_rotation_intent_denied",
                deviceId, correlationId, clock.UtcNow, cancellationToken);
            throw;
        }

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

        var tokenHash = AgentEnrollmentToken.Hash(token);
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
            await LockDeviceAsync(deviceId, cancellationToken);
            var grant = await database.AgentEnrollmentGrants.AsNoTracking().SingleOrDefaultAsync(
                row => row.TokenSha256 == tokenHash && row.DeviceId == deviceId &&
                    row.ConsumedAt == null && row.ExpiresAt > now, cancellationToken);
            if (grant is null)
            {
                throw new UnauthorizedAccessException("Agent enrollment is denied.");
            }

            var bindingMatches = grant.RecoveryRequestId is null
                ? await MatchesExpectedBindingAsync(
                    deviceId, grant.ExpectedCertificateSha256, cancellationToken)
                : await MatchesRecoveryBindingAsync(deviceId,
                    grant.ExpectedCertificateSha256!, cancellationToken);
            if (!bindingMatches)
            {
                await WriteAuditInTransactionAsync(actor, "core.agent_enrollment.denied_collision",
                    deviceId, correlationId, clock.UtcNow, transaction, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                throw new UnauthorizedAccessException("Agent enrollment is denied.");
            }

            if (grant.ReplacementCertificateSha256 != CertificateFingerprint(certificate))
            {
                await WriteAuditInTransactionAsync(actor,
                    "core.agent_enrollment.denied_replacement_mismatch", deviceId,
                    correlationId, clock.UtcNow, transaction, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                throw new UnauthorizedAccessException("Agent enrollment is denied.");
            }

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

            await WriteAuditInTransactionAsync(actor, "core.agent_enrollment.completed",
                deviceId, correlationId, clock.UtcNow, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
    }

    private ValueTask WriteAuditAsync(
        ActorReference actor,
        string action,
        DeviceId deviceId,
        CorrelationId correlationId,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken) =>
        audit.WriteAsync(CreateAuditRecord(actor, action, deviceId, correlationId, occurredAt),
            cancellationToken);

    private ValueTask WriteAuditInTransactionAsync(
        ActorReference actor,
        string action,
        DeviceId deviceId,
        CorrelationId correlationId,
        DateTimeOffset occurredAt,
        IDbContextTransaction transaction,
        CancellationToken cancellationToken) =>
        audit.WriteInTransactionAsync(CreateAuditRecord(actor, action, deviceId, correlationId, occurredAt),
            transaction.GetDbTransaction(), cancellationToken);

    private static AuditRecord CreateAuditRecord(
        ActorReference actor,
        string action,
        DeviceId deviceId,
        CorrelationId correlationId,
        DateTimeOffset occurredAt) =>
        new(
            actor, action,
            new AuditTarget("device", deviceId.Value.ToString("D")),
            correlationId, occurredAt);

    private static string CertificateFingerprint(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData));

    private async ValueTask<bool> MatchesRecoveryBindingAsync(
        DeviceId deviceId, string expectedCertificateSha256,
        CancellationToken cancellationToken) =>
        await database.AgentCertificates.AsNoTracking().AnyAsync(
            row => row.DeviceId == deviceId &&
                row.CertificateSha256 == expectedCertificateSha256 &&
                row.RevokedAt != null, cancellationToken) &&
        !await database.AgentCertificates.AsNoTracking().AnyAsync(
            row => row.DeviceId == deviceId && row.RevokedAt == null,
            cancellationToken);

    private ValueTask<bool> ActiveBindingExistsAsync(DeviceId deviceId,
        string fingerprint, DateTimeOffset now, CancellationToken cancellationToken) =>
        new(database.AgentCertificates.AsNoTracking().AnyAsync(
            row => row.DeviceId == deviceId && row.CertificateSha256 == fingerprint &&
                row.RevokedAt == null && row.NotBefore <= now && row.NotAfter > now,
            cancellationToken));

    private async ValueTask LockDeviceAsync(DeviceId deviceId, CancellationToken cancellationToken)
    {
        if (!await CoreDeviceRowLock.TryLockAsync(database, deviceId, cancellationToken))
        {
            throw new InvalidOperationException("Agent device record disappeared during enrollment.");
        }
    }

    private async ValueTask<bool> MatchesExpectedBindingAsync(
        DeviceId deviceId,
        string? expectedCertificateSha256,
        CancellationToken cancellationToken)
    {
        if (expectedCertificateSha256 is not null)
        {
            return await ActiveBindingExistsAsync(
                deviceId, expectedCertificateSha256, clock.UtcNow.ToUniversalTime(),
                cancellationToken);
        }

        return !await database.AgentCertificates.AsNoTracking().AnyAsync(
            row => row.DeviceId == deviceId, cancellationToken);
    }

    private static bool IsToken(string? token) =>
        token is { Length: 64 } &&
        token.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
}

public sealed class AgentEnrollmentConflictException : Exception
{
    public AgentEnrollmentConflictException()
        : base("Agent identity already has a different certificate binding.")
    {
    }
}

public sealed class AgentRotationIntentException : Exception
{
    public AgentRotationIntentException()
        : base("An active Agent rotation intent is required.")
    {
    }
}
