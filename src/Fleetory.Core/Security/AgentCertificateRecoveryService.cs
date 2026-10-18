using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Fleetory.Core.Security;

public sealed class AgentCertificateRecoveryService(
    IAuthorizationService authorization,
    IAuditWriter audit,
    CoreDbContext database,
    IClock clock)
{
    public const string RequestPermission = "core.agent_certificate.recover.request";
    public const string ApprovePermission = "core.agent_certificate.recover.approve";
    private static readonly TimeSpan RequestLifetime = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan GrantLifetime = TimeSpan.FromMinutes(5);

    public async ValueTask<Guid> RequestAsync(
        ActorReference actor, DeviceId deviceId, string expectedCertificateSha256,
        string replacementCertificateSha256, string evidenceSha256,
        string incidentReference, CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        ValidateRequest(deviceId, expectedCertificateSha256,
            replacementCertificateSha256, evidenceSha256, incidentReference);
        var allowed = actor.Kind == ActorKind.Person &&
            (await authorization.AuthorizeAsync(
                new AuthorizationRequest(actor, RequestPermission), cancellationToken)).IsAllowed;
        await WriteAuditAsync(actor, allowed ? "recovery_requested" : "recovery_denied",
            deviceId, correlationId, evidenceSha256, incidentReference,
            clock.UtcNow, cancellationToken);
        if (!allowed)
        {
            throw new UnauthorizedAccessException("Agent certificate recovery is not authorized.");
        }

        var now = clock.UtcNow.ToUniversalTime();
        var recoveryId = Guid.NewGuid();
        try
        {
            await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
            if (!await CoreDeviceRowLock.TryLockAsync(database, deviceId, cancellationToken) ||
                !await BindingExistsAsync(deviceId, expectedCertificateSha256, cancellationToken) ||
                await database.AgentCertificates.AsNoTracking().AnyAsync(
                    row => row.CertificateSha256 == replacementCertificateSha256,
                    cancellationToken) ||
                await database.AgentCertificateRecoveries.AsNoTracking().AnyAsync(
                    row => row.DeviceId == deviceId && row.ApprovedAt == null &&
                        row.ExpiresAt > now, cancellationToken) ||
                await ActiveRecoveryGrantExistsAsync(deviceId, now, cancellationToken))
            {
                throw new AgentRecoveryConflictException();
            }

            database.AgentCertificateRecoveries.Add(AgentCertificateRecoveryRecord.Create(
                recoveryId, deviceId, actor.SubjectId, expectedCertificateSha256,
                replacementCertificateSha256, evidenceSha256, incidentReference,
                now.Add(RequestLifetime)));
            await database.SaveChangesAsync(cancellationToken);
            await WriteAuditInTransactionAsync(actor, "recovery_created", deviceId,
                correlationId, evidenceSha256, incidentReference, clock.UtcNow,
                transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (AgentRecoveryConflictException)
        {
            await WriteAuditAsync(actor, "recovery_conflict", deviceId, correlationId,
                evidenceSha256, incidentReference, clock.UtcNow, cancellationToken);
            throw;
        }

        return recoveryId;
    }

    public async ValueTask<string> ApproveAsync(
        ActorReference actor, DeviceId deviceId, Guid recoveryId,
        string replacementCertificateSha256, string evidenceSha256,
        string incidentReference, CorrelationId correlationId,
        CancellationToken cancellationToken = default)
    {
        if (recoveryId == Guid.Empty || deviceId.Value == Guid.Empty ||
            !AgentCertificateFingerprint.IsValid(replacementCertificateSha256) ||
            !AgentCertificateFingerprint.IsValid(evidenceSha256) ||
            !IsIncidentReferenceValid(incidentReference))
        {
            throw new ArgumentException("Agent certificate recovery approval is invalid.");
        }

        var allowed = actor.Kind == ActorKind.Person &&
            (await authorization.AuthorizeAsync(
                new AuthorizationRequest(actor, ApprovePermission), cancellationToken)).IsAllowed;
        await WriteAuditAsync(actor, allowed ? "recovery_approval_requested" :
            "recovery_approval_denied", deviceId, correlationId, evidenceSha256,
            incidentReference, clock.UtcNow, cancellationToken);
        if (!allowed)
        {
            throw new UnauthorizedAccessException("Agent certificate recovery approval is not authorized.");
        }

        var now = clock.UtcNow.ToUniversalTime();
        var token = AgentEnrollmentToken.Create();
        try
        {
            await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
            if (!await CoreDeviceRowLock.TryLockAsync(database, deviceId, cancellationToken))
            {
                throw new AgentRecoveryConflictException();
            }

            var request = await database.AgentCertificateRecoveries.AsNoTracking()
                .SingleOrDefaultAsync(row => row.RecoveryId == recoveryId &&
                    row.DeviceId == deviceId && row.ApprovedAt == null &&
                    row.ExpiresAt > now, cancellationToken);
            if (request is null)
            {
                throw new AgentRecoveryConflictException();
            }

            if (request.RequesterSubjectId == actor.SubjectId)
            {
                throw new UnauthorizedAccessException(
                    "A separate administrator must approve certificate recovery.");
            }

            if (request.ReplacementCertificateSha256 != replacementCertificateSha256 ||
                request.EvidenceSha256 != evidenceSha256 ||
                request.IncidentReference != incidentReference ||
                !await BindingExistsAsync(deviceId,
                    request.ExpectedCertificateSha256, cancellationToken) ||
                await database.AgentCertificates.AsNoTracking().AnyAsync(
                    row => row.CertificateSha256 == replacementCertificateSha256,
                    cancellationToken) ||
                await ActiveRecoveryGrantExistsAsync(deviceId, now, cancellationToken))
            {
                throw new AgentRecoveryConflictException();
            }

            var revoked = await database.AgentCertificates
                .Where(row => row.DeviceId == deviceId && row.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(row => row.RevokedAt, now), cancellationToken);
            await database.AgentRotationIntents
                .Where(row => row.DeviceId == deviceId)
                .ExecuteDeleteAsync(cancellationToken);
            await database.AgentEnrollmentGrants
                .Where(row => row.DeviceId == deviceId && row.ConsumedAt == null)
                .ExecuteDeleteAsync(cancellationToken);

            var approved = await database.AgentCertificateRecoveries
                .Where(row => row.RecoveryId == recoveryId && row.ApprovedAt == null)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(row => row.ApprovedAt, now)
                    .SetProperty(row => row.ApproverSubjectId, actor.SubjectId),
                    cancellationToken);
            if (approved != 1)
            {
                throw new AgentRecoveryConflictException();
            }

            database.AgentEnrollmentGrants.Add(AgentEnrollmentGrantRecord.Create(
                AgentEnrollmentToken.Hash(token), deviceId, now.Add(GrantLifetime),
                request.ExpectedCertificateSha256, replacementCertificateSha256,
                recoveryId));
            await database.SaveChangesAsync(cancellationToken);
            await WriteAuditInTransactionAsync(actor, "recovery_approved", deviceId,
                correlationId, evidenceSha256, incidentReference, clock.UtcNow,
                transaction, cancellationToken, revoked);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (AgentRecoveryConflictException)
        {
            await WriteAuditAsync(actor, "recovery_approval_conflict", deviceId,
                correlationId, evidenceSha256, incidentReference, clock.UtcNow,
                cancellationToken);
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            await WriteAuditAsync(actor, "recovery_approval_denied", deviceId,
                correlationId, evidenceSha256, incidentReference, clock.UtcNow,
                cancellationToken);
            throw;
        }

        return token;
    }

    private static void ValidateRequest(DeviceId deviceId,
        string expectedCertificateSha256, string replacementCertificateSha256,
        string evidenceSha256, string incidentReference)
    {
        if (deviceId.Value == Guid.Empty ||
            !AgentCertificateFingerprint.IsValid(expectedCertificateSha256) ||
            !AgentCertificateFingerprint.IsValid(replacementCertificateSha256) ||
            expectedCertificateSha256 == replacementCertificateSha256 ||
            !AgentCertificateFingerprint.IsValid(evidenceSha256) ||
            !IsIncidentReferenceValid(incidentReference))
        {
            throw new ArgumentException("Agent certificate recovery request is invalid.");
        }
    }

    private static bool IsIncidentReferenceValid(string? value) =>
        value is { Length: > 0 and <= 128 } &&
        value.All(character => char.IsLetterOrDigit(character) ||
            character is '-' or '_' or '.' or ':' or '/');

    private ValueTask<bool> BindingExistsAsync(DeviceId deviceId, string fingerprint,
        CancellationToken cancellationToken) =>
        new(database.AgentCertificates.AsNoTracking().AnyAsync(
            row => row.DeviceId == deviceId && row.CertificateSha256 == fingerprint,
            cancellationToken));

    private ValueTask<bool> ActiveRecoveryGrantExistsAsync(DeviceId deviceId,
        DateTimeOffset now, CancellationToken cancellationToken) =>
        new(database.AgentEnrollmentGrants.AsNoTracking().AnyAsync(
            row => row.DeviceId == deviceId && row.RecoveryRequestId != null &&
                row.ConsumedAt == null && row.ExpiresAt > now,
            cancellationToken));

    private ValueTask WriteAuditAsync(ActorReference actor, string action,
        DeviceId deviceId, CorrelationId correlationId, string evidenceSha256,
        string incidentReference, DateTimeOffset occurredAt,
        CancellationToken cancellationToken) =>
        audit.WriteAsync(CreateAuditRecord(actor, action, deviceId,
            correlationId, evidenceSha256, incidentReference, occurredAt),
            cancellationToken);

    private ValueTask WriteAuditInTransactionAsync(ActorReference actor, string action,
        DeviceId deviceId, CorrelationId correlationId, string evidenceSha256,
        string incidentReference, DateTimeOffset occurredAt,
        IDbContextTransaction transaction, CancellationToken cancellationToken,
        int? revokedCount = null) =>
        audit.WriteInTransactionAsync(CreateAuditRecord(actor, action, deviceId,
            correlationId, evidenceSha256, incidentReference, occurredAt,
            revokedCount), transaction.GetDbTransaction(), cancellationToken);

    private static AuditRecord CreateAuditRecord(ActorReference actor, string action,
        DeviceId deviceId, CorrelationId correlationId, string evidenceSha256,
        string incidentReference, DateTimeOffset occurredAt, int? revokedCount = null)
    {
        var context = new Dictionary<string, string>
        {
            ["evidence_sha256"] = evidenceSha256,
            ["incident_reference"] = incidentReference
        };
        if (revokedCount is not null)
        {
            context["revoked_count"] = revokedCount.Value.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
        }

        return new AuditRecord(actor, $"core.agent_certificate.{action}",
            new AuditTarget("device", deviceId.Value.ToString("D")),
            correlationId, occurredAt, context);
    }
}

public sealed class AgentRecoveryConflictException : Exception
{
    public AgentRecoveryConflictException()
        : base("Agent certificate recovery state does not match the request.")
    {
    }
}
