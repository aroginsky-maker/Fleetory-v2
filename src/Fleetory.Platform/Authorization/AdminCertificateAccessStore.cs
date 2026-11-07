using Fleetory.Platform.Persistence;
using Npgsql;
using NpgsqlTypes;

namespace Fleetory.Platform.Authorization;

public enum AdminCertificateAccess { Accepted, Revoked, Unregistered }

/// <summary>Retains the registration deadline so later admission work cannot extend a rotation overlap.</summary>
public sealed record AdminCertificateAccessResult(
    AdminCertificateAccess Status, DateTimeOffset? RegistrationExpiresAt = null)
{
    public AdminCertificateAccess GetStatusAt(DateTimeOffset now) =>
        Status == AdminCertificateAccess.Accepted && RegistrationExpiresAt is { } expiry && now >= expiry
            ? AdminCertificateAccess.Unregistered : Status;
}

/// <summary>Checks the durable Admin credential registry on every request.</summary>
public interface IAdminCertificateAccessStore
{
    ValueTask<AdminCertificateAccessResult> CheckAsync(string certificateSha256,
        string actorSubjectId, bool requireRegistration,
        CancellationToken cancellationToken = default);
}

internal sealed class AdminCertificateAccessStore(PostgreSqlConnectionSettings settings)
    : IAdminCertificateAccessStore
{
    public async ValueTask<AdminCertificateAccessResult> CheckAsync(
        string certificateSha256,
        string actorSubjectId,
        bool requireRegistration,
        CancellationToken cancellationToken = default)
    {
        if (certificateSha256 is null || certificateSha256.Length != 64 ||
            certificateSha256.Any(character => !Uri.IsHexDigit(character) ||
                char.IsLetter(character) && !char.IsUpper(character)))
        {
            throw new ArgumentException("Certificate SHA-256 must be uppercase hexadecimal.",
                nameof(certificateSha256));
        }
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSubjectId);

        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT EXISTS (
                SELECT 1 FROM platform.admin_certificate_revocations
                WHERE certificate_sha256 = @certificate_sha256),
                registration.certificate_sha256, registration.overlap_ends_at
            FROM (SELECT 1) AS request
            LEFT JOIN platform.admin_certificate_registrations AS registration
              ON registration.certificate_sha256 = @certificate_sha256
             AND registration.actor_subject_id = @actor_subject_id
             AND (registration.overlap_ends_at IS NULL OR registration.overlap_ends_at > clock_timestamp())
            """, connection);
        command.Parameters.AddWithValue("certificate_sha256", NpgsqlDbType.Varchar,
            certificateSha256);
        command.Parameters.AddWithValue("actor_subject_id", NpgsqlDbType.Varchar,
            actorSubjectId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("Admin certificate registry returned no result.");
        }

        var status = reader.GetBoolean(0) ? AdminCertificateAccess.Revoked :
            requireRegistration && reader.IsDBNull(1)
                ? AdminCertificateAccess.Unregistered : AdminCertificateAccess.Accepted;
        var expiry = requireRegistration && status == AdminCertificateAccess.Accepted && !reader.IsDBNull(2)
            ? reader.GetFieldValue<DateTimeOffset>(2) : (DateTimeOffset?)null;
        return new AdminCertificateAccessResult(status, expiry);
    }
}
