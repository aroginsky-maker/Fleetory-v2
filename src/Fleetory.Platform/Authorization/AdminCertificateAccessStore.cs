using Fleetory.Platform.Persistence;
using Npgsql;
using NpgsqlTypes;

namespace Fleetory.Platform.Authorization;

public enum AdminCertificateAccess { Accepted, Revoked, Unregistered }

/// <summary>Checks the durable Admin credential registry on every request.</summary>
public interface IAdminCertificateAccessStore
{
    ValueTask<AdminCertificateAccess> CheckAsync(string certificateSha256,
        string actorSubjectId, bool requireRegistration,
        CancellationToken cancellationToken = default);
}

internal sealed class AdminCertificateAccessStore(PostgreSqlConnectionSettings settings)
    : IAdminCertificateAccessStore
{
    public async ValueTask<AdminCertificateAccess> CheckAsync(
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
                EXISTS (
                    SELECT 1 FROM platform.admin_certificate_registrations
                    WHERE certificate_sha256 = @certificate_sha256
                      AND actor_subject_id = @actor_subject_id
                      AND (overlap_ends_at IS NULL OR overlap_ends_at > now()))
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

        return reader.GetBoolean(0) ? AdminCertificateAccess.Revoked :
            requireRegistration && !reader.GetBoolean(1)
                ? AdminCertificateAccess.Unregistered : AdminCertificateAccess.Accepted;
    }
}
