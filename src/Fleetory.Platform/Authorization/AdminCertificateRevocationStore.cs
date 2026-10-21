using Fleetory.Platform.Persistence;
using Npgsql;
using NpgsqlTypes;

namespace Fleetory.Platform.Authorization;

/// <summary>Checks the durable emergency revocation list for each Admin request.</summary>
public interface IAdminCertificateRevocationStore
{
    ValueTask<bool> IsRevokedAsync(string certificateSha256,
        CancellationToken cancellationToken = default);
}

internal sealed class AdminCertificateRevocationStore(PostgreSqlConnectionSettings settings)
    : IAdminCertificateRevocationStore
{
    public async ValueTask<bool> IsRevokedAsync(
        string certificateSha256,
        CancellationToken cancellationToken = default)
    {
        if (certificateSha256 is null || certificateSha256.Length != 64 ||
            certificateSha256.Any(character => !Uri.IsHexDigit(character) ||
                char.IsLetter(character) && !char.IsUpper(character)))
        {
            throw new ArgumentException("Certificate SHA-256 must be uppercase hexadecimal.",
                nameof(certificateSha256));
        }

        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT EXISTS (
                SELECT 1 FROM platform.admin_certificate_revocations
                WHERE certificate_sha256 = @certificate_sha256)
            """, connection);
        command.Parameters.AddWithValue("certificate_sha256", NpgsqlDbType.Varchar,
            certificateSha256);
        return (bool?)await command.ExecuteScalarAsync(cancellationToken) == true;
    }
}
