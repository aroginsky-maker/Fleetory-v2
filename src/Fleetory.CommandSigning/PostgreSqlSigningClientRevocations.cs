using Npgsql;

namespace Fleetory.CommandSigning;

/// <summary>The signer can read, but never change, the independently administered denylist.</summary>
public sealed class PostgreSqlSigningClientRevocations(NpgsqlDataSource source) : ISigningClientRevocations
{
    public async Task EnsureNotRevokedAsync(string certificateSha256, CancellationToken cancellationToken = default)
    {
        if (certificateSha256 is not { Length: 64 } || !certificateSha256.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("A certificate SHA-256 is required.", nameof(certificateSha256));
        }
        await using var command = source.CreateCommand("""
            SELECT EXISTS (SELECT 1 FROM signer.client_certificate_revocations
                           WHERE certificate_sha256 = $1);
            """);
        command.Parameters.AddWithValue(certificateSha256.ToUpperInvariant());
        if (await command.ExecuteScalarAsync(cancellationToken) is true)
        {
            throw new UnauthorizedAccessException("Signing client certificate is revoked.");
        }
    }
}
