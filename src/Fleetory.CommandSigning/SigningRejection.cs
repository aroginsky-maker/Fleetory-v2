using Npgsql;

namespace Fleetory.CommandSigning;

public sealed class SigningRequestConflictException() : InvalidOperationException(
    "Signing RequestId is already reserved; reconcile its journal record.");

public enum SigningRejectionReason { InvalidRequest, Forbidden, Duplicate, RateLimited, Unavailable, Cancelled }

public sealed partial class PostgreSqlSigningRequestJournal
{
    public async Task<Guid> RecordRejectionAsync(string fingerprint, SigningRejectionReason reason,
        Guid? requestId = null, Guid? deviceId = null,
        CancellationToken cancellationToken = default)
    {
        if (fingerprint.Length != 64 || !fingerprint.All(Uri.IsHexDigit) || !Enum.IsDefined(reason))
        {
            throw new ArgumentException("Signing rejection metadata is invalid.");
        }
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await RequireDurableCommitAsync(connection, transaction, cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO signer.signing_rejections (event_id, client_certificate_sha256, reason, request_id, target_device_id)
            VALUES ($1, $2, $3, $4, $5);
            """, connection, transaction);
        var eventId = Guid.NewGuid();
        command.Parameters.AddWithValue(eventId);
        command.Parameters.AddWithValue(fingerprint.ToUpperInvariant());
        command.Parameters.AddWithValue(reason.ToString());
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Uuid, Value = (object?)requestId ?? DBNull.Value });
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Uuid, Value = (object?)deviceId ?? DBNull.Value });
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return eventId;
    }
}
