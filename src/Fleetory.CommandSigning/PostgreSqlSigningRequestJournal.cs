using System.Security.Cryptography;
using Fleetory.Core.Contracts;
using Npgsql;

namespace Fleetory.CommandSigning;

/// <summary>Append-only signer-owned journal; schema provisioning belongs to an independent deployment identity.</summary>
public sealed class PostgreSqlSigningRequestJournal(NpgsqlDataSource dataSource) : ISigningRequestJournal
{
    public async Task<bool> TryBeginAsync(SigningRequest request, CancellationToken cancellationToken = default)
    {
        ValidateRequest(request);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await RequireDurableCommitAsync(connection, transaction, cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO signer.signing_requests
                (request_id, caller_id, client_certificate_sha256, target_device_id, command_type)
            VALUES ($1, $2, $3, $4, 'Inventory.Refresh')
            ON CONFLICT (request_id) DO NOTHING;
            """, connection, transaction);
        AddRequestParameters(command, request);
        var inserted = await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return inserted == 1;
    }

    public async Task CompleteAsync(SigningRequest request, SignedCommandEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ValidateRequest(request);
        ArgumentNullException.ThrowIfNull(envelope);
        if (envelope.TargetDeviceId != request.TargetDeviceId || envelope.CommandId == Guid.Empty ||
            envelope.FormatVersion != 1 || envelope.CommandType != AgentCommandTypes.InventoryRefresh ||
            !envelope.Payload.IsEmpty || envelope.Signature.Length != 64 ||
            envelope.SigningKeyId is not { Length: >= 1 and <= 128 } ||
            !envelope.SigningKeyId.All(character => char.IsAsciiLetterOrDigit(character) || character == '-'))
        {
            throw new ArgumentException("Signing result does not match the authorized request.", nameof(envelope));
        }
        var bytes = envelope.GetSigningBytes();
        var hash = Convert.ToHexString(SHA256.HashData([.. bytes, .. envelope.Signature.Span]));
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await RequireDurableCommitAsync(connection, transaction, cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO signer.signing_results (request_id, command_id, signing_key_id, envelope_sha256)
            SELECT request_id, $5, $6, $7 FROM signer.signing_requests
            WHERE request_id = $1 AND caller_id = $2 AND client_certificate_sha256 = $3 AND target_device_id = $4
            ON CONFLICT (request_id) DO NOTHING;
            """, connection, transaction);
        AddRequestParameters(command, request);
        command.Parameters.AddWithValue(envelope.CommandId);
        command.Parameters.AddWithValue(envelope.SigningKeyId);
        command.Parameters.AddWithValue(hash);
        await command.ExecuteNonQueryAsync(cancellationToken);
        await using var verify = new NpgsqlCommand("""
            SELECT EXISTS (
                SELECT 1 FROM signer.signing_requests AS request
                JOIN signer.signing_results AS result USING (request_id)
                WHERE request.request_id = $1 AND request.caller_id = $2
                    AND request.client_certificate_sha256 = $3 AND request.target_device_id = $4
                    AND result.command_id = $5 AND result.signing_key_id = $6 AND result.envelope_sha256 = $7
            );
            """, connection, transaction);
        AddRequestParameters(verify, request);
        verify.Parameters.AddWithValue(envelope.CommandId);
        verify.Parameters.AddWithValue(envelope.SigningKeyId);
        verify.Parameters.AddWithValue(hash);
        if (await verify.ExecuteScalarAsync(cancellationToken) is not true)
        {
            throw new InvalidOperationException("Signing journal completion is missing or conflicts with its reservation.");
        }
        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task RequireDurableCommitAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SET LOCAL synchronous_commit = on", connection, transaction);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddRequestParameters(NpgsqlCommand command, SigningRequest request)
    {
        command.Parameters.AddWithValue(request.RequestId);
        command.Parameters.AddWithValue(request.CallerId);
        command.Parameters.AddWithValue(request.ClientCertificateSha256.ToUpperInvariant());
        command.Parameters.AddWithValue(request.TargetDeviceId.Value);
    }

    private static void ValidateRequest(SigningRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequestId == Guid.Empty || request.TargetDeviceId.Value == Guid.Empty ||
            request.CallerId is not { Length: >= 1 and <= 96 } ||
            !request.CallerId.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_') ||
            request.ClientCertificateSha256 is not { Length: 64 } || !request.ClientCertificateSha256.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Signing request identity is invalid.", nameof(request));
        }
    }
}
