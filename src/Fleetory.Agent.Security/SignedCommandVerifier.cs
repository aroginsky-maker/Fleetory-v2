using System.Security.Cryptography;
using Fleetory.Core.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Agent.Security;

public enum CommandVerificationStatus
{
    Accepted,
    InvalidEnvelope,
    WrongTarget,
    OutsideValidityWindow,
    UnknownKey,
    InvalidSignature,
    DeniedByPolicy,
    Replay
}

public sealed record VerifiedCommand(
    DeviceId TargetDeviceId,
    Guid CommandId,
    string CommandType,
    ReadOnlyMemory<byte> Payload);

public sealed record CommandVerificationResult(
    CommandVerificationStatus Status,
    VerifiedCommand? Command = null);

/// <summary>Fail-closed verification before an Agent dispatches a command to a local handler.</summary>
public sealed class SignedCommandVerifier(
    ICommandVerificationKeys keys,
    ICommandReplayStore replayStore,
    ICommandExecutionPolicy policy,
    IClock clock)
{
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromSeconds(30);

    public async ValueTask<CommandVerificationResult> VerifyAsync(
        SignedCommandEnvelope envelope,
        DeviceId localDeviceId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsWellFormed(envelope))
        {
            return new(CommandVerificationStatus.InvalidEnvelope);
        }

        if (envelope.TargetDeviceId != localDeviceId)
        {
            return new(CommandVerificationStatus.WrongTarget);
        }

        var now = clock.UtcNow;
        if (envelope.ExpiresAt <= now ||
            envelope.IssuedAt > now.Add(MaximumClockSkew) ||
            envelope.ExpiresAt <= envelope.IssuedAt ||
            envelope.ExpiresAt - envelope.IssuedAt > MaximumLifetime)
        {
            return new(CommandVerificationStatus.OutsideValidityWindow);
        }

        var publicKey = await keys.FindPublicKeyAsync(
            localDeviceId, envelope.SigningKeyId, cancellationToken);
        if (publicKey is null || publicKey.Value.Length is 0 or > 1024)
        {
            return new(CommandVerificationStatus.UnknownKey);
        }

        var payload = envelope.Payload.ToArray();
        var signature = envelope.Signature.ToArray();
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKey.Value.Span, out var bytesRead);
            if (bytesRead != publicKey.Value.Length ||
                ecdsa.KeySize != 256 ||
                ecdsa.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value ||
                !ecdsa.VerifyData(
                    envelope.GetSigningBytes(), signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return new(CommandVerificationStatus.InvalidSignature);
            }
        }
        catch (CryptographicException)
        {
            return new(CommandVerificationStatus.InvalidSignature);
        }

        if (!await policy.IsAllowedAsync(
                localDeviceId, envelope.CommandType, payload.ToArray(), cancellationToken))
        {
            return new(CommandVerificationStatus.DeniedByPolicy);
        }

        if (!await replayStore.TryConsumeAsync(
                localDeviceId, envelope.CommandId, envelope.Nonce,
                envelope.ExpiresAt, cancellationToken))
        {
            return new(CommandVerificationStatus.Replay);
        }

        return new(CommandVerificationStatus.Accepted,
            new VerifiedCommand(localDeviceId, envelope.CommandId, envelope.CommandType, payload));
    }

    private static bool IsWellFormed(SignedCommandEnvelope envelope) =>
        envelope.FormatVersion == 1 &&
        envelope.TargetDeviceId.Value != Guid.Empty &&
        envelope.CommandId != Guid.Empty &&
        IsIdentifier(envelope.CommandType, 128) &&
        IsIdentifier(envelope.SigningKeyId, 128) &&
        IsIdentifier(envelope.Nonce, 128) &&
        envelope.Nonce.Length >= 16 &&
        envelope.Payload.Length <= 64 * 1024 &&
        envelope.Signature.Length == 64;

    private static bool IsIdentifier(string? value, int maximumLength) =>
        !string.IsNullOrEmpty(value) &&
        value.Length <= maximumLength &&
        value.All(character =>
            character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-');
}
