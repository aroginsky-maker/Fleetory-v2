namespace Fleetory.Core.Contracts;

public enum CommandRiskLevel
{
    Low,
    High,
    Bulk
}

public enum CommandApprovalRequirement
{
    None,
    TwoPerson
}

public sealed record CommandPolicyDecision(
    bool Allowed,
    CommandRiskLevel Risk,
    CommandApprovalRequirement Approval);

/// <summary>Supplies a trusted, target-specific P-256 public key. Private signing keys stay outside Fleetory Server.</summary>
public interface ICommandVerificationKeys
{
    ValueTask<ReadOnlyMemory<byte>?> FindPublicKeyAsync(
        DeviceId targetDeviceId,
        string keyId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Atomically rejects reuse of either the command ID or nonce for the device, then records both before execution.
/// Implementations must survive process restarts and fail closed on storage errors.
/// </summary>
public interface ICommandReplayStore
{
    ValueTask<bool> TryConsumeAsync(
        DeviceId targetDeviceId,
        Guid commandId,
        string nonce,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);
}

/// <summary>Agent-local capability/risk policy. A valid signature alone never authorizes execution.</summary>
public interface ICommandExecutionPolicy
{
    ValueTask<bool> IsAllowedAsync(
        DeviceId targetDeviceId,
        string commandType,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default);
}
