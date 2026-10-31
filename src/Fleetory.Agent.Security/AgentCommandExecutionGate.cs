using Fleetory.Core.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Agent.Security;

/// <summary>Runs the only enabled Agent action after local signature, policy and replay checks.</summary>
public sealed class AgentCommandExecutionGate
{
    private readonly DeviceId _localDeviceId;
    private readonly SignedCommandVerifier _verifier;
    private readonly IClock _clock;
    private readonly IAgentInventoryRefreshHandler _inventoryRefresh;

    private AgentCommandExecutionGate(
        DeviceId localDeviceId,
        SignedCommandVerifier verifier,
        IClock clock,
        IAgentInventoryRefreshHandler inventoryRefresh)
    {
        _localDeviceId = localDeviceId;
        _verifier = verifier;
        _clock = clock;
        _inventoryRefresh = inventoryRefresh;
    }

    public static AgentCommandExecutionGate Create(
        DeviceId localDeviceId,
        string trustDirectory,
        string replayDatabasePath,
        IClock clock,
        IAgentInventoryRefreshHandler inventoryRefresh)
    {
        if (localDeviceId.Value == Guid.Empty)
        {
            throw new ArgumentException("A local DeviceId is required.", nameof(localDeviceId));
        }

        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(inventoryRefresh);
        var verifier = new SignedCommandVerifier(
            new DirectoryCommandVerificationKeys(localDeviceId, trustDirectory),
            new SqliteCommandReplayStore(replayDatabasePath),
            new AgentCommandExecutionPolicy(localDeviceId), clock);
        return new AgentCommandExecutionGate(localDeviceId, verifier, clock, inventoryRefresh);
    }

    public async ValueTask<CommandVerificationStatus> ExecuteAsync(
        SignedCommandEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        var result = await _verifier.VerifyAsync(envelope, _localDeviceId, cancellationToken);
        if (result.Status != CommandVerificationStatus.Accepted)
        {
            return result.Status;
        }

        var command = result.Command ?? throw new InvalidOperationException(
            "The verifier accepted a command without verified content.");
        if (command.TargetDeviceId != _localDeviceId ||
            command.CommandType != AgentCommandTypes.InventoryRefresh ||
            !command.Payload.IsEmpty)
        {
            return CommandVerificationStatus.DeniedByPolicy;
        }

        if (!SignedCommandVerifier.IsWithinValidityWindow(envelope, _clock.UtcNow))
        {
            return CommandVerificationStatus.OutsideValidityWindow;
        }

        await _inventoryRefresh.RefreshAsync(command.CommandId, cancellationToken);
        return CommandVerificationStatus.Accepted;
    }
}

public interface IAgentInventoryRefreshHandler
{
    ValueTask RefreshAsync(Guid commandId, CancellationToken cancellationToken = default);
}
