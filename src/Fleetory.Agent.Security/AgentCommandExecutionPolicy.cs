using Fleetory.Core.Contracts;

namespace Fleetory.Agent.Security;

/// <summary>Initial local policy: allow a bounded, argument-free inventory refresh only.</summary>
public sealed class AgentCommandExecutionPolicy(DeviceId localDeviceId) : ICommandExecutionPolicy
{
    public CommandPolicyDecision Evaluate(
        DeviceId targetDeviceId,
        string commandType,
        ReadOnlyMemory<byte> payload)
    {
        var risk = Classify(commandType);
        var allowed = localDeviceId.Value != Guid.Empty &&
            targetDeviceId == localDeviceId &&
            commandType == AgentCommandTypes.InventoryRefresh &&
            payload.IsEmpty;
        return new(
            allowed,
            risk,
            risk == CommandRiskLevel.Low
                ? CommandApprovalRequirement.None
                : CommandApprovalRequirement.TwoPerson);
    }

    public ValueTask<bool> IsAllowedAsync(
        DeviceId targetDeviceId,
        string commandType,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Evaluate(targetDeviceId, commandType, payload).Allowed);
    }

    private static CommandRiskLevel Classify(string commandType) =>
        commandType == AgentCommandTypes.InventoryRefresh
            ? CommandRiskLevel.Low
            : commandType.StartsWith("Fleet.Bulk.", StringComparison.Ordinal)
                ? CommandRiskLevel.Bulk
                : CommandRiskLevel.High;
}
