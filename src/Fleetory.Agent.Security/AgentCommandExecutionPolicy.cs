using Fleetory.Core.Contracts;

namespace Fleetory.Agent.Security;

/// <summary>Initial local policy: allow a bounded, argument-free inventory refresh only.</summary>
public sealed class AgentCommandExecutionPolicy(DeviceId localDeviceId) : ICommandExecutionPolicy
{
    public ValueTask<bool> IsAllowedAsync(
        DeviceId targetDeviceId,
        string commandType,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            localDeviceId.Value != Guid.Empty &&
            targetDeviceId == localDeviceId &&
            commandType == AgentCommandTypes.InventoryRefresh &&
            payload.IsEmpty);
    }
}
