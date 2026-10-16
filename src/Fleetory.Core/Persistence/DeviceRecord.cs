using Fleetory.Core.Contracts;

namespace Fleetory.Core.Persistence;

internal sealed class DeviceRecord
{
    private DeviceRecord()
    {
    }

    private DeviceRecord(
        DeviceId deviceId,
        string displayName,
        DateTimeOffset updatedAt)
    {
        DeviceId = deviceId;
        DisplayName = displayName;
        UpdatedAt = updatedAt.ToUniversalTime();
        Revision = 1;
    }

    public DeviceId DeviceId { get; private set; }

    public string DisplayName { get; private set; } = string.Empty;

    public DateTimeOffset UpdatedAt { get; private set; }

    public long Revision { get; private set; }

    public static DeviceRecord Create(
        DeviceId deviceId,
        string displayName,
        DateTimeOffset updatedAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        return new DeviceRecord(deviceId, displayName, updatedAt);
    }

    public void UpdateDisplayName(string displayName, DateTimeOffset updatedAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        DisplayName = displayName;
        UpdatedAt = updatedAt.ToUniversalTime();
        Revision = checked(Revision + 1);
    }
}
