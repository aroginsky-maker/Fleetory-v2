using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Fleetory.Core.Contracts;

namespace Fleetory.Core.Persistence;

[Table("devices", Schema = CoreDbContext.SchemaName)]
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

    [Key]
    [Column("device_id", TypeName = "uuid")]
    public DeviceId DeviceId { get; private set; }

    [Required]
    [MaxLength(256)]
    [Column("display_name")]
    public string DisplayName { get; private set; } = string.Empty;

    [Required]
    [Column("updated_at", TypeName = "timestamp with time zone")]
    public DateTimeOffset UpdatedAt { get; private set; }

    [ConcurrencyCheck]
    [Column("revision")]
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
