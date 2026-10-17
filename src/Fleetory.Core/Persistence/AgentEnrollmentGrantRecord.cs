using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Fleetory.Core.Contracts;

namespace Fleetory.Core.Persistence;

[Table("agent_enrollment_grants", Schema = CoreDbContext.SchemaName)]
internal sealed class AgentEnrollmentGrantRecord
{
    private AgentEnrollmentGrantRecord()
    {
    }

    private AgentEnrollmentGrantRecord(string tokenSha256, DeviceId deviceId, DateTimeOffset expiresAt)
    {
        TokenSha256 = tokenSha256;
        DeviceId = deviceId;
        ExpiresAt = expiresAt.ToUniversalTime();
    }

    [Key]
    [MaxLength(64)]
    [Column("token_sha256")]
    public string TokenSha256 { get; private set; } = string.Empty;

    [Column("device_id", TypeName = "uuid")]
    public DeviceId DeviceId { get; private set; }

    [Column("expires_at", TypeName = "timestamp with time zone")]
    public DateTimeOffset ExpiresAt { get; private set; }

    [Column("consumed_at", TypeName = "timestamp with time zone")]
    public DateTimeOffset? ConsumedAt { get; private set; }

    public static AgentEnrollmentGrantRecord Create(
        string tokenSha256, DeviceId deviceId, DateTimeOffset expiresAt)
    {
        if (deviceId.Value == Guid.Empty || tokenSha256.Length != 64 ||
            tokenSha256.Any(character => character is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
        {
            throw new ArgumentException("Agent enrollment grant is invalid.");
        }

        return new AgentEnrollmentGrantRecord(tokenSha256, deviceId, expiresAt);
    }
}
