using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Fleetory.Core.Contracts;

namespace Fleetory.Core.Persistence;

[Table("agent_rotation_intents", Schema = CoreDbContext.SchemaName)]
internal sealed class AgentRotationIntentRecord
{
    private AgentRotationIntentRecord()
    {
    }

    private AgentRotationIntentRecord(Guid intentId, DeviceId deviceId,
        string currentCertificateSha256, string replacementCertificateSha256,
        DateTimeOffset expiresAt)
    {
        IntentId = intentId;
        DeviceId = deviceId;
        CurrentCertificateSha256 = currentCertificateSha256;
        ReplacementCertificateSha256 = replacementCertificateSha256;
        ExpiresAt = expiresAt.ToUniversalTime();
    }

    [Key]
    [Column("intent_id", TypeName = "uuid")]
    public Guid IntentId { get; private set; }

    [Column("device_id", TypeName = "uuid")]
    public DeviceId DeviceId { get; private set; }

    [MaxLength(64)]
    [Column("current_certificate_sha256")]
    public string CurrentCertificateSha256 { get; private set; } = string.Empty;

    [MaxLength(64)]
    [Column("replacement_certificate_sha256")]
    public string ReplacementCertificateSha256 { get; private set; } = string.Empty;

    [Column("expires_at", TypeName = "timestamp with time zone")]
    public DateTimeOffset ExpiresAt { get; private set; }

    [Column("claimed_at", TypeName = "timestamp with time zone")]
    public DateTimeOffset? ClaimedAt { get; private set; }

    public static AgentRotationIntentRecord Create(Guid intentId, DeviceId deviceId,
        string currentCertificateSha256, string replacementCertificateSha256,
        DateTimeOffset expiresAt)
    {
        if (intentId == Guid.Empty || deviceId.Value == Guid.Empty ||
            !AgentCertificateFingerprint.IsValid(currentCertificateSha256) ||
            !AgentCertificateFingerprint.IsValid(replacementCertificateSha256) ||
            currentCertificateSha256 == replacementCertificateSha256)
        {
            throw new ArgumentException("Agent rotation intent is invalid.");
        }

        return new AgentRotationIntentRecord(intentId, deviceId,
            currentCertificateSha256, replacementCertificateSha256, expiresAt);
    }
}
