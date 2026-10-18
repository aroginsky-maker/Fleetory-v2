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

    private AgentEnrollmentGrantRecord(string tokenSha256, DeviceId deviceId,
        DateTimeOffset expiresAt, string? expectedCertificateSha256,
        string? replacementCertificateSha256)
    {
        TokenSha256 = tokenSha256;
        DeviceId = deviceId;
        ExpiresAt = expiresAt.ToUniversalTime();
        ExpectedCertificateSha256 = expectedCertificateSha256;
        ReplacementCertificateSha256 = replacementCertificateSha256;
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

    [MaxLength(64)]
    [Column("expected_certificate_sha256")]
    public string? ExpectedCertificateSha256 { get; private set; }

    [MaxLength(64)]
    [Column("replacement_certificate_sha256")]
    public string? ReplacementCertificateSha256 { get; private set; }

    public static AgentEnrollmentGrantRecord Create(
        string tokenSha256, DeviceId deviceId, DateTimeOffset expiresAt,
        string? expectedCertificateSha256, string? replacementCertificateSha256)
    {
        if (deviceId.Value == Guid.Empty || !AgentCertificateFingerprint.IsValid(tokenSha256) ||
            expectedCertificateSha256 is not null &&
            !AgentCertificateFingerprint.IsValid(expectedCertificateSha256) ||
            (expectedCertificateSha256 is null) != (replacementCertificateSha256 is null) ||
            replacementCertificateSha256 is not null &&
            !AgentCertificateFingerprint.IsValid(replacementCertificateSha256))
        {
            throw new ArgumentException("Agent enrollment grant is invalid.");
        }

        return new AgentEnrollmentGrantRecord(tokenSha256, deviceId, expiresAt,
            expectedCertificateSha256, replacementCertificateSha256);
    }
}
