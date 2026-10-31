using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Fleetory.Core.Contracts;

namespace Fleetory.Core.Persistence;

[Table("agent_certificates", Schema = CoreDbContext.SchemaName)]
internal sealed class AgentCertificateRecord
{
    private AgentCertificateRecord()
    {
    }

    private AgentCertificateRecord(
        DeviceId deviceId,
        string certificateSha256,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        DeviceId = deviceId;
        CertificateSha256 = certificateSha256;
        NotBefore = notBefore.ToUniversalTime();
        NotAfter = notAfter.ToUniversalTime();
    }

    [Key]
    [MaxLength(64)]
    [Column("certificate_sha256")]
    public string CertificateSha256 { get; private set; } = string.Empty;

    [Column("device_id", TypeName = "uuid")]
    public DeviceId DeviceId { get; private set; }

    [Column("not_before", TypeName = "timestamp with time zone")]
    public DateTimeOffset NotBefore { get; private set; }

    [Column("not_after", TypeName = "timestamp with time zone")]
    public DateTimeOffset NotAfter { get; private set; }

    [Column("revoked_at", TypeName = "timestamp with time zone")]
    public DateTimeOffset? RevokedAt { get; private set; }

    public static AgentCertificateRecord Create(
        DeviceId deviceId,
        string certificateSha256,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        if (deviceId.Value == Guid.Empty || !AgentCertificateFingerprint.IsValid(certificateSha256) ||
            notAfter <= notBefore)
        {
            throw new ArgumentException("Agent certificate binding is invalid.");
        }

        return new AgentCertificateRecord(deviceId, certificateSha256, notBefore, notAfter);
    }

    public void Revoke(DateTimeOffset revokedAt)
    {
        RevokedAt ??= revokedAt.ToUniversalTime();
    }
}
