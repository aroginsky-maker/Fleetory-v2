using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Fleetory.Core.Contracts;

namespace Fleetory.Core.Persistence;

[Table("agent_certificate_recoveries", Schema = CoreDbContext.SchemaName)]
internal sealed class AgentCertificateRecoveryRecord
{
    private AgentCertificateRecoveryRecord()
    {
    }

    private AgentCertificateRecoveryRecord(
        Guid recoveryId, DeviceId deviceId, string requesterSubjectId,
        string expectedCertificateSha256, string replacementCertificateSha256,
        string evidenceSha256, string incidentReference, DateTimeOffset expiresAt)
    {
        RecoveryId = recoveryId;
        DeviceId = deviceId;
        RequesterSubjectId = requesterSubjectId;
        ExpectedCertificateSha256 = expectedCertificateSha256;
        ReplacementCertificateSha256 = replacementCertificateSha256;
        EvidenceSha256 = evidenceSha256;
        IncidentReference = incidentReference;
        ExpiresAt = expiresAt.ToUniversalTime();
    }

    [Key]
    [Column("recovery_id", TypeName = "uuid")]
    public Guid RecoveryId { get; private set; }

    [Column("device_id", TypeName = "uuid")]
    public DeviceId DeviceId { get; private set; }

    [MaxLength(128)]
    [Column("requester_subject_id")]
    public string RequesterSubjectId { get; private set; } = string.Empty;

    [MaxLength(64)]
    [Column("expected_certificate_sha256")]
    public string ExpectedCertificateSha256 { get; private set; } = string.Empty;

    [MaxLength(64)]
    [Column("replacement_certificate_sha256")]
    public string ReplacementCertificateSha256 { get; private set; } = string.Empty;

    [MaxLength(64)]
    [Column("evidence_sha256")]
    public string EvidenceSha256 { get; private set; } = string.Empty;

    [MaxLength(128)]
    [Column("incident_reference")]
    public string IncidentReference { get; private set; } = string.Empty;

    [Column("expires_at", TypeName = "timestamp with time zone")]
    public DateTimeOffset ExpiresAt { get; private set; }

    [Column("approved_at", TypeName = "timestamp with time zone")]
    public DateTimeOffset? ApprovedAt { get; private set; }

    [MaxLength(128)]
    [Column("approver_subject_id")]
    public string? ApproverSubjectId { get; private set; }

    public static AgentCertificateRecoveryRecord Create(
        Guid recoveryId, DeviceId deviceId, string requesterSubjectId,
        string expectedCertificateSha256, string replacementCertificateSha256,
        string evidenceSha256, string incidentReference, DateTimeOffset expiresAt)
    {
        if (recoveryId == Guid.Empty || deviceId.Value == Guid.Empty ||
            string.IsNullOrWhiteSpace(requesterSubjectId) || requesterSubjectId.Length > 128 ||
            !AgentCertificateFingerprint.IsValid(expectedCertificateSha256) ||
            !AgentCertificateFingerprint.IsValid(replacementCertificateSha256) ||
            expectedCertificateSha256 == replacementCertificateSha256 ||
            !AgentCertificateFingerprint.IsValid(evidenceSha256) ||
            string.IsNullOrWhiteSpace(incidentReference) || incidentReference.Length > 128)
        {
            throw new ArgumentException("Agent certificate recovery request is invalid.");
        }

        return new AgentCertificateRecoveryRecord(recoveryId, deviceId,
            requesterSubjectId, expectedCertificateSha256,
            replacementCertificateSha256, evidenceSha256, incidentReference,
            expiresAt);
    }
}
