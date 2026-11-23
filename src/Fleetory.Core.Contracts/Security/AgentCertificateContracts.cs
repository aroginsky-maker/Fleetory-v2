using System.Security.Cryptography.X509Certificates;

namespace Fleetory.Core.Contracts;

public sealed record AgentCertificateBinding(
    DeviceId DeviceId,
    string CertificateSha256,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    DateTimeOffset? RevokedAt);

public enum AgentCertificateStatus
{
    Accepted,
    InvalidCertificate,
    Expired,
    UnknownCertificate,
    WrongDevice,
    Revoked
}

public interface IAgentCertificateBindingStore
{
    ValueTask<AgentCertificateBinding?> FindBySha256Async(
        string certificateSha256,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Checks a registered certificate binding for each Agent request. The caller must first
/// obtain the certificate from an authenticated TLS client-certificate handshake.
/// </summary>
public interface IAgentCertificateBindingVerifier
{
    ValueTask<AgentCertificateStatus> VerifyAsync(
        DeviceId deviceId,
        X509Certificate2 certificate,
        CancellationToken cancellationToken = default);
}
