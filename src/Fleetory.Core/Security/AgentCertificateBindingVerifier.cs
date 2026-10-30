using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Core.Security;

public sealed class AgentCertificateBindingVerifier(
    IAgentCertificateBindingStore bindings,
    IClock clock)
    : IAgentCertificateBindingVerifier
{
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

    public async ValueTask<AgentCertificateStatus> VerifyAsync(
        DeviceId deviceId,
        X509Certificate2 certificate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        cancellationToken.ThrowIfCancellationRequested();

        if (deviceId.Value == Guid.Empty || !HasClientAuthenticationPurpose(certificate))
        {
            return AgentCertificateStatus.InvalidCertificate;
        }

        var instant = clock.UtcNow.ToUniversalTime();
        if (!CertificateValidity.IsCurrent(certificate, instant))
        {
            return AgentCertificateStatus.Expired;
        }

        var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        var binding = await bindings.FindBySha256Async(fingerprint, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        instant = clock.UtcNow.ToUniversalTime();
        if (!CertificateValidity.IsCurrent(certificate, instant))
        {
            return AgentCertificateStatus.Expired;
        }
        if (binding is null)
        {
            return AgentCertificateStatus.UnknownCertificate;
        }

        if (!StringComparer.Ordinal.Equals(binding.CertificateSha256, fingerprint))
        {
            return AgentCertificateStatus.UnknownCertificate;
        }

        if (binding.DeviceId != deviceId)
        {
            return AgentCertificateStatus.WrongDevice;
        }

        if (binding.RevokedAt is not null)
        {
            return AgentCertificateStatus.Revoked;
        }

        if (instant < binding.NotBefore || instant >= binding.NotAfter)
        {
            return AgentCertificateStatus.Expired;
        }

        return AgentCertificateStatus.Accepted;
    }

    private static bool HasClientAuthenticationPurpose(X509Certificate2 certificate)
    {
        if (!X509EndEntityPolicy.HasDigitalSignatureUsage(certificate))
        {
            return false;
        }

        var eku = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SingleOrDefault();
        return eku is not null && eku.EnhancedKeyUsages
            .Cast<Oid>()
            .Any(oid => oid.Value == ClientAuthenticationOid);
    }
}
