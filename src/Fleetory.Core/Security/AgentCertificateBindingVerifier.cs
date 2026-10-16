using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
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

        if (deviceId.Value == Guid.Empty || !HasClientAuthenticationPurpose(certificate))
        {
            return AgentCertificateStatus.InvalidCertificate;
        }

        var instant = clock.UtcNow.ToUniversalTime();
        if (instant < certificate.NotBefore.ToUniversalTime() ||
            instant >= certificate.NotAfter.ToUniversalTime())
        {
            return AgentCertificateStatus.Expired;
        }

        var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        var binding = await bindings.FindBySha256Async(fingerprint, cancellationToken);
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
        var basicConstraints = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault();
        if (basicConstraints is null || basicConstraints.CertificateAuthority)
        {
            return false;
        }

        var keyUsage = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .SingleOrDefault();
        if (keyUsage is null ||
            (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
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
