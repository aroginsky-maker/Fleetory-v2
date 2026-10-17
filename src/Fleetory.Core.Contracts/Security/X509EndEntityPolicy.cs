using System.Security.Cryptography.X509Certificates;

namespace Fleetory.Core.Contracts;

/// <summary>Common end-entity key checks for Fleetory-issued TLS certificates.</summary>
public static class X509EndEntityPolicy
{
    public static bool HasDigitalSignatureUsage(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        return constraints?.CertificateAuthority != true && usage is not null &&
            (usage.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0 &&
            (usage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0;
    }
}
