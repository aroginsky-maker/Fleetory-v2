using System.Security.Cryptography.X509Certificates;

namespace Fleetory.Platform.Contracts;

/// <summary>Checks the leaf time window; chain trust and proof of possession belong to the TLS boundary.</summary>
public static class CertificateValidity
{
    public static bool IsCurrent(X509Certificate2 certificate, DateTimeOffset instant)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return instant >= certificate.NotBefore.ToUniversalTime() &&
            instant < certificate.NotAfter.ToUniversalTime();
    }
}
