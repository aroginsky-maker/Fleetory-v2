using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;

namespace Fleetory.Core.Tests;

public sealed class X509EndEntityPolicyTests
{
    [Theory]
    [InlineData(null, true, false, true)]
    [InlineData(false, true, false, true)]
    [InlineData(true, true, true, false)]
    [InlineData(false, false, false, false)]
    [InlineData(null, true, true, false)]
    public void Accepts_only_signing_end_entity_keys(bool? isCa,
        bool digitalSignature, bool certificateSigning, bool expected)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Fleetory Test",
            key, HashAlgorithmName.SHA256);
        if (isCa is not null)
        {
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(isCa.Value, false, 0, true));
        }

        var flags = (digitalSignature ? X509KeyUsageFlags.DigitalSignature : 0) |
            (certificateSigning ? X509KeyUsageFlags.KeyCertSign : 0);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(flags, true));
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));

        Assert.Equal(expected, X509EndEntityPolicy.HasDigitalSignatureUsage(certificate));
    }
}
