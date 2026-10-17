using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Platform.Contracts.Secrets;

namespace Fleetory.Server.Infrastructure;

internal sealed class MutualTlsMaterial : IDisposable
{
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    private readonly X509Certificate2 rootCa;

    private MutualTlsMaterial(X509Certificate2 rootCa, X509Certificate2 serverCertificate)
    {
        this.rootCa = rootCa;
        ServerCertificate = serverCertificate;
    }

    public X509Certificate2 ServerCertificate { get; }
    public X509Certificate2 RootCa => rootCa;

    public static MutualTlsMaterial Load(
        ISecretProvider secrets,
        string rootCaSecret,
        string serverCertificateSecret,
        string serverPrivateKeySecret)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        X509Certificate2? root = null;
        X509Certificate2? server = null;
        try
        {
            root = X509Certificate2.CreateFromPem(
                secrets.GetRequiredSecret(rootCaSecret));
            var serverPem = secrets.GetRequiredSecret(serverCertificateSecret);
            var keyPem = secrets.GetRequiredSecret(serverPrivateKeySecret);
            server = X509Certificate2.CreateFromPem(serverPem, keyPem);
            var pkcs12 = server.Export(X509ContentType.Pkcs12);
            try
            {
                var tlsCertificate = X509CertificateLoader.LoadPkcs12(
                    pkcs12, null, X509KeyStorageFlags.UserKeySet);
                server.Dispose();
                server = tlsCertificate;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs12);
            }

            if (!IsCertificateAuthority(root) || !IsEndEntity(server) || !server.HasPrivateKey ||
                !BuildChain(server, root, ServerAuthenticationOid))
            {
                throw new InvalidOperationException("Gateway TLS material is invalid.");
            }

            return new MutualTlsMaterial(root, server);
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            root?.Dispose();
            server?.Dispose();
            throw new InvalidOperationException("Gateway TLS material is invalid.");
        }
        catch
        {
            root?.Dispose();
            server?.Dispose();
            throw;
        }
    }

    public bool ValidateClientCertificate(
        X509Certificate2? certificate,
        X509Chain? _,
        SslPolicyErrors __) =>
        certificate is not null && IsEndEntity(certificate) &&
        BuildChain(certificate, rootCa, ClientAuthenticationOid);

    public void Dispose()
    {
        ServerCertificate.Dispose();
        rootCa.Dispose();
    }

    private static bool IsCertificateAuthority(X509Certificate2 certificate)
    {
        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        return constraints?.CertificateAuthority == true && usage is not null &&
            (usage.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0;
    }

    private static bool IsEndEntity(X509Certificate2 certificate)
    {
        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        return constraints is { CertificateAuthority: false } && usage is not null &&
            (usage.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0;
    }

    private static bool BuildChain(X509Certificate2 certificate, X509Certificate2 root, string purposeOid)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(purposeOid));

        return chain.Build(certificate) &&
            chain.ChainElements.Count == 2 &&
            chain.ChainElements[^1].Certificate.RawData.AsSpan().SequenceEqual(root.RawData);
    }
}
