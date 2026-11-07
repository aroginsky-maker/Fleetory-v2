using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Platform.Contracts.Secrets;

namespace Fleetory.Security.Infrastructure;

public sealed class MutualTlsMaterial : IDisposable
{
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    private readonly X509Certificate2Collection trustedRoots;
    private readonly X509Certificate2Collection serverChain;
    private readonly Func<X509Certificate2, bool> leafPolicy;

    private MutualTlsMaterial(X509Certificate2Collection trustedRoots, X509Certificate2 serverCertificate,
        X509Certificate2Collection serverChain, Func<X509Certificate2, bool> leafPolicy)
    {
        this.trustedRoots = trustedRoots;
        ServerCertificate = serverCertificate;
        this.serverChain = serverChain;
        this.leafPolicy = leafPolicy;
    }

    public X509Certificate2 ServerCertificate { get; }
    public X509Certificate2Collection ServerCertificateChain => serverChain;
    public bool SharesRootWith(MutualTlsMaterial other) =>
        trustedRoots.Cast<X509Certificate2>().Any(root =>
            other.trustedRoots.Cast<X509Certificate2>().Any(candidate =>
                root.RawData.AsSpan().SequenceEqual(candidate.RawData)));

    public static MutualTlsMaterial Load(
        ISecretProvider secrets,
        string rootCaSecret,
        string serverCertificateSecret,
        string serverPrivateKeySecret,
        Func<X509Certificate2, bool> leafPolicy)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(leafPolicy);
        var roots = new X509Certificate2Collection();
        X509Certificate2? server = null;
        var intermediates = new X509Certificate2Collection();
        var pemCertificates = new X509Certificate2Collection();
        try
        {
            roots.ImportFromPem(secrets.GetRequiredSecret(rootCaSecret));
            if (roots.Count is < 1 or > 2 || roots.Cast<X509Certificate2>().Any(root =>
                    !IsCertificateAuthority(root)) ||
                roots.Count == 2 && roots[0].RawData.AsSpan().SequenceEqual(roots[1].RawData))
            {
                throw new InvalidOperationException("Gateway TLS material is invalid.");
            }
            var serverPem = secrets.GetRequiredSecret(serverCertificateSecret);
            var keyPem = secrets.GetRequiredSecret(serverPrivateKeySecret);
            pemCertificates.ImportFromPem(serverPem);
            if (pemCertificates.Count is < 1 or > 4)
            {
                throw new InvalidOperationException("Gateway TLS material is invalid.");
            }

            server = X509Certificate2.CreateFromPem(serverPem, keyPem);
            if (!pemCertificates[0].RawData.AsSpan().SequenceEqual(server.RawData))
            {
                throw new InvalidOperationException("Gateway TLS material is invalid.");
            }

            for (var index = 1; index < pemCertificates.Count; index++)
            {
                if (!IsCertificateAuthority(pemCertificates[index]))
                {
                    throw new InvalidOperationException("Gateway TLS material is invalid.");
                }

                intermediates.Add(pemCertificates[index]);
            }

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

            if (!leafPolicy(server) || !server.HasPrivateKey ||
                !roots.Cast<X509Certificate2>().Any(root =>
                    BuildChain(server, root, ServerAuthenticationOid, intermediates)))
            {
                throw new InvalidOperationException("Gateway TLS material is invalid.");
            }

            pemCertificates[0].Dispose();
            return new MutualTlsMaterial(roots, server, intermediates, leafPolicy);
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            DisposeAll(roots);
            server?.Dispose();
            DisposeAll(pemCertificates);
            throw new InvalidOperationException("Gateway TLS material is invalid.");
        }
        catch
        {
            DisposeAll(roots);
            server?.Dispose();
            DisposeAll(pemCertificates);
            throw;
        }
    }

    public bool ValidateClientCertificate(
        X509Certificate2? certificate,
        X509Chain? peerChain,
        SslPolicyErrors __) =>
        certificate is not null && leafPolicy(certificate) &&
        trustedRoots.Cast<X509Certificate2>().Any(root =>
            BuildChain(certificate, root, ClientAuthenticationOid,
                peerChain?.ChainElements.Cast<X509ChainElement>()
                    .Skip(1).Select(element => element.Certificate)));

    public void Dispose()
    {
        ServerCertificate.Dispose();
        DisposeAll(trustedRoots);
        DisposeAll(serverChain);
    }

    private static bool IsCertificateAuthority(X509Certificate2 certificate)
    {
        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        return constraints?.CertificateAuthority == true && usage is not null &&
            (usage.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0;
    }

    private static bool BuildChain(X509Certificate2 certificate, X509Certificate2 root,
        string purposeOid, IEnumerable<X509Certificate2>? intermediates = null)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(purposeOid));
        if (intermediates is not null)
        {
            foreach (var intermediate in intermediates)
            {
                chain.ChainPolicy.ExtraStore.Add(intermediate);
            }
        }

        return chain.Build(certificate) &&
            chain.ChainElements.Count is >= 2 and <= 5 &&
            chain.ChainElements[^1].Certificate.RawData.AsSpan().SequenceEqual(root.RawData);
    }

    private static void DisposeAll(X509Certificate2Collection certificates)
    {
        foreach (var certificate in certificates) { certificate.Dispose(); }
    }
}
