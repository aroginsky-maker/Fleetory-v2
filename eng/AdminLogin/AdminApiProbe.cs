using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Platform.Contracts;
using Fleetory.Core.Contracts;
namespace Fleetory.AdminLogin;

/// <summary>One audited read-only request; no response data or bearer token is retained.</summary>
public sealed class AdminApiProbe : IDisposable
{
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _leaf;
    private readonly HttpClient _http;
    private readonly Uri _origin;
    private readonly Guid _role;

    public AdminApiProbe(Uri origin, Guid person, Guid role, string rootPem, string leafPem, string keyPem)
    {
        if (!origin.IsAbsoluteUri || origin.Scheme != "https" || origin.Host != "localhost" ||
            origin.Port is < 1024 or > 65535 || origin.AbsolutePath != "/" ||
            origin.Query.Length != 0 || origin.Fragment.Length != 0 || origin.UserInfo.Length != 0 ||
            person == Guid.Empty || role == Guid.Empty) throw new InvalidOperationException("Invalid Admin probe profile.");
        _origin = origin; _role = role;
        _root = X509Certificate2.CreateFromPem(rootPem);
        try
        {
            _leaf = LoadClient(leafPem, keyPem);
            try
            {
                var ca = _root.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
                if (ca?.CertificateAuthority != true || !_leaf.HasPrivateKey ||
                    !X509EndEntityPolicy.HasDigitalSignatureUsage(_leaf) ||
                    !(_leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault()?.EnhancedKeyUsages
                        .Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2") ?? false) ||
                    !AdminCertificateIdentity.TryReadActor(_leaf, out var actor) ||
                    actor!.SubjectId != $"person:{person:N}" || !BuildChain(_leaf, "1.3.6.1.5.5.7.3.2"))
                    throw new InvalidOperationException("Invalid Admin client material.");
                var handler = new HttpClientHandler
                {
                    AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
                    UseDefaultCredentials = false, ClientCertificateOptions = ClientCertificateOption.Manual
                };
                handler.ClientCertificates.Add(_leaf);
                handler.ServerCertificateCustomValidationCallback = (_, server, peerChain, errors) =>
                    server is not null && X509EndEntityPolicy.HasDigitalSignatureUsage(server) &&
                    (errors & (SslPolicyErrors.RemoteCertificateNameMismatch |
                    SslPolicyErrors.RemoteCertificateNotAvailable)) == 0 && BuildChain(server, "1.3.6.1.5.5.7.3.1", peerChain?.ChainElements.Cast<X509ChainElement>()
                        .Skip(1).Select(element => element.Certificate));
                _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            }
            catch { _leaf.Dispose(); throw; }
        }
        catch { _root.Dispose(); throw; }
    }

    public async Task<int> RunAsync(string accessToken, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(accessToken) || accessToken.Length > 16384 || accessToken.Any(char.IsControl))
            throw new InvalidOperationException("Invalid bearer material.");
        using var request = new HttpRequestMessage(HttpMethod.Get,
            new Uri(_origin, $"admin/authorization/roles/{_role:D}/versions"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        // An approved manager's absent sentinel is 404; an existing role may return 200.
        // The authenticated endpoint authorizes before either result. Never display its body.
        if (response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.NotFound))
            throw new InvalidOperationException("Admin authorization probe was denied.");
        cancellationToken.ThrowIfCancellationRequested();
        return (int)response.StatusCode;
    }

    private static X509Certificate2 LoadClient(string certificatePem, string keyPem)
    {
        using var pem = X509Certificate2.CreateFromPem(certificatePem, keyPem);
        if (!OperatingSystem.IsWindows())
            return X509Certificate2.CreateFromPem(certificatePem, keyPem);
        // Schannel requires a user key container rather than a PEM ephemeral key.
        // Without PersistKeySet the import owns its temporary container; Dispose removes it.
        var pfx = pem.Export(X509ContentType.Pfx);
        try { return X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet); }
        finally { CryptographicOperations.ZeroMemory(pfx); }
    }
    private bool BuildChain(X509Certificate2 certificate, string purpose, IEnumerable<X509Certificate2>? intermediates = null)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(purpose));
        if (intermediates is not null)
            foreach (var intermediate in intermediates) chain.ChainPolicy.ExtraStore.Add(intermediate);
        return chain.Build(certificate) && chain.ChainElements.Count is >= 2 and <= 5 &&
            chain.ChainElements[^1].Certificate.RawData.AsSpan().SequenceEqual(_root.RawData);
    }

    public void Dispose() { _http.Dispose(); _leaf.Dispose(); _root.Dispose(); }
}
