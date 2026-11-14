using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.AdminLogin;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Fleetory.Server.Tests;

public sealed class AdminApiProbeTests
{
    [Theory]
    [InlineData(200)]
    [InlineData(404)]
    public async Task Authenticated_read_accepts_only_expected_status_without_reading_body(int status)
    {
        using var material=new Pki();
        await using var server=await TlsServer.StartAsync(material,status);
        using var probe=material.Probe(server.Origin);
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Assert.Equal(status,await probe.RunAsync("synthetic-bearer",timeout.Token));
        Assert.Equal(1,server.Requests);
        Assert.True(server.ValidatedPeer);
        Assert.Equal($"/admin/authorization/roles/{material.Role:D}/versions",server.Path);
        Assert.Equal("Bearer synthetic-bearer",server.Authorization);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(302)]
    public async Task Denial_or_redirect_fails_even_with_valid_mtls(int status)
    {
        using var material=new Pki();
        await using var server=await TlsServer.StartAsync(material,status);
        using var probe=material.Probe(server.Origin);
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAnyAsync<Exception>(()=>probe.RunAsync("synthetic-bearer",timeout.Token));
        Assert.True(server.ValidatedPeer);
        Assert.Equal(1,server.Requests);
    }

    [Theory]
    [InlineData("person")]
    [InlineData("key")]
    [InlineData("ca-client")]
    [InlineData("expired")]
    public void Invalid_client_material_is_rejected_before_request(string mutation)
    {
        using var material=new Pki();
        using var foreign=new Pki();
        var cert=mutation=="ca-client" ? material.Issue(true,true,"client",material.Person) :
            mutation=="expired" ? material.Issue(true,false,"client",material.Person,expired:true) : material.Client;
        try
        {
            Assert.ThrowsAny<Exception>(()=>new AdminApiProbe(new Uri("https://localhost:15444"),
                mutation=="person" ? Guid.NewGuid() : material.Person,material.Role,material.Root.ExportCertificatePem(),
                cert.ExportCertificatePem(),Pki.PrivateKey(mutation=="key" ? foreign.Client : cert)));
        }
        finally { if (!ReferenceEquals(cert,material.Client)) cert.Dispose(); }
    }

    [Theory]
    [InlineData("root")]
    [InlineData("hostname")]
    public async Task Server_identity_must_match_approved_root_and_localhost(string mutation)
    {
        using var material=new Pki();
        using var foreign=new Pki();
        using var serverCert=mutation=="root" ? foreign.Issue(false,false,"localhost",Guid.Empty) :
            material.Issue(false,false,"foreign.invalid",Guid.Empty);
        await using var server=await TlsServer.StartAsync(material,200,serverCert);
        using var probe=material.Probe(server.Origin);
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAnyAsync<Exception>(()=>probe.RunAsync("synthetic-bearer",timeout.Token));
        Assert.Equal(0,server.Requests);
    }

    [Fact]
    public async Task Tls_peer_fingerprint_is_actually_enforced_by_server()
    {
        using var material=new Pki();
        await using var server=await TlsServer.StartAsync(material,200);
        using var otherClient=material.Issue(true,false,"other",material.Person);
        using var probe=new AdminApiProbe(server.Origin,material.Person,material.Role,
            material.Root.ExportCertificatePem(),otherClient.ExportCertificatePem(),Pki.PrivateKey(otherClient));
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAnyAsync<Exception>(()=>probe.RunAsync("synthetic-bearer",timeout.Token));
        Assert.False(server.ValidatedPeer);
        Assert.Equal(0,server.Requests);
    }

    private sealed class Pki : IDisposable
    {
        public Guid Person {get;}=Guid.NewGuid();
        public Guid Role {get;}=Guid.NewGuid();
        public X509Certificate2 Root {get;}
        public X509Certificate2 Client {get;}
        public X509Certificate2 Server {get;}
        public Pki()
        {
            using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request=new CertificateRequest("CN=Probe test root",key,HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
            Root=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-2),DateTimeOffset.UtcNow.AddYears(2));
            Client=Issue(true,false,"client",Person);
            Server=Issue(false,false,"localhost",Guid.Empty);
        }
        public X509Certificate2 Issue(bool client,bool ca,string name,Guid person,bool expired=false)
        {
            using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request=new CertificateRequest($"CN={name}",key,HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca,false,0,true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature|
                (ca ? X509KeyUsageFlags.KeyCertSign : X509KeyUsageFlags.None),true));
            var usages=new OidCollection {new(client ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1")};
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages,true));
            var san=new SubjectAlternativeNameBuilder();
            if (client) san.AddUri(new Uri($"urn:fleetory:admin:{person:D}")); else san.AddDnsName(name);
            request.CertificateExtensions.Add(san.Build());
            var now=DateTimeOffset.UtcNow;
            using var bare=request.Create(Root,now.AddDays(-2),expired ? now.AddDays(-1) : now.AddDays(2),RandomNumberGenerator.GetBytes(16));
            using var withKey=bare.CopyWithPrivateKey(key);
            // Match existing gateway fixtures: Schannel requires a user key container.
            var pkcs12=withKey.Export(X509ContentType.Pkcs12);
            try {return X509CertificateLoader.LoadPkcs12(pkcs12,null,X509KeyStorageFlags.UserKeySet|X509KeyStorageFlags.Exportable);}
            finally {CryptographicOperations.ZeroMemory(pkcs12);}
        }
        public static string PrivateKey(X509Certificate2 certificate)
        {using var key=certificate.GetECDsaPrivateKey()!;return key.ExportPkcs8PrivateKeyPem();}
        public AdminApiProbe Probe(Uri origin)=>new(origin,Person,Role,Root.ExportCertificatePem(),Client.ExportCertificatePem(),PrivateKey(Client));
        public void Dispose() {Server.Dispose();Client.Dispose();Root.Dispose();}
    }

    private sealed class TlsServer : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly TaskCompletionSource _releaseBody=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Uri Origin {get;private set;}=null!;
        public bool ValidatedPeer {get;private set;}
        public int Requests {get;private set;}
        public string? Path {get;private set;}
        public string? Authorization {get;private set;}
        private TlsServer(WebApplication app) {_app=app;}
        public static async Task<TlsServer> StartAsync(Pki material,int status,X509Certificate2? serverCertificate=null)
        {
            TlsServer? instance=null;
            var builder=WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options=>options.Listen(IPAddress.Loopback,0,listen=>listen.UseHttps(https=>
            {
                https.ServerCertificate=serverCertificate??material.Server;
                https.ClientCertificateMode=ClientCertificateMode.RequireCertificate;
                https.ClientCertificateValidation=(certificate,_,_)=>
                {
                    using var chain=new X509Chain();
                    chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(material.Root);
                    chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;
                    chain.ChainPolicy.DisableCertificateDownloads=true;
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
                    var allowed=chain.Build(certificate)&&certificate.RawData.AsSpan().SequenceEqual(material.Client.RawData);
                    instance!.ValidatedPeer=allowed;
                    return allowed;
                };
            })));
            var app=builder.Build();
            instance=new TlsServer(app);
            app.Run(async context=>
            {
                instance.Requests++;
                instance.Path=context.Request.Path;
                instance.Authorization=context.Request.Headers.Authorization;
                Assert.Equal("GET",context.Request.Method);
                context.Response.StatusCode=status;
                if (status==302) context.Response.Headers.Location="https://untrusted.invalid/";
                // A declared large body that never completes proves the probe needs headers only.
                context.Response.ContentLength=1024*1024;
                await context.Response.StartAsync();
                await context.Response.Body.FlushAsync();
                try {await instance._releaseBody.Task.WaitAsync(context.RequestAborted);}
                catch (OperationCanceledException) { }
            });
            await app.StartAsync();
            var address=app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            instance.Origin=new UriBuilder(address) {Host="localhost"}.Uri;
            return instance;
        }
        public async ValueTask DisposeAsync()
        {
            _releaseBody.TrySetResult();
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try {await _app.StopAsync(timeout.Token);} finally {await _app.DisposeAsync();}
        }
    }
}
