using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Server;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class AgentGatewayTlsTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public async Task Mutual_tls_accepts_only_a_bound_certificate_on_the_agent_listener()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        using var pki = new TestPki(deviceId);
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("agent-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("agent-gateway-server-cert", pki.Server.ExportCertificatePem());
        secrets.Write("agent-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());

        var webPort = GetFreePort();
        var agentPort = GetFreePort();
        while (webPort == agentPort)
        {
            agentPort = GetFreePort();
        }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AgentGateway:Port={agentPort}"
        ]);
        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
            database.Devices.Add(DeviceRecord.Create(deviceId, "mTLS test device", DateTimeOffset.UtcNow));
            database.AgentCertificates.Add(AgentCertificateRecord.Create(
                deviceId,
                Convert.ToHexString(SHA256.HashData(pki.Client.RawData)),
                pki.Client.NotBefore.ToUniversalTime(),
                pki.Client.NotAfter.ToUniversalTime()));
            await database.SaveChangesAsync();
        }

        await app.StartAsync();
        try
        {
            using var authenticated = pki.CreateClient(pki.Client);
            using var web = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{webPort}") };
            using var agentResponse = await authenticated.GetAsync(
                $"https://127.0.0.1:{agentPort}/agent/identity");
            Assert.Equal(HttpStatusCode.NoContent, agentResponse.StatusCode);
            using var webAgentResponse = await web.GetAsync("/agent/identity");
            using var webHealthResponse = await web.GetAsync("/health/live");
            using var agentHealthResponse = await authenticated.GetAsync(
                $"https://127.0.0.1:{agentPort}/health/live");

            Assert.Equal(HttpStatusCode.NotFound, webAgentResponse.StatusCode);
            Assert.Equal(HttpStatusCode.OK, webHealthResponse.StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, agentHealthResponse.StatusCode);

            await using (var scope = fixture.Services.CreateAsyncScope())
            {
                var database = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
                var fingerprint = Convert.ToHexString(SHA256.HashData(pki.Client.RawData));
                var binding = await database.AgentCertificates.SingleAsync(
                    row => row.CertificateSha256 == fingerprint);
                binding.Revoke(DateTimeOffset.UtcNow);
                await database.SaveChangesAsync();
            }

            using var revokedResponse = await authenticated.GetAsync(
                $"https://127.0.0.1:{agentPort}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, revokedResponse.StatusCode);

            using var unknown = pki.CreateClient(pki.UnregisteredClient);
            using var unknownResponse = await unknown.GetAsync(
                $"https://127.0.0.1:{agentPort}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, unknownResponse.StatusCode);

            using var malformedIdentity = pki.CreateClient(pki.MalformedIdentityClient);
            using var malformedResponse = await malformedIdentity.GetAsync(
                $"https://127.0.0.1:{agentPort}/agent/identity");
            Assert.Equal(HttpStatusCode.Forbidden, malformedResponse.StatusCode);

            using var foreignPki = new TestPki(deviceId);
            using var foreign = pki.CreateClient(foreignPki.Client);
            await Assert.ThrowsAsync<HttpRequestException>(async () =>
                await foreign.GetAsync($"https://127.0.0.1:{agentPort}/agent/identity"));

            using var noCertificate = pki.CreateClient();
            await Assert.ThrowsAsync<HttpRequestException>(async () =>
                await noCertificate.GetAsync($"https://127.0.0.1:{agentPort}/agent/identity"));
        }
        finally
        {
            await app.StopAsync();
        }
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private sealed class TestSecretDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "fleetory-mtls-test-" + Guid.NewGuid().ToString("N"));

        public TestSecretDirectory() => Directory.CreateDirectory(Path);

        public void Write(string name, string value)
        {
            var path = System.IO.Path.Combine(Path, name);
            File.WriteAllText(path, value);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }

        public void Dispose()
        {
            foreach (var file in Directory.GetFiles(Path))
            {
                File.Delete(file);
            }

            Directory.Delete(Path);
        }
    }

    private sealed class TestPki : IDisposable
    {
        private readonly ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa unregisteredKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa malformedIdentityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public TestPki(DeviceId deviceId)
        {
            var now = DateTimeOffset.UtcNow;
            var rootRequest = new CertificateRequest("CN=Fleetory Test CA", rootKey, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            Root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(7));

            ServerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Server = Issue("CN=localhost", ServerKey, "1.3.6.1.5.5.7.3.1", now,
                san => san.AddIpAddress(IPAddress.Loopback));
            Client = Issue("CN=Fleetory Test Agent", clientKey, "1.3.6.1.5.5.7.3.2", now,
                san => san.AddUri(new Uri($"urn:fleetory:device:{deviceId.Value:D}")));
            UnregisteredClient = Issue("CN=Fleetory Unknown Agent", unregisteredKey,
                "1.3.6.1.5.5.7.3.2", now,
                san => san.AddUri(new Uri($"urn:fleetory:device:{deviceId.Value:D}")));
            MalformedIdentityClient = Issue("CN=Fleetory Malformed Agent", malformedIdentityKey,
                "1.3.6.1.5.5.7.3.2", now,
                san => san.AddUri(new Uri("urn:fleetory:device:not-a-guid")));
        }

        public X509Certificate2 Root { get; }
        public X509Certificate2 Server { get; }
        public X509Certificate2 Client { get; }
        public X509Certificate2 UnregisteredClient { get; }
        public X509Certificate2 MalformedIdentityClient { get; }
        public ECDsa ServerKey { get; }

        public HttpClient CreateClient(X509Certificate2? certificate = null)
        {
            var handler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual
            };
            if (certificate is not null)
            {
                handler.ClientCertificates.Add(certificate);
            }

            handler.ServerCertificateCustomValidationCallback = (_, server, _, errors) =>
            {
                if (server is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                {
                    return false;
                }

                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(Root);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(server);
            };
            return new HttpClient(handler);
        }

        public void Dispose()
        {
            UnregisteredClient.Dispose();
            MalformedIdentityClient.Dispose();
            Client.Dispose();
            Server.Dispose();
            ServerKey.Dispose();
            Root.Dispose();
            unregisteredKey.Dispose();
            malformedIdentityKey.Dispose();
            clientKey.Dispose();
            rootKey.Dispose();
        }

        private X509Certificate2 Issue(
            string subject,
            ECDsa key,
            string purpose,
            DateTimeOffset now,
            Action<SubjectAlternativeNameBuilder> configureSan)
        {
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature, true));
            var purposes = new OidCollection { new Oid(purpose) };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(purposes, true));
            var san = new SubjectAlternativeNameBuilder();
            configureSan(san);
            request.CertificateExtensions.Add(san.Build());

            using var publicCertificate = request.Create(
                Root, now.AddHours(-1), now.AddDays(1), Guid.NewGuid().ToByteArray());
            using var withPrivateKey = publicCertificate.CopyWithPrivateKey(key);
            var pkcs12 = withPrivateKey.Export(X509ContentType.Pkcs12);
            try
            {
                return X509CertificateLoader.LoadPkcs12(
                    pkcs12, null, X509KeyStorageFlags.UserKeySet);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs12);
            }
        }
    }
}
