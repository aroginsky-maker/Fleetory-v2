using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
using Fleetory.Core.Persistence;
using Fleetory.Core.Security;
using Fleetory.Platform.Contracts;
using Fleetory.Server;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class AgentGatewayTlsTests(PostgreSqlTestFixture fixture)
{
    [Fact]
    public void Admin_gateway_rejects_reuse_of_the_agent_root_ca()
    {
        using var pki = new TestPki(new DeviceId(Guid.NewGuid()));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("agent-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("agent-gateway-server-cert", pki.Server.ExportCertificatePem());
        secrets.Write("agent-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());
        secrets.Write("admin-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", pki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());

        var exception = Assert.Throws<InvalidOperationException>(() => FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            "--Fleetory:AdminGateway:Enabled=true",
            "--Fleetory:Web:Port=45101",
            "--Fleetory:AgentGateway:Port=45102",
            "--Fleetory:AdminGateway:Port=45103"
        ]));
        Assert.Contains("separate root CAs", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Separate_admin_mtls_listener_revokes_a_bound_agent_certificate()
    {
        var deviceId = new DeviceId(Guid.NewGuid());
        var adminId = Guid.NewGuid();
        using var agentPki = new TestPki(deviceId);
        using var adminPki = new TestPki(
            new Uri($"urn:fleetory:admin:{adminId:D}"),
            new Uri($"urn:fleetory:admin:{Guid.NewGuid():D}"));
        using var secrets = new TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("agent-gateway-root-ca", agentPki.Root.ExportCertificatePem());
        secrets.Write("agent-gateway-server-cert", agentPki.Server.ExportCertificatePem());
        secrets.Write("agent-gateway-server-key", agentPki.ServerKey.ExportPkcs8PrivateKeyPem());
        secrets.Write("admin-gateway-root-ca", adminPki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", adminPki.Server.ExportCertificatePem());
        secrets.Write("admin-gateway-server-key", adminPki.ServerKey.ExportPkcs8PrivateKeyPem());

        var ports = Enumerable.Range(0, 3).Select(_ => GetFreePort()).ToArray();
        while (ports.Distinct().Count() != ports.Length)
        {
            ports = Enumerable.Range(0, 3).Select(_ => GetFreePort()).ToArray();
        }

        await using var app = FleetoryApplication.Build([
            "--environment=Development",
            $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AgentGateway:Enabled=true",
            "--Fleetory:AdminGateway:Enabled=true",
            $"--Fleetory:Web:Port={ports[0]}",
            $"--Fleetory:AgentGateway:Port={ports[1]}",
            $"--Fleetory:AdminGateway:Port={ports[2]}"
        ]);

        await using (var scope = fixture.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<CoreDbContext>();
            database.Devices.Add(DeviceRecord.Create(deviceId, "admin gateway test device", DateTimeOffset.UtcNow));
            database.AgentCertificates.Add(AgentCertificateRecord.Create(
                deviceId, Convert.ToHexString(SHA256.HashData(agentPki.Client.RawData)),
                agentPki.Client.NotBefore.ToUniversalTime(),
                agentPki.Client.NotAfter.ToUniversalTime()));
            await database.SaveChangesAsync();
        }

        await GrantAdminRevocationAsync(adminId);
        await app.StartAsync();
        try
        {
            using var agent = agentPki.CreateClient(agentPki.Client);
            using var admin = adminPki.CreateClient(adminPki.Client);
            using var ungranted = adminPki.CreateClient(adminPki.UnregisteredClient);
            using var wrongCa = agentPki.CreateClient(agentPki.Client);
            using var web = new HttpClient();
            var agentUrl = $"https://127.0.0.1:{ports[1]}/agent/identity";
            var revokePath = $"/admin/devices/{deviceId.Value:D}/certificates/" +
                Convert.ToHexString(SHA256.HashData(agentPki.Client.RawData)) + "/revoke";
            var adminUrl = $"https://127.0.0.1:{ports[2]}{revokePath}";

            using var before = await agent.GetAsync(agentUrl);
            Assert.Equal(HttpStatusCode.NoContent, before.StatusCode);
            using var webAttempt = await web.PostAsync($"http://127.0.0.1:{ports[0]}{revokePath}", null);
            Assert.Equal(HttpStatusCode.NotFound, webAttempt.StatusCode);
            using var agentAttempt = await agent.PostAsync(
                $"https://127.0.0.1:{ports[1]}{revokePath}", null);
            Assert.Equal(HttpStatusCode.NotFound, agentAttempt.StatusCode);
            using var denied = await ungranted.PostAsync(adminUrl, null);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            using var invalidIdentity = adminPki.CreateClient(adminPki.MalformedIdentityClient);
            using var invalid = await invalidIdentity.PostAsync(adminUrl, null);
            Assert.Equal(HttpStatusCode.Forbidden, invalid.StatusCode);
            await Assert.ThrowsAsync<HttpRequestException>(async () =>
                await wrongCa.PostAsync(adminUrl, null));
            using var noCertificate = adminPki.CreateClient();
            await Assert.ThrowsAsync<HttpRequestException>(async () =>
                await noCertificate.PostAsync(adminUrl, null));

            var correlation = Guid.NewGuid().ToString("N");
            using var request = new HttpRequestMessage(HttpMethod.Post, adminUrl);
            request.Headers.Add("X-Correlation-ID", correlation);
            using var revoked = await admin.SendAsync(request);
            Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);
            using var after = await agent.GetAsync(agentUrl);
            Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
            using var adminHealth = await admin.GetAsync($"https://127.0.0.1:{ports[2]}/health/live");
            Assert.Equal(HttpStatusCode.NotFound, adminHealth.StatusCode);
            Assert.Equal(2, await CountRevocationAuditAsync(correlation));
        }
        finally
        {
            await app.StopAsync();
        }
    }

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

    private async Task GrantAdminRevocationAsync(Guid adminId)
    {
        var roleId = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.authorization_roles (role_id, name)
            VALUES (@role_id, @name);
            INSERT INTO platform.authorization_role_permissions (role_id, permission)
            VALUES (@role_id, @permission);
            INSERT INTO platform.authorization_assignments
                (assignment_id, actor_subject_id, actor_kind, role_id, scope_id)
            VALUES (@assignment_id, @actor_subject_id, @actor_kind, @role_id, NULL);
            """, connection);
        command.Parameters.AddWithValue("role_id", roleId);
        command.Parameters.AddWithValue("name", $"Admin Gateway {roleId:N}");
        command.Parameters.AddWithValue("permission", AgentCertificateRevocationService.Permission);
        command.Parameters.AddWithValue("assignment_id", Guid.NewGuid());
        command.Parameters.AddWithValue("actor_subject_id", $"person:{adminId:N}");
        command.Parameters.AddWithValue("actor_kind", (int)ActorKind.Person);
        await command.ExecuteNonQueryAsync();
    }

    private async Task<int> CountRevocationAuditAsync(string correlation)
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT count(*) FROM platform.audit_events
            WHERE correlation_id = @correlation_id
              AND action IN ('core.agent_certificate.revoke_requested',
                             'core.agent_certificate.revoke_completed')
            """, connection);
        command.Parameters.AddWithValue("correlation_id", correlation);
        return Convert.ToInt32(await command.ExecuteScalarAsync());
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
            : this(new Uri($"urn:fleetory:device:{deviceId.Value:D}"))
        {
        }

        public TestPki(Uri clientUri, Uri? unregisteredUri = null)
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
                san => san.AddUri(clientUri));
            UnregisteredClient = Issue("CN=Fleetory Unknown Agent", unregisteredKey,
                "1.3.6.1.5.5.7.3.2", now,
                san => san.AddUri(unregisteredUri ?? clientUri));
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
