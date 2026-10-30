using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
using Fleetory.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Npgsql;

namespace Fleetory.Persistence.Tests;

[Collection(PostgreSqlTestCollection.Name)]
public sealed class AdminConnectionLifetimeTests(PostgreSqlTestFixture fixture)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Expired_admin_leaf_cannot_authorize_another_request_on_the_same_tls_connection(
        bool expireDuringRegistryRead)
    {
        using var pki = new AgentGatewayTlsTests.TestPki(new DeviceId(Guid.NewGuid()));
        using var secrets = new AgentGatewayTlsTests.TestSecretDirectory();
        secrets.Write("fleetory-postgresql", fixture.ConnectionString);
        secrets.Write("admin-gateway-root-ca", pki.Root.ExportCertificatePem());
        secrets.Write("admin-gateway-server-cert", pki.ServerChainPem);
        secrets.Write("admin-gateway-server-key", pki.ServerKey.ExportPkcs8PrivateKeyPem());
        var webPort = AgentGatewayTlsTests.GetFreePort();
        var adminPort = AgentGatewayTlsTests.GetFreePort();
        while (adminPort == webPort) { adminPort = AgentGatewayTlsTests.GetFreePort(); }
        await using var app = FleetoryApplication.Build([
            "--environment=Development", $"--Fleetory:Secrets:Directory={secrets.Path}",
            "--Fleetory:AdminGateway:Enabled=true", $"--Fleetory:Web:Port={webPort}",
            $"--Fleetory:AdminGateway:Port={adminPort}"
        ]);
        var dispatches = 0;
        app.MapGet("/admin/connection-lifetime-probe", () =>
        {
            Interlocked.Increment(ref dispatches);
            return Results.NoContent();
        });
        await app.StartAsync();
        try
        {
            using var lifetime = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var certificate = ShortLivedAdminCertificate(pki.Root, Guid.NewGuid());
            var connections = 0;
            using var handler = new SocketsHttpHandler { UseProxy = false, MaxConnectionsPerServer = 1 };
            handler.SslOptions.ClientCertificates = new X509CertificateCollection { certificate };
            handler.SslOptions.RemoteCertificateValidationCallback = (_, server, chain, errors) =>
                pki.ValidateServer(server as X509Certificate2, chain, errors);
            handler.ConnectCallback = async (context, cancellationToken) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(context.DnsEndPoint, cancellationToken);
                    Interlocked.Increment(ref connections);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            };
            using var client = new HttpClient(handler)
            {
                DefaultRequestVersion = HttpVersion.Version11,
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact
            };
            var uri = $"https://127.0.0.1:{adminPort}/admin/connection-lifetime-probe";
            using var first = await client.GetAsync(uri, lifetime.Token);
            Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
            using var second = expireDuringRegistryRead
                ? await SendDuringBlockedRegistryReadAsync(client, uri, certificate, lifetime.Token)
                : await SendAfterExpiryAsync(client, uri, certificate, lifetime.Token);
            Assert.Equal(1, connections);
            Assert.Equal(HttpStatusCode.Forbidden, second.StatusCode);
            Assert.Equal(1, dispatches);
            await using var connection = new NpgsqlConnection(fixture.ConnectionString);
            await connection.OpenAsync(lifetime.Token);
            await using var denied = new NpgsqlCommand("""
                SELECT count(*) FROM platform.audit_events AS event
                JOIN platform.audit_export_queue AS queue ON queue.audit_event_id = event.event_id
                WHERE event.action = 'admin.certificate.validity_denied'
                  AND event.target_type = 'admin_certificate' AND event.target_id = @fingerprint
                """, connection);
            denied.Parameters.AddWithValue("fingerprint", certificate.GetCertHashString(HashAlgorithmName.SHA256));
            Assert.Equal(1L, await denied.ExecuteScalarAsync(lifetime.Token));
        }
        finally { await app.StopAsync(); }
    }

    private async Task<HttpResponseMessage> SendDuringBlockedRegistryReadAsync(HttpClient client,
        string uri, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        await using var blocker = new NpgsqlConnection(fixture.ConnectionString);
        await blocker.OpenAsync(cancellationToken);
        await using var transaction = await blocker.BeginTransactionAsync(cancellationToken);
        await using var tableLock = new NpgsqlCommand(
            "LOCK TABLE platform.admin_certificate_registrations IN ACCESS EXCLUSIVE MODE", blocker, transaction);
        await tableLock.ExecuteNonQueryAsync(cancellationToken);
        var pending = client.GetAsync(uri, cancellationToken);
        try
        {
            await using var probe = new NpgsqlCommand("""
                SELECT EXISTS (SELECT 1 FROM pg_locks
                               WHERE relation = 'platform.admin_certificate_registrations'::regclass
                                 AND NOT granted AND pid <> pg_backend_pid())
                """, blocker, transaction);
            while (await probe.ExecuteScalarAsync(cancellationToken) is not true)
            {
                await Task.Delay(20, cancellationToken);
            }
            await WaitForExpiryAsync(certificate, cancellationToken);
        }
        finally { await transaction.RollbackAsync(); }
        return await pending;
    }

    private static async Task<HttpResponseMessage> SendAfterExpiryAsync(HttpClient client,
        string uri, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        await WaitForExpiryAsync(certificate, cancellationToken);
        return await client.GetAsync(uri, cancellationToken);
    }

    private static async Task WaitForExpiryAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        var expiry = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
        while (DateTimeOffset.UtcNow < expiry) { await Task.Delay(100, cancellationToken); }
    }

    private static X509Certificate2 ShortLivedAdminCertificate(X509Certificate2 root, Guid person)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Fleetory short-lived Admin", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri($"urn:fleetory:admin:{person:D}"));
        request.CertificateExtensions.Add(san.Build());
        var now = DateTimeOffset.UtcNow;
        using var leaf = request.Create(root, now.AddMinutes(-1), now.AddSeconds(10),
            RandomNumberGenerator.GetBytes(16));
        using var withPrivateKey = leaf.CopyWithPrivateKey(key);
        return AgentGatewayTlsTests.TestPki.LoadTlsCertificate(withPrivateKey);
    }
}
