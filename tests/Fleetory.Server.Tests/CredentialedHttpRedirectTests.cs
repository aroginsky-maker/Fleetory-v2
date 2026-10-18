using System.Net;
using System.Net.Sockets;
using System.Text;
using Fleetory.Platform.Audit;
using Fleetory.Platform.Contracts;
using Fleetory.Platform.Secrets;
using Fleetory.SharedKernel;

namespace Fleetory.Server.Tests;

public sealed class CredentialedHttpRedirectTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Secret_and_audit_clients_refuse_redirects_with_default_http_handler(
        bool auditClient)
    {
        using var origin = new TcpListener(IPAddress.Loopback, 0);
        using var destination = new TcpListener(IPAddress.Loopback, 0);
        origin.Start();
        destination.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var destinationPort = ((IPEndPoint)destination.LocalEndpoint).Port;
        var originPort = ((IPEndPoint)origin.LocalEndpoint).Port;
        var redirect = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:" +
            destinationPort + "/capture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        var originRequest = ReplyOnceAsync(origin, redirect, timeout.Token);
        var redirectedRequest = ReplyOnceAsync(destination,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            timeout.Token);
        var address = new Uri($"http://127.0.0.1:{originPort}/");

        if (auditClient)
        {
            using var sink = new ImmudbAuditExportSink(address, "writer", "password",
                allowInsecureLoopback: true);
            var now = DateTimeOffset.UtcNow;
            var auditEvent = new AuditExportEvent(Guid.NewGuid(), new AuditRecord(
                new ActorReference("person:test", ActorKind.Person), "test.action",
                null, new CorrelationId("redirect-test"), now), now);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await sink.PublishAsync(auditEvent, timeout.Token));
        }
        else
        {
            using var provider = new OpenBaoSecretProvider(address, "test-token",
                allowInsecureLoopback: true);
            Assert.Throws<InvalidOperationException>(() =>
                provider.GetRequiredSecret("fleetory-postgresql"));
        }

        var request = await originRequest;
        Assert.Contains(auditClient ? "POST /api/login" :
            "GET /v1/secret/data/fleetory/fleetory-postgresql", request,
            StringComparison.Ordinal);
        Assert.False(redirectedRequest.IsCompletedSuccessfully);
        await timeout.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await redirectedRequest);
    }

    private static async Task<string> ReplyOnceAsync(TcpListener listener,
        string response, CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        var stream = client.GetStream();
        var buffer = new byte[4096];
        var count = await stream.ReadAsync(buffer, cancellationToken);
        var request = Encoding.ASCII.GetString(buffer, 0, count);
        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
        return request;
    }
}
