using System.Net;
using System.Text;
using System.Text.Json;
using Fleetory.Platform.Audit;
using Fleetory.Platform.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Platform.Tests;

public sealed class ImmudbAuditExportSinkTests
{
    [Fact]
    public async Task Repeated_delivery_reads_the_same_single_revision_and_rejects_a_conflict()
    {
        using var handler = new ImmudbHandler();
        using var sink = new ImmudbAuditExportSink(new Uri("https://audit.example/"),
            "audit-writer", "private-password", handler: handler);
        var eventId = Guid.NewGuid();
        var occurredAt = DateTimeOffset.UtcNow;
        var auditEvent = NewEvent(eventId, "Core.Device.Read", occurredAt);

        await sink.PublishAsync(auditEvent);
        await sink.PublishAsync(auditEvent);
        Assert.Equal(2, handler.WriteAttempts);
        Assert.Equal(1, handler.CommittedWrites);

        var conflict = NewEvent(eventId, "Core.Device.Delete", occurredAt);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await sink.PublishAsync(conflict));
        Assert.DoesNotContain("private-password", exception.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, handler.CommittedWrites);
    }

    [Fact]
    public async Task Uncertain_write_is_retried_without_creating_a_second_revision()
    {
        using var handler = new ImmudbHandler { WriteResponseFailuresRemaining = 1 };
        using var sink = new ImmudbAuditExportSink(new Uri("https://audit.example/"),
            "audit-writer", "private-password", handler: handler);
        var auditEvent = NewEvent(Guid.NewGuid(), "Core.Device.Read", DateTimeOffset.UtcNow);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await sink.PublishAsync(auditEvent));
        Assert.Equal(1, handler.CommittedWrites);

        await sink.PublishAsync(auditEvent);
        Assert.Equal(2, handler.WriteAttempts);
        Assert.Equal(1, handler.CommittedWrites);
    }

    [Fact]
    public async Task Refuses_bad_authentication_or_modified_revision()
    {
        using var handler = new ImmudbHandler { LoginForbidden = true };
        using var sink = new ImmudbAuditExportSink(new Uri("https://audit.example/"),
            "audit-writer", "private-password", handler: handler);
        var auditEvent = NewEvent(Guid.NewGuid(), "Core.Device.Read", DateTimeOffset.UtcNow);

        var authError = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await sink.PublishAsync(auditEvent));
        Assert.DoesNotContain("private-password", authError.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, handler.WriteAttempts);

        handler.LoginForbidden = false;
        handler.StoredRevision = "2";
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await sink.PublishAsync(auditEvent));
        Assert.Equal(1, handler.CommittedWrites);
    }

    [Theory]
    [InlineData("http://audit.example/")]
    [InlineData("http://127.0.0.1:8090/other")]
    [InlineData("https://audit.example/path")]
    public void Rejects_insecure_or_non_origin_address(string address)
    {
        Assert.Throws<ArgumentException>(() => new ImmudbAuditExportSink(
            new Uri(address), "writer", "password", allowInsecureLoopback: true));
    }

    private static AuditExportEvent NewEvent(Guid eventId, string action, DateTimeOffset occurredAt) =>
        new(eventId, new AuditRecord(
            new ActorReference("person:demo", ActorKind.Person), action,
            new AuditTarget("Device", "device-1"), new CorrelationId("correlation-1"),
            occurredAt, new Dictionary<string, string> { ["Decision"] = "Allowed" }),
            occurredAt.AddMilliseconds(1));

    private sealed class ImmudbHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
        public bool LoginForbidden { get; set; }
        public int WriteResponseFailuresRemaining { get; set; }
        public string StoredRevision { get; set; } = "1";
        public int WriteAttempts { get; private set; }
        public int CommittedWrites { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.DoesNotContain("private-password", request.RequestUri!.ToString(),
                StringComparison.Ordinal);
            if (request.RequestUri.AbsolutePath == "/api/login")
            {
                if (LoginForbidden)
                {
                    return Json(HttpStatusCode.Unauthorized, "{\"error\":\"bad credentials\"}");
                }

                using var login = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
                var password = Encoding.UTF8.GetString(Convert.FromBase64String(
                    login.RootElement.GetProperty("password").GetString()!));
                Assert.Equal("private-password", password);
                return Json(HttpStatusCode.OK, "{\"token\":\"test-token\"}");
            }

            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal("test-token", request.Headers.Authorization?.Parameter);
            if (request.RequestUri.AbsolutePath == "/api/db/set")
            {
                WriteAttempts++;
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
                var entry = body.RootElement.GetProperty("KVs")[0];
                var key = entry.GetProperty("key").GetString()!;
                var value = entry.GetProperty("value").GetString()!;
                Assert.Equal(key, body.RootElement.GetProperty("preconditions")[0]
                    .GetProperty("keyMustNotExist").GetProperty("key").GetString());
                if (_values.TryAdd(key, value))
                {
                    CommittedWrites++;
                    if (WriteResponseFailuresRemaining > 0)
                    {
                        WriteResponseFailuresRemaining--;
                        return Json(HttpStatusCode.ServiceUnavailable, "{}");
                    }
                    return Json(HttpStatusCode.OK, "{\"id\":\"1\"}");
                }

                return Json(HttpStatusCode.BadRequest, "{\"error\":\"precondition failed\"}");
            }

            var encoded = request.RequestUri.AbsolutePath["/api/db/get/".Length..];
            var storedKey = Uri.UnescapeDataString(encoded);
            return _values.TryGetValue(storedKey, out var storedValue)
                ? Json(HttpStatusCode.OK, JsonSerializer.Serialize(new
                {
                    key = storedKey, value = storedValue, revision = StoredRevision
                }))
                : Json(HttpStatusCode.NotFound, "{}");
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
            new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }
}
