using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using Fleetory.CommandSigner.Host;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

namespace Fleetory.Persistence.Tests;

public sealed partial class SigningHostTlsTests
{
    [Fact]
    public async Task A_stalled_tls_handshake_emits_a_bounded_transport_failure_without_signing()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        using var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Loopback, new Uri(lab.Url).Port);
        var audit = await lab.TlsLogs.First.Task.WaitAsync(TimeSpan.FromSeconds(20));
        AssertTlsFailure(audit);
        Assert.True(Convert.ToInt64(audit.Fields["ElapsedMilliseconds"]) >= 4000);
        Assert.Equal(0, lab.TransitCalls);
        Assert.Equal(0L, await lab.CountAsync("signing_requests"));
        Assert.Equal(0L, await lab.CountAsync("signing_rejections"));
    }

    [Fact]
    public async Task Plaintext_on_the_tls_port_is_audited_without_logging_attempted_credentials()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        using var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Loopback, new Uri(lab.Url).Port);
        await socket.GetStream().WriteAsync(Encoding.ASCII.GetBytes(
            "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer private-sentinel\r\n\r\n"));
        var audit = await lab.TlsLogs.First.Task.WaitAsync(TimeSpan.FromSeconds(15));
        AssertTlsFailure(audit);
        Assert.DoesNotContain("private-sentinel", JsonSerializer.Serialize(audit.Fields));
        Assert.Equal(0, lab.TransitCalls);
        Assert.Equal(0L, await lab.CountAsync("signing_rejections"));
    }

    [Fact]
    public async Task Successful_tls_followed_by_http_denial_is_not_misclassified_as_a_handshake_failure()
    {
        await using var lab = await HostLab.CreateAsync(fixture);
        using (var client = lab.Pki.CreateClient(lab.Pki.Client))
        using (var denied = await client.PostAsJsonAsync(lab.Url + "/signing/inventory-refresh", new { }))
        {
            Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
            Assert.True(denied.Headers.Contains("X-Fleetory-Audit-Id"));
        }
        await lab.StopHostAsync();
        Assert.Empty(lab.TlsLogs.Records);
        Assert.Equal(1L, await lab.CountAsync("signing_rejections"));
    }

    [Fact]
    public async Task Disabling_generic_logging_does_not_disable_tls_security_audit()
    {
        await using var lab = await HostLab.CreateAsync(fixture, quiet: true);
        using var client = lab.Pki.CreateClient(null);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(lab.Url + "/health/live"));
        AssertTlsFailure(await lab.TlsLogs.First.Task.WaitAsync(TimeSpan.FromSeconds(15)));
    }

    [Theory]
    [InlineData("valid", "conn-42", "127.0.0.1", 4321)]
    [InlineData("unsafe-id", "invalid", "127.0.0.1", 4321)]
    [InlineData("long-id", "invalid", "127.0.0.1", 4321)]
    [InlineData("empty-id", "invalid", "127.0.0.1", 4321)]
    [InlineData("dns-peer", "conn-42", "unknown", 0)]
    public async Task Audit_uses_only_sanitized_transport_metadata_and_never_exception_text(
        string kind, string expectedId, string expectedAddress, int expectedPort)
    {
        using var collector = new TlsLogCollector();
        using var factory = LoggerFactory.Create(builder => builder.AddProvider(collector));
        var audit = new SigningTlsHandshakeAudit(factory.CreateLogger<SigningTlsHandshakeAudit>());
        await using var connection = new DefaultConnectionContext
        {
            ConnectionId = kind switch
            {
                "unsafe-id" => "\nprivate-sentinel", "long-id" => new string('a', 65), "empty-id" => "", _ => "conn-42"
            },
            RemoteEndPoint = kind == "dns-peer" ? new DnsEndPoint("private-sentinel", 123) : new IPEndPoint(IPAddress.Loopback, 4321)
        };
        await Assert.ThrowsAsync<AuthenticationException>(() => audit.ObserveAsync(connection,
            _ => throw new AuthenticationException("private-sentinel")));
        var record = Assert.Single(collector.Records);
        Assert.Equal(expectedId, record.Fields["ConnectionId"]);
        Assert.Equal(expectedAddress, record.Fields["RemoteAddress"]);
        Assert.Equal(expectedPort, record.Fields["RemotePort"]);
        Assert.Null(record.Exception);
        Assert.DoesNotContain("private-sentinel", record.Message);
        Assert.DoesNotContain("private-sentinel", JsonSerializer.Serialize(record.Fields));
    }

    private static void AssertTlsFailure(TlsAuditRecord audit)
    {
        Assert.Equal(SigningTlsHandshakeAudit.FailureEvent, audit.EventId);
        Assert.Equal(LogLevel.Warning, audit.Level);
        Assert.Equal("fleetory.signer-tls-failure.v1", audit.Fields["Schema"]);
        Assert.Equal("TlsNotEstablished", audit.Fields["Reason"]);
        Assert.NotEqual(Guid.Empty, Assert.IsType<Guid>(audit.Fields["AuditEventId"]));
        Assert.Equal(TimeSpan.Zero, DateTimeOffset.Parse(Assert.IsType<string>(audit.Fields["ObservedAt"]),
            System.Globalization.CultureInfo.InvariantCulture).Offset);
        Assert.NotEmpty(Assert.IsType<string>(audit.Fields["ConnectionId"]));
        Assert.Equal("127.0.0.1", audit.Fields["RemoteAddress"]);
        Assert.True(Convert.ToInt32(audit.Fields["RemotePort"]) > 0);
        Assert.True(Convert.ToInt64(audit.Fields["ElapsedMilliseconds"]) >= 0);
        Assert.Null(audit.Exception);
        Assert.DoesNotContain("disposable-host-token", audit.Message);
        Assert.DoesNotContain("PRIVATE KEY", audit.Message);
    }

    private sealed record TlsAuditRecord(EventId EventId, LogLevel Level,
        IReadOnlyDictionary<string, object?> Fields, string Message, Exception? Exception);

    private sealed class TlsLogCollector : ILoggerProvider
    {
        public ConcurrentQueue<TlsAuditRecord> Records { get; } = new();
        public TaskCompletionSource<TlsAuditRecord> First { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ILogger CreateLogger(string categoryName) => new CaptureLogger(this, categoryName);
        public void Dispose() { }

        private sealed class CaptureLogger(TlsLogCollector owner, string category) : ILogger
        {
            public bool IsEnabled(LogLevel logLevel) => category == typeof(SigningTlsHandshakeAudit).FullName && logLevel >= LogLevel.Warning;
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (!IsEnabled(logLevel)) { return; }
                var fields = Assert.IsType<IEnumerable<KeyValuePair<string, object?>>>(state, exactMatch: false).ToDictionary();
                var record = new TlsAuditRecord(eventId, logLevel, fields, formatter(state, exception), exception);
                owner.Records.Enqueue(record);
                owner.First.TrySetResult(record);
            }
        }
    }
}
