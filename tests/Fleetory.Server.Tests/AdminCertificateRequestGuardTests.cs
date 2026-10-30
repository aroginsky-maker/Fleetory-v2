using System.Data.Common;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Platform.Contracts;
using Fleetory.Server.Infrastructure;
using Fleetory.SharedKernel;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Fleetory.Server.Tests;

public sealed class AdminCertificateRequestGuardTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
    private static readonly ActorReference Actor = new("person:05d409dcf03c497ca0d743cc095e8fe5", ActorKind.Person);

    [Theory]
    [InlineData(-61, false)]
    [InlineData(-60, true)]
    [InlineData(59, true)]
    [InlineData(60, false)]
    public async Task Admin_leaf_uses_exact_current_window_and_audits_denial(int seconds, bool expected)
    {
        using var test = new RequestFixture();
        test.Clock.UtcNow = Now.AddSeconds(seconds);
        Assert.Equal(expected, await test.CheckAsync());
        if (expected) { Assert.Empty(test.Audit.Records); }
        else
        {
            Assert.Equal(StatusCodes.Status403Forbidden, test.Context.Response.StatusCode);
            var denied = Assert.Single(test.Audit.Records);
            Assert.Equal("admin.certificate.validity_denied", denied.Action);
            Assert.Equal(Actor, denied.Actor);
            Assert.Equal(test.Fingerprint, denied.Target?.Id);
            Assert.Equal(test.Clock.UtcNow, denied.OccurredAt);
        }
    }

    [Fact]
    public async Task The_same_leaf_is_rechecked_when_the_clock_moves_between_checks()
    {
        using var test = new RequestFixture();
        Assert.True(await test.CheckAsync());
        test.Clock.UtcNow = Now.AddMinutes(1);
        Assert.False(await test.CheckAsync());
        Assert.Single(test.Audit.Records);
    }

    [Fact]
    public async Task Audit_failure_prevents_admission()
    {
        using var test = new RequestFixture();
        test.Clock.UtcNow = Now.AddMinutes(1);
        test.Audit.Fail = true;
        await Assert.ThrowsAsync<InvalidOperationException>(test.CheckAsync);
    }

    [Fact]
    public async Task Cancelled_request_is_not_admitted()
    {
        using var test = new RequestFixture();
        using var lifetime = new CancellationTokenSource();
        await lifetime.CancelAsync();
        test.Context.RequestAborted = lifetime.Token;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(test.CheckAsync);
        Assert.Empty(test.Audit.Records);
    }

    private sealed class MutableClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = Now;
    }

    private sealed class MemoryAudit : IAuditWriter
    {
        public List<AuditRecord> Records { get; } = [];
        public bool Fail { get; set; }

        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken = default)
        {
            if (Fail) { throw new InvalidOperationException("Audit unavailable."); }
            Records.Add(record);
            return ValueTask.CompletedTask;
        }

        public ValueTask WriteInTransactionAsync(AuditRecord record, DbTransaction transaction,
            CancellationToken cancellationToken = default) => throw new InvalidOperationException("Unexpected transaction.");
    }

    private sealed class RequestFixture : IDisposable
    {
        private readonly ServiceProvider _services;
        private readonly X509Certificate2 _certificate;

        public RequestFixture()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            _certificate = new CertificateRequest("CN=Admin window test", key, HashAlgorithmName.SHA256)
                .CreateSelfSigned(Now.AddMinutes(-1), Now.AddMinutes(1));
            Fingerprint = _certificate.GetCertHashString(HashAlgorithmName.SHA256);
            _services = new ServiceCollection().AddSingleton<IClock>(Clock)
                .AddSingleton<IAuditWriter>(Audit).BuildServiceProvider();
            Context.RequestServices = _services;
            Context.TraceIdentifier = "admin-window-test";
        }

        public MutableClock Clock { get; } = new();
        public MemoryAudit Audit { get; } = new();
        public DefaultHttpContext Context { get; } = new();
        public string Fingerprint { get; }
        public Task<bool> CheckAsync() => AdminCertificateRequestGuard.CheckAsync(Context, _certificate, Actor, Fingerprint);

        public void Dispose()
        {
            _certificate.Dispose();
            _services.Dispose();
        }
    }
}
