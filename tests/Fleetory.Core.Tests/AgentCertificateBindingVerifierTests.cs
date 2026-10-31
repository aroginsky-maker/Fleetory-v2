using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;
using Fleetory.Core.Security;
using Fleetory.SharedKernel;

namespace Fleetory.Core.Tests;

public sealed class AgentCertificateBindingVerifierTests
{
    private static readonly DeviceId Device = new(Guid.Parse("b7d5b950-455a-4f96-bd20-f2aa61262ae9"));
    private static readonly DateTimeOffset Now = new(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Registered_client_certificate_is_bound_to_one_device()
    {
        using var certificate = CreateCertificate();
        var store = new MemoryBindings();
        store.Add(certificate, Device);
        var verifier = new AgentCertificateBindingVerifier(store, new FixedClock(Now));

        Assert.Equal(AgentCertificateStatus.Accepted,
            await verifier.VerifyAsync(Device, certificate));
        Assert.Equal(AgentCertificateStatus.WrongDevice,
            await verifier.VerifyAsync(new DeviceId(Guid.NewGuid()), certificate));
    }

    [Fact]
    public async Task Unregistered_or_revoked_certificate_is_denied()
    {
        using var certificate = CreateCertificate();
        var store = new MemoryBindings();
        var verifier = new AgentCertificateBindingVerifier(store, new FixedClock(Now));

        Assert.Equal(AgentCertificateStatus.UnknownCertificate,
            await verifier.VerifyAsync(Device, certificate));

        store.Add(certificate, Device, revokedAt: Now.AddMinutes(-1));
        Assert.Equal(AgentCertificateStatus.Revoked,
            await verifier.VerifyAsync(Device, certificate));
    }

    [Fact]
    public async Task Expired_certificate_or_binding_is_denied()
    {
        using var certificate = CreateCertificate();
        var store = new MemoryBindings();
        store.Add(certificate, Device, notAfter: Now.AddMinutes(-1));
        var verifier = new AgentCertificateBindingVerifier(store, new FixedClock(Now));

        Assert.Equal(AgentCertificateStatus.Expired,
            await verifier.VerifyAsync(Device, certificate));
        verifier = new AgentCertificateBindingVerifier(store, new FixedClock(Now.AddDays(2)));
        Assert.Equal(AgentCertificateStatus.Expired,
            await verifier.VerifyAsync(Device, certificate));
        verifier = new AgentCertificateBindingVerifier(store, new FixedClock(Now.AddDays(-2)));
        Assert.Equal(AgentCertificateStatus.Expired,
            await verifier.VerifyAsync(Device, certificate));
    }

    [Theory]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    public async Task Missing_client_purpose_or_ca_certificate_is_denied(
        bool clientEku,
        bool digitalSignature,
        bool endEntity)
    {
        using var certificate = CreateCertificate(clientEku, digitalSignature, endEntity);
        var store = new MemoryBindings();
        store.Add(certificate, Device);
        var verifier = new AgentCertificateBindingVerifier(store, new FixedClock(Now));

        Assert.Equal(AgentCertificateStatus.InvalidCertificate,
            await verifier.VerifyAsync(Device, certificate));
    }

    [Fact]
    public async Task Empty_device_id_is_rejected_before_lookup()
    {
        using var certificate = CreateCertificate();
        var store = new MemoryBindings();
        var verifier = new AgentCertificateBindingVerifier(store, new FixedClock(Now));

        Assert.Equal(AgentCertificateStatus.InvalidCertificate,
            await verifier.VerifyAsync(new DeviceId(Guid.Empty), certificate));
        Assert.Equal(0, store.LookupCount);
    }

    [Fact]
    public async Task Store_failure_propagates_instead_of_accepting()
    {
        using var certificate = CreateCertificate();
        var store = new MemoryBindings { Fail = true };
        var verifier = new AgentCertificateBindingVerifier(store, new FixedClock(Now));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await verifier.VerifyAsync(Device, certificate));
    }

    [Theory]
    [InlineData(true, 86400, AgentCertificateStatus.Expired)]
    [InlineData(false, 86400, AgentCertificateStatus.Expired)]
    [InlineData(true, -86401, AgentCertificateStatus.Expired)]
    [InlineData(false, -86401, AgentCertificateStatus.Expired)]
    [InlineData(true, 86399, AgentCertificateStatus.Accepted)]
    [InlineData(false, 86399, AgentCertificateStatus.UnknownCertificate)]
    [InlineData(true, -86400, AgentCertificateStatus.Accepted)]
    [InlineData(false, -86400, AgentCertificateStatus.UnknownCertificate)]
    public async Task Leaf_validity_is_rechecked_after_lookup(
        bool registered, int seconds, AgentCertificateStatus expected)
    {
        using var certificate = CreateCertificate();
        var store = new MemoryBindings();
        if (registered)
        {
            store.Add(certificate, Device, notAfter: Now.AddDays(2), notBefore: Now.AddDays(-2));
        }
        var result = await VerifyAfterLookupAsync(store, certificate, Now.AddSeconds(seconds));
        Assert.Equal(expected, result);
        Assert.Equal(1, store.LookupCount);
    }

    [Theory]
    [InlineData(60, AgentCertificateStatus.Expired)]
    [InlineData(-61, AgentCertificateStatus.Expired)]
    [InlineData(59, AgentCertificateStatus.Accepted)]
    [InlineData(-60, AgentCertificateStatus.Accepted)]
    public async Task Binding_validity_is_rechecked_after_lookup(int seconds, AgentCertificateStatus expected)
    {
        using var certificate = CreateCertificate();
        var store = new MemoryBindings();
        store.Add(certificate, Device, notAfter: Now.AddMinutes(1), notBefore: Now.AddMinutes(-1));
        Assert.Equal(expected, await VerifyAfterLookupAsync(store, certificate, Now.AddSeconds(seconds)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancelled_verification_never_accepts_a_binding(bool duringLookup)
    {
        using var certificate = CreateCertificate();
        var store = new MemoryBindings();
        store.Add(certificate, Device);
        using var lifetime = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (duringLookup)
        {
            // Simulate a store that completes despite cancellation of the outer request.
            store.BeforeReturning = async _ => { entered.TrySetResult(); await release.Task; };
        }
        else { await lifetime.CancelAsync(); }
        var verifier = new AgentCertificateBindingVerifier(store, new FixedClock(Now));
        var pending = verifier.VerifyAsync(Device, certificate, lifetime.Token).AsTask();
        try
        {
            if (duringLookup)
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                await lifetime.CancelAsync();
                release.TrySetResult();
            }
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await pending.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.Equal(duringLookup ? 1 : 0, store.LookupCount);
        }
        finally { release.TrySetResult(); }
    }

    private static async Task<AgentCertificateStatus> VerifyAfterLookupAsync(
        MemoryBindings store, X509Certificate2 certificate, DateTimeOffset completedAt)
    {
        var clock = new MutableClock();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        store.BeforeReturning = async cancellationToken =>
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
        };
        var pending = new AgentCertificateBindingVerifier(store, clock)
            .VerifyAsync(Device, certificate).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            clock.UtcNow = completedAt;
            release.TrySetResult();
            return await pending.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally { release.TrySetResult(); }
    }

    private sealed class MutableClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = Now;
    }

    private static X509Certificate2 CreateCertificate(
        bool clientEku = true,
        bool digitalSignature = true,
        bool endEntity = true)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Fleetory Test Agent", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(!endEntity, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            digitalSignature ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.KeyEncipherment,
            true));

        var purposes = new OidCollection();
        purposes.Add(new Oid(clientEku ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1"));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(purposes, true));

        return request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
    }

    private sealed class MemoryBindings : IAgentCertificateBindingStore
    {
        private readonly Dictionary<string, AgentCertificateBinding> bindings = new(StringComparer.Ordinal);

        public int LookupCount { get; private set; }
        public bool Fail { get; init; }
        public Func<CancellationToken, Task>? BeforeReturning { get; set; }

        public void Add(
            X509Certificate2 certificate,
            DeviceId deviceId,
            DateTimeOffset? notAfter = null,
            DateTimeOffset? revokedAt = null,
            DateTimeOffset? notBefore = null)
        {
            var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
            bindings[fingerprint] = new AgentCertificateBinding(
                deviceId,
                fingerprint,
                notBefore ?? Now.AddDays(-1),
                notAfter ?? Now.AddDays(1),
                revokedAt);
        }

        public async ValueTask<AgentCertificateBinding?> FindBySha256Async(
            string certificateSha256,
            CancellationToken cancellationToken = default)
        {
            LookupCount++;
            if (Fail)
            {
                throw new InvalidOperationException("Identity store unavailable.");
            }

            if (BeforeReturning is { } beforeReturning) { await beforeReturning(cancellationToken); }
            bindings.TryGetValue(certificateSha256, out var binding);
            return binding;
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }
}
