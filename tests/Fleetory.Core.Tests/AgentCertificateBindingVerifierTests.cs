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

        public void Add(
            X509Certificate2 certificate,
            DeviceId deviceId,
            DateTimeOffset? notAfter = null,
            DateTimeOffset? revokedAt = null)
        {
            var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
            bindings[fingerprint] = new AgentCertificateBinding(
                deviceId,
                fingerprint,
                Now.AddDays(-1),
                notAfter ?? Now.AddDays(1),
                revokedAt);
        }

        public ValueTask<AgentCertificateBinding?> FindBySha256Async(
            string certificateSha256,
            CancellationToken cancellationToken = default)
        {
            LookupCount++;
            if (Fail)
            {
                throw new InvalidOperationException("Identity store unavailable.");
            }

            bindings.TryGetValue(certificateSha256, out var binding);
            return ValueTask.FromResult(binding);
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }
}
