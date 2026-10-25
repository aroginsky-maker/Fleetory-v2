using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.CommandSigning;
using Fleetory.Core.Contracts;

namespace Fleetory.Core.Tests;

public sealed class SigningClientAuthorizationTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 25, 12, 0, 0, TimeSpan.Zero);
    private static readonly DeviceId Device = new(Guid.Parse("08a4cb5c-e482-4c5b-9e91-faf869ed7ef0"));
    private const string ClientOid = "1.3.6.1.5.5.7.3.2";

    [Fact]
    public void Registered_leaf_is_scoped_to_its_target_and_configured_identity()
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        using var policy = CreatePolicy(certificates.Root, Grant(client));
        Assert.Equal("approval-service", policy.GetAuthorizedInventoryRefreshCaller(client, Device));
        Assert.Null(policy.GetAuthorizedInventoryRefreshCaller(client, new DeviceId(Guid.NewGuid())));
        Assert.Null(policy.GetAuthorizedInventoryRefreshCaller(client, default));
        Assert.Null(policy.GetAuthorizedInventoryRefreshCaller(null, Device));
    }

    [Fact]
    public void A_trusted_but_unregistered_server_or_agent_certificate_is_denied()
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        using var other = certificates.Issue();
        using var policy = CreatePolicy(certificates.Root, Grant(client));
        Assert.Null(policy.GetAuthorizedInventoryRefreshCaller(other, Device));
    }

    [Fact]
    public void A_pinned_leaf_from_an_untrusted_root_is_denied()
    {
        using var trusted = new Certificates();
        using var foreign = new Certificates();
        using var client = foreign.Issue();
        using var policy = CreatePolicy(trusted.Root, Grant(client));
        Assert.Null(policy.GetAuthorizedInventoryRefreshCaller(client, Device));
    }

    [Theory]
    [InlineData("no-eku")]
    [InlineData("server-eku")]
    [InlineData("ca")]
    [InlineData("no-digital-signature")]
    [InlineData("expired")]
    [InlineData("future")]
    public void Registered_but_invalid_client_certificate_is_denied(string kind)
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue(kind);
        using var policy = CreatePolicy(certificates.Root, Grant(client));
        Assert.Null(policy.GetAuthorizedInventoryRefreshCaller(client, Device));
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(0, true)]
    [InlineData(599, true)]
    [InlineData(600, false)]
    public void Grant_window_is_half_open_and_checked_again_for_every_request(int seconds, bool expected)
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        var clock = new MutableTime(Now.AddSeconds(seconds));
        var grant = Grant(client) with { NotBefore = Now, ExpiresAt = Now.AddMinutes(10) };
        using var policy = CreatePolicy(certificates.Root, grant, clock);
        Assert.Equal(expected, policy.GetAuthorizedInventoryRefreshCaller(client, Device) is not null);
        clock.UtcNow = Now.AddHours(1);
        Assert.Null(policy.GetAuthorizedInventoryRefreshCaller(client, Device));
    }

    [Fact]
    public void Policy_owns_public_trust_and_an_immutable_device_snapshot()
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        var devices = new List<DeviceId> { Device };
        using var root = X509CertificateLoader.LoadCertificate(certificates.Root.RawData);
        using var policy = CreatePolicy(root, Grant(client) with { AllowedDevices = devices });
        root.Dispose();
        devices.Clear();
        var unauthorized = new DeviceId(Guid.NewGuid());
        devices.Add(unauthorized);
        Assert.Equal("approval-service", policy.GetAuthorizedInventoryRefreshCaller(client, Device));
        Assert.Null(policy.GetAuthorizedInventoryRefreshCaller(client, unauthorized));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Same_subject_root_rollover_and_explicit_intermediate_are_supported_without_downloads(bool reverseRoots)
    {
        using var first = new Certificates();
        using var second = new Certificates();
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var intermediatePublic = Certificates.Request("CN=Intermediate", intermediateKey, true)
            .Create(second.Root, Now.AddDays(-1), Now.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using var intermediate = intermediatePublic.CopyWithPrivateKey(intermediateKey);
        using var client = second.Issue(issuer: intermediate);
        // Equal CA subject names reproduce OpenSSL choosing the wrong key from a combined trust bundle.
        using var policy = new SigningClientAuthorizationPolicy(
            reverseRoots ? [second.Root, first.Root] : [first.Root, second.Root],
            [intermediate], [Grant(client)], new MutableTime(Now));
        Assert.Equal("approval-service", policy.GetAuthorizedInventoryRefreshCaller(client, Device));
        using var missingIntermediate = CreatePolicy(second.Root, Grant(client));
        Assert.Null(missingIntermediate.GetAuthorizedInventoryRefreshCaller(client, Device));
    }

    [Theory]
    [InlineData("caller")]
    [InlineData("fingerprint")]
    [InlineData("empty-devices")]
    [InlineData("empty-device")]
    [InlineData("duplicate-device")]
    [InlineData("many-devices")]
    [InlineData("window")]
    [InlineData("long-window")]
    [InlineData("offset")]
    public void Invalid_grants_fail_during_configuration(string kind)
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        var grant = Grant(client);
        grant = kind switch
        {
            "caller" => grant with { CallerId = "untrusted caller\r\n" },
            "fingerprint" => grant with { CertificateSha256 = new string('G', 64) },
            "empty-devices" => grant with { AllowedDevices = [] },
            "empty-device" => grant with { AllowedDevices = [default] },
            "duplicate-device" => grant with { AllowedDevices = [Device, Device] },
            "many-devices" => grant with { AllowedDevices = Enumerable.Range(0, 1025).Select(_ => new DeviceId(Guid.NewGuid())).ToArray() },
            "window" => grant with { ExpiresAt = grant.NotBefore },
            "long-window" => grant with { ExpiresAt = grant.NotBefore.AddHours(25) },
            "offset" => grant with { NotBefore = grant.NotBefore.ToOffset(TimeSpan.FromHours(3)) },
            _ => throw new InvalidOperationException()
        };
        Assert.Throws<ArgumentException>(() => CreatePolicy(certificates.Root, grant));
    }

    [Fact]
    public void Duplicate_fingerprints_and_non_ca_trust_are_rejected()
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        var grant = Grant(client);
        Assert.Throws<ArgumentException>(() => new SigningClientAuthorizationPolicy(
            [certificates.Root], [], [grant, grant with { CertificateSha256 = grant.CertificateSha256.ToLowerInvariant() }]));
        Assert.Throws<ArgumentException>(() => CreatePolicy(client, grant));
        Assert.Throws<ArgumentException>(() => new SigningClientAuthorizationPolicy([], [], [grant]));
        Assert.Throws<ArgumentException>(() => new SigningClientAuthorizationPolicy([certificates.Root], [], []));
        using var disposed = CreatePolicy(certificates.Root, grant);
        disposed.Dispose();
        Assert.Throws<ObjectDisposedException>(() => disposed.GetAuthorizedInventoryRefreshCaller(client, Device));
    }

    [Fact]
    public void Malformed_certificate_handles_fail_closed()
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        using var policy = CreatePolicy(certificates.Root, Grant(client));
        client.Dispose();
        Assert.Null(policy.GetAuthorizedInventoryRefreshCaller(client, Device));
    }

    [Fact]
    public void Replacing_the_policy_removes_old_leaf_authority_after_rotation()
    {
        using var certificates = new Certificates();
        using var oldClient = certificates.Issue();
        using var replacement = certificates.Issue();
        using var overlap = new SigningClientAuthorizationPolicy(
            [certificates.Root], [], [Grant(oldClient), Grant(replacement)], new MutableTime(Now));
        Assert.NotNull(overlap.GetAuthorizedInventoryRefreshCaller(oldClient, Device));
        Assert.NotNull(overlap.GetAuthorizedInventoryRefreshCaller(replacement, Device));
        using var rotated = CreatePolicy(certificates.Root, Grant(replacement));
        Assert.Null(rotated.GetAuthorizedInventoryRefreshCaller(oldClient, Device));
        Assert.NotNull(rotated.GetAuthorizedInventoryRefreshCaller(replacement, Device));
    }

    [Fact]
    public async Task Denied_or_cancelled_requests_make_no_transit_call()
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        using var policy = CreatePolicy(certificates.Root, Grant(client));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var transit = new TransitTestHandler(key);
        using var signer = CreateTransitSigner(transit, key);
        var service = new AuthorizedCommandSigner(policy, signer);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.SignInventoryRefreshAsync(null, Device));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.SignInventoryRefreshAsync(client, new DeviceId(Guid.NewGuid())));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.SignInventoryRefreshAsync(client, Device, cancelled.Token));
        Assert.Equal(0, transit.CallCount);
    }

    [Fact]
    public async Task Authorized_signing_uses_the_configured_caller_and_only_inventory_refresh()
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        using var policy = CreatePolicy(certificates.Root, Grant(client));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var transit = new TransitTestHandler(key);
        using var signer = CreateTransitSigner(transit, key);
        var signed = await new AuthorizedCommandSigner(policy, signer).SignInventoryRefreshAsync(client, Device);
        Assert.Equal("approval-service", signed.CallerId);
        Assert.Equal(Device, signed.Envelope.TargetDeviceId);
        Assert.Equal(AgentCommandTypes.InventoryRefresh, signed.Envelope.CommandType);
        Assert.True(signed.Envelope.Payload.IsEmpty);
        Assert.Equal(1, transit.CallCount);
    }

    [Fact]
    public async Task Grant_expiring_during_transit_prevents_envelope_release()
    {
        using var certificates = new Certificates();
        using var client = certificates.Issue();
        var clock = new MutableTime(Now);
        using var policy = CreatePolicy(certificates.Root, Grant(client), clock);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var transit = new TransitTestHandler(key) { OnSigning = () => clock.UtcNow = Now.AddHours(1) };
        using var signer = CreateTransitSigner(transit, key);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            new AuthorizedCommandSigner(policy, signer).SignInventoryRefreshAsync(client, Device));
        Assert.Equal(1, transit.CallCount);
    }

    private static SigningClientGrant Grant(X509Certificate2 certificate) =>
        new("approval-service", certificate.GetCertHashString(HashAlgorithmName.SHA256), [Device], Now.AddMinutes(-5), Now.AddMinutes(5));

    private static SigningClientAuthorizationPolicy CreatePolicy(X509Certificate2 root, SigningClientGrant grant, MutableTime? clock = null) =>
        new([root], [], [grant], clock ?? new MutableTime(Now));

    private static OpenBaoCommandSigner CreateTransitSigner(TransitTestHandler transit, ECDsa key) =>
        new(new Uri("http://127.0.0.1:8200/"), "test-token", "test-key", 2,
            key.ExportSubjectPublicKeyInfo(), allowHttpLoopback: true, transit);

    private sealed class MutableTime(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }

    private sealed class Certificates : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public X509Certificate2 Root { get; }

        public Certificates() => Root = Request("CN=Signing Client Root", _key, true)
            .CreateSelfSigned(Now.AddDays(-3), Now.AddDays(3));

        public X509Certificate2 Issue(string kind = "valid", X509Certificate2? issuer = null)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = Request("CN=Caller-controlled subject", key, kind == "ca", kind == "no-digital-signature");
            if (kind != "no-eku")
            {
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    [new Oid(kind == "server-eku" ? "1.3.6.1.5.5.7.3.1" : ClientOid)], true));
            }
            var start = kind == "future" ? Now.AddHours(1) : Now.AddHours(-2);
            var end = kind == "expired" ? Now.AddHours(-1) : Now.AddHours(2);
            return request.Create(issuer ?? Root, start, end, RandomNumberGenerator.GetBytes(16));
        }

        public static CertificateRequest Request(string subject, ECDsa key, bool ca, bool noSignature = false)
        {
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(ca ?
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign :
                noSignature ? X509KeyUsageFlags.KeyEncipherment : X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            return request;
        }

        public void Dispose() { Root.Dispose(); _key.Dispose(); }
    }

}
