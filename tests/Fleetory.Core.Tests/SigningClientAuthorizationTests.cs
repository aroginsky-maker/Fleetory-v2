using System.Collections.Concurrent;
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
        var service = new AuthorizedCommandSigner(policy, signer, new MemorySigningJournal(), new MemorySigningRevocations());
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.SignInventoryRefreshAsync(Guid.NewGuid(), null, Device));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.SignInventoryRefreshAsync(Guid.NewGuid(), client, new DeviceId(Guid.NewGuid())));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.SignInventoryRefreshAsync(Guid.NewGuid(), client, Device, cancelled.Token));
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
        var signed = await new AuthorizedCommandSigner(policy, signer, new MemorySigningJournal(), new MemorySigningRevocations()).SignInventoryRefreshAsync(Guid.NewGuid(), client, Device);
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
            new AuthorizedCommandSigner(policy, signer, new MemorySigningJournal(), new MemorySigningRevocations()).SignInventoryRefreshAsync(Guid.NewGuid(), client, Device));
        Assert.Equal(1, transit.CallCount);
    }

    [Fact]
    public async Task Signing_reservation_and_result_exist_before_the_envelope_is_returned()
    {
        using var scenario = new JournalScenario();
        var requestId = Guid.NewGuid();
        var result = await scenario.Service.SignInventoryRefreshAsync(requestId, scenario.Client, Device);
        var request = Assert.Single(scenario.Journal.Requests.Values);
        Assert.Equal(requestId, request.RequestId);
        Assert.Equal("approval-service", request.CallerId);
        Assert.Equal(scenario.Client.GetCertHashString(HashAlgorithmName.SHA256), request.ClientCertificateSha256);
        Assert.Equal(Device, request.TargetDeviceId);
        Assert.Same(result.Envelope, Assert.Single(scenario.Journal.Results.Values));
    }

    [Fact]
    public async Task Repeated_request_does_not_generate_another_command()
    {
        using var scenario = new JournalScenario();
        var requestId = Guid.NewGuid();
        await scenario.Service.SignInventoryRefreshAsync(requestId, scenario.Client, Device);
        await Assert.ThrowsAsync<SigningRequestConflictException>(() =>
            scenario.Service.SignInventoryRefreshAsync(requestId, scenario.Client, Device));
        Assert.Equal(1, scenario.Transit.CallCount);
        Assert.Single(scenario.Journal.Results);
    }

    [Fact]
    public async Task Concurrent_same_request_is_signed_only_once()
    {
        using var scenario = new JournalScenario();
        var requestId = Guid.NewGuid();
        var calls = Enumerable.Range(0, 12).Select(async _ =>
        {
            try
            {
                await scenario.Service.SignInventoryRefreshAsync(requestId, scenario.Client, Device);
                return true;
            }
            catch (InvalidOperationException) { return false; }
        });
        var results = await Task.WhenAll(calls);
        Assert.Equal(1, results.Count(signed => signed));
        Assert.Equal(1, scenario.Transit.CallCount);
    }

    [Fact]
    public async Task Failed_reservation_prevents_transit_access()
    {
        using var scenario = new JournalScenario();
        scenario.Journal.FailBegin = true;
        await Assert.ThrowsAsync<IOException>(() => scenario.Service.SignInventoryRefreshAsync(Guid.NewGuid(), scenario.Client, Device));
        Assert.Equal(0, scenario.Transit.CallCount);
        Assert.Empty(scenario.Journal.Requests);
    }

    [Fact]
    public async Task Failed_completion_withholds_the_signature_and_prevents_resigning()
    {
        using var scenario = new JournalScenario();
        scenario.Journal.FailCompletion = true;
        var requestId = Guid.NewGuid();
        await Assert.ThrowsAsync<IOException>(() => scenario.Service.SignInventoryRefreshAsync(requestId, scenario.Client, Device));
        Assert.Single(scenario.Journal.Requests);
        Assert.Empty(scenario.Journal.Results);
        await Assert.ThrowsAsync<SigningRequestConflictException>(() => scenario.Service.SignInventoryRefreshAsync(requestId, scenario.Client, Device));
        Assert.Equal(1, scenario.Transit.CallCount);
    }

    [Fact]
    public async Task Transit_failure_leaves_a_pending_reservation()
    {
        using var scenario = new JournalScenario();
        scenario.Transit.Replacement = "vault:v3:unexpected";
        await Assert.ThrowsAsync<CryptographicException>(() => scenario.Service.SignInventoryRefreshAsync(Guid.NewGuid(), scenario.Client, Device));
        Assert.Single(scenario.Journal.Requests);
        Assert.Empty(scenario.Journal.Results);
    }

    [Fact]
    public async Task Grant_expiring_during_journal_commit_prevents_release()
    {
        using var scenario = new JournalScenario();
        scenario.Journal.OnCompleting = () => scenario.Clock.UtcNow = Now.AddHours(1);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => scenario.Service.SignInventoryRefreshAsync(Guid.NewGuid(), scenario.Client, Device));
        Assert.Single(scenario.Journal.Results);
    }

    [Fact]
    public async Task Cancellation_during_journal_commit_prevents_release()
    {
        using var scenario = new JournalScenario();
        using var lifetime = new CancellationTokenSource();
        scenario.Journal.OnCompleting = lifetime.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            scenario.Service.SignInventoryRefreshAsync(Guid.NewGuid(), scenario.Client, Device, lifetime.Token));
        Assert.Single(scenario.Journal.Results);
    }

    [Fact]
    public async Task Empty_request_id_is_rejected_before_journaling()
    {
        using var scenario = new JournalScenario();
        await Assert.ThrowsAsync<ArgumentException>(() => scenario.Service.SignInventoryRefreshAsync(Guid.Empty, scenario.Client, Device));
        Assert.Empty(scenario.Journal.Requests);
        Assert.Equal(0, scenario.Transit.CallCount);
    }

    [Theory]
    [InlineData("before", 0, 0, 0)]
    [InlineData("reservation", 0, 1, 0)]
    [InlineData("transit", 1, 1, 0)]
    [InlineData("completion", 1, 1, 1)]
    public async Task Revocation_at_each_boundary_withholds_the_envelope(string stage, int transitCalls, int requests, int results)
    {
        using var scenario = new JournalScenario();
        void Revoke() => scenario.Revocations.IsRevoked = true;
        switch (stage)
        {
            case "before": Revoke(); break;
            case "reservation": scenario.Journal.OnBeginning = Revoke; break;
            case "transit": scenario.Transit.OnSigning = Revoke; break;
            case "completion": scenario.Journal.OnCompleting = Revoke; break;
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            scenario.Service.SignInventoryRefreshAsync(Guid.NewGuid(), scenario.Client, Device));
        Assert.Equal(transitCalls, scenario.Transit.CallCount);
        Assert.Equal(requests, scenario.Journal.Requests.Count);
        Assert.Equal(results, scenario.Journal.Results.Count);
    }

    [Theory]
    [InlineData(1, 0, 0)]
    [InlineData(2, 0, 1)]
    [InlineData(3, 1, 1)]
    [InlineData(4, 1, 1)]
    public async Task Revocation_read_failure_at_each_boundary_withholds_the_envelope(int check, int transitCalls, int requests)
    {
        using var scenario = new JournalScenario();
        scenario.Revocations.FailOnCheck = check;
        await Assert.ThrowsAsync<IOException>(() =>
            scenario.Service.SignInventoryRefreshAsync(Guid.NewGuid(), scenario.Client, Device));
        Assert.Equal(transitCalls, scenario.Transit.CallCount);
        Assert.Equal(requests, scenario.Journal.Requests.Count);
        Assert.Equal(check == 4 ? 1 : 0, scenario.Journal.Results.Count);
    }

    [Theory]
    [InlineData(1, 300, 0, 0, 0)]
    [InlineData(2, 300, 0, 1, 0)]
    [InlineData(3, 300, 1, 1, 0)]
    [InlineData(4, 300, 1, 1, 1)]
    [InlineData(1, 299, 1, 1, 1)]
    [InlineData(2, 299, 1, 1, 1)]
    [InlineData(3, 299, 1, 1, 1)]
    [InlineData(4, 299, 1, 1, 1)]
    public async Task Caller_grant_is_rechecked_after_a_delayed_revocation_read(
        int check, int elapsedSeconds, int transitCalls, int requests, int results)
    {
        using var scenario = new JournalScenario();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        scenario.Revocations.OnReadingAsync = async (number, cancellationToken) =>
        {
            if (number != check) { return; }
            entered.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
        };
        var requestId = Guid.NewGuid();
        var pending = scenario.Service.SignInventoryRefreshAsync(requestId, scenario.Client, Device);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            scenario.Clock.UtcNow = Now.AddSeconds(elapsedSeconds);
            release.TrySetResult();
            if (elapsedSeconds == 300)
            {
                await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
                    await pending.WaitAsync(TimeSpan.FromSeconds(5)));
            }
            else
            {
                Assert.Equal("approval-service",
                    (await pending.WaitAsync(TimeSpan.FromSeconds(5))).CallerId);
            }
            Assert.Equal(transitCalls, scenario.Transit.CallCount);
            Assert.Equal(requests, scenario.Journal.Requests.Count);
            Assert.Equal(results, scenario.Journal.Results.Count);

            // A rejected request with a reservation must never sign again after clock recovery.
            scenario.Clock.UtcNow = Now;
            if (requests != 0)
            {
                await Assert.ThrowsAsync<SigningRequestConflictException>(() =>
                    scenario.Service.SignInventoryRefreshAsync(requestId, scenario.Client, Device));
                Assert.Equal(transitCalls, scenario.Transit.CallCount);
            }
            else
            {
                await scenario.Service.SignInventoryRefreshAsync(requestId, scenario.Client, Device);
                Assert.Equal(1, scenario.Transit.CallCount);
            }
        }
        finally { release.TrySetResult(); }
    }

    private sealed class MemorySigningRevocations : ISigningClientRevocations
    {
        private int _checks;
        public bool IsRevoked { get; set; }
        public int FailOnCheck { get; set; }
        public Func<int, CancellationToken, Task>? OnReadingAsync { get; set; }

        public async Task EnsureNotRevokedAsync(string certificateSha256, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (++_checks == FailOnCheck) { throw new IOException("Revocation store unavailable."); }
            if (OnReadingAsync is { } reading) { await reading(_checks, cancellationToken); }
            if (IsRevoked) { throw new UnauthorizedAccessException("Client revoked."); }
        }
    }

    private static SigningClientGrant Grant(X509Certificate2 certificate) =>
        new("approval-service", certificate.GetCertHashString(HashAlgorithmName.SHA256), [Device], Now.AddMinutes(-5), Now.AddMinutes(5));

    private static SigningClientAuthorizationPolicy CreatePolicy(X509Certificate2 root, SigningClientGrant grant, MutableTime? clock = null) =>
        new([root], [], [grant], clock ?? new MutableTime(Now));

    private static OpenBaoCommandSigner CreateTransitSigner(TransitTestHandler transit, ECDsa key) =>
        new(new Uri("http://127.0.0.1:8200/"), "test-token", "test-key", 2,
            key.ExportSubjectPublicKeyInfo(), allowHttpLoopback: true, transit);

    private sealed class MemorySigningJournal : ISigningRequestJournal
    {
        public ConcurrentDictionary<Guid, SigningRequest> Requests { get; } = new();
        public ConcurrentDictionary<Guid, SignedCommandEnvelope> Results { get; } = new();
        public bool FailBegin { get; set; }
        public bool FailCompletion { get; set; }
        public Action? OnBeginning { get; set; }
        public Action? OnCompleting { get; set; }

        public Task<bool> TryBeginAsync(SigningRequest request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (FailBegin) { throw new IOException("Reservation unavailable."); }
            var inserted = Requests.TryAdd(request.RequestId, request);
            OnBeginning?.Invoke();
            return Task.FromResult(inserted);
        }

        public Task CompleteAsync(SigningRequest request, SignedCommandEnvelope envelope, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (FailCompletion) { throw new IOException("Completion unavailable."); }
            Results[request.RequestId] = envelope;
            OnCompleting?.Invoke();
            return Task.CompletedTask;
        }
    }

    private sealed class JournalScenario : IDisposable
    {
        private readonly Certificates _certificates = new();
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly OpenBaoCommandSigner _signer;
        private readonly SigningClientAuthorizationPolicy _policy;
        public MutableTime Clock { get; } = new(Now);
        public MemorySigningJournal Journal { get; } = new();
        public MemorySigningRevocations Revocations { get; } = new();
        public X509Certificate2 Client { get; }
        public TransitTestHandler Transit { get; }
        public AuthorizedCommandSigner Service { get; }

        public JournalScenario()
        {
            Client = _certificates.Issue();
            Transit = new TransitTestHandler(_key);
            _signer = CreateTransitSigner(Transit, _key);
            _policy = CreatePolicy(_certificates.Root, Grant(Client), Clock);
            Service = new AuthorizedCommandSigner(_policy, _signer, Journal, Revocations);
        }

        public void Dispose()
        {
            _signer.Dispose();
            _policy.Dispose();
            Client.Dispose();
            _key.Dispose();
            _certificates.Dispose();
        }
    }

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
