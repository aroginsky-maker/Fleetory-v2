using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Fleetory.Agent.Security;
using Fleetory.CommandSigning;
using Fleetory.Core.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Core.Tests;

public sealed class OpenBaoCommandSignerTests
{
    private static readonly DeviceId Device = new(Guid.Parse("be7675ae-712f-4886-b729-9f3a89df70d1"));

    [Fact]
    public async Task Transit_signature_is_accepted_once_by_agent_and_replay_is_rejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitTestHandler(key);
        using var signer = CreateSigner(key, handler);

        var envelope = await signer.SignInventoryRefreshAsync(Device);
        var verifier = new SignedCommandVerifier(
            new StaticKey(key.ExportSubjectPublicKeyInfo()), new OnceReplay(),
            new AgentCommandExecutionPolicy(Device), new SystemClock());
        var first = await verifier.VerifyAsync(envelope, Device);
        var second = await verifier.VerifyAsync(envelope, Device);

        Assert.Equal("Inventory.Refresh", envelope.CommandType);
        Assert.True(envelope.Payload.IsEmpty);
        Assert.Equal("test-key-v2", envelope.SigningKeyId);
        Assert.Equal(CommandVerificationStatus.Accepted, first.Status);
        Assert.Equal(CommandVerificationStatus.Replay, second.Status);
        Assert.Equal("test-token", handler.Token);
        Assert.Equal(2, handler.RequestedVersion);
    }

    [Theory]
    [InlineData("vault:v3:")]
    [InlineData("vault:v2:***")]
    [InlineData("vault:v2:AA")]
    public async Task Unexpected_version_or_invalid_signature_fails_closed(string replacement)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitTestHandler(key) { Replacement = replacement };
        using var signer = CreateSigner(key, handler);

        await Assert.ThrowsAsync<CryptographicException>(
            () => signer.SignInventoryRefreshAsync(Device));
    }

    [Fact]
    public async Task Mismatched_public_key_and_redirect_fail_closed()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitTestHandler(key);
        using var signer = CreateSigner(other, handler);
        await Assert.ThrowsAsync<CryptographicException>(
            () => signer.SignInventoryRefreshAsync(Device));

        handler.Redirect = true;
        using var redirectedSigner = CreateSigner(key, handler);
        await Assert.ThrowsAsync<HttpRequestException>(
            () => redirectedSigner.SignInventoryRefreshAsync(Device));
    }

    [Fact]
    public async Task Oversized_transit_response_fails_closed()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitTestHandler(key) { Replacement = new string('A', 5000) };
        using var signer = CreateSigner(key, handler);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => signer.SignInventoryRefreshAsync(Device));
    }

    [Fact]
    public async Task Remote_failure_reason_cannot_echo_signing_credentials()
    {
        const string sentinel = "disposable-signer-credential";
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitTestHandler(key)
        {
            FailureStatus = HttpStatusCode.ServiceUnavailable,
            FailureReason = sentinel
        };
        using var signer = CreateSigner(key, handler);
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => signer.SignInventoryRefreshAsync(Device));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, exception.StatusCode);
        Assert.DoesNotContain(sentinel, exception.ToString());
    }

    [Theory]
    [InlineData("{broken")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("{\"data\":null}")]
    [InlineData("{\"data\":{}}")]
    [InlineData("{\"data\":{\"signature\":42}}")]
    [InlineData("{\"data\":{\"signature\":null}}")]
    public async Task Malformed_response_never_releases_an_envelope(string json)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitTestHandler(key) { JsonResponse = json };
        using var signer = CreateSigner(key, handler);
        await Assert.ThrowsAsync<CryptographicException>(() => signer.SignInventoryRefreshAsync(Device));
    }

    [Theory]
    [InlineData("credential\r\ninjected")]
    [InlineData("credential with spaces")]
    [InlineData("credential\tvalue")]
    [InlineData("credential\u007fvalue")]
    [InlineData("credential\u00e9value")]
    public void Invalid_credential_is_rejected_without_echo(string credential)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var exception = Assert.Throws<ArgumentException>(() => new OpenBaoCommandSigner(
            new Uri("https://vault.example/"), credential, "test-key", 2, key.ExportSubjectPublicKeyInfo()));
        Assert.DoesNotContain(credential, exception.ToString());
    }

    [Fact]
    public void Oversized_credential_is_rejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Throws<ArgumentException>(() => new OpenBaoCommandSigner(
            new Uri("https://vault.example/"), new string('A', 8193), "test-key", 2, key.ExportSubjectPublicKeyInfo()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11000)]
    public void Internal_deadline_cannot_disable_the_production_bound(int milliseconds)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitTestHandler(key);
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateSigner(
            key, handler, TimeSpan.FromMilliseconds(milliseconds)));
    }

    [Fact]
    public async Task Already_cancelled_call_never_reaches_transit()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitTestHandler(key);
        using var signer = CreateSigner(key, handler);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => signer.SignInventoryRefreshAsync(Device, cancellation.Token));
        Assert.Equal(0, handler.CallCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task Deadline_covers_headers_and_body_over_real_http(bool sendHeaders) =>
        AssertStalledRequestCancelledAsync(sendHeaders, cancelCaller: false);

    [Fact]
    public Task Caller_cancellation_interrupts_a_real_body_read() =>
        AssertStalledRequestCancelledAsync(sendHeaders: true, cancelCaller: true);

    private static async Task AssertStalledRequestCancelledAsync(bool sendHeaders, bool cancelCaller)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var serverLifetime = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var caller = new CancellationTokenSource();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var received = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = HoldResponseAsync(listener, sendHeaders, received, serverLifetime.Token);
        var origin = new Uri($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        using var signer = new OpenBaoCommandSigner(origin, "test-token", "test-key", 2,
            key.ExportSubjectPublicKeyInfo(), allowHttpLoopback: true, handler: null,
            requestTimeout: TimeSpan.FromSeconds(cancelCaller ? 10 : 1));
        try
        {
            var signing = signer.SignInventoryRefreshAsync(Device, caller.Token);
            await received.Task.WaitAsync(TimeSpan.FromSeconds(5));
            if (cancelCaller) { caller.Cancel(); }
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => signing.WaitAsync(TimeSpan.FromSeconds(3)));
        }
        finally
        {
            serverLifetime.Cancel();
            listener.Stop();
            try { await server; }
            catch (OperationCanceledException) when (serverLifetime.IsCancellationRequested) { }
        }
    }

    private static async Task HoldResponseAsync(TcpListener listener, bool sendHeaders,
        TaskCompletionSource received, CancellationToken cancellationToken)
    {
        using var peer = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = peer.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
        while (!string.IsNullOrEmpty(await reader.ReadLineAsync(cancellationToken))) { }
        if (sendHeaders)
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 80\r\nConnection: close\r\n\r\n"), cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }
        received.TrySetResult();
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    [Fact]
    public async Task Invalid_configuration_or_target_never_calls_transit()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitTestHandler(key);
        var publicKey = key.ExportSubjectPublicKeyInfo();
        Assert.Throws<ArgumentException>(() => new OpenBaoCommandSigner(
            new Uri("http://vault.example/"), "token", "test-key", 2, publicKey));
        Assert.Throws<ArgumentException>(() => new OpenBaoCommandSigner(
            new Uri("https://user:password@vault.example/"), "token", "test-key", 2, publicKey));
        Assert.Throws<ArgumentException>(() => new OpenBaoCommandSigner(
            new Uri("https://vault.example/"), "token", "../other", 2, publicKey));
        Assert.Throws<ArgumentException>(() => new OpenBaoCommandSigner(
            new Uri("https://vault.example/"), "token", "test-key", 0, publicKey));
        using var signer = CreateSigner(key, handler);
        await Assert.ThrowsAsync<ArgumentException>(
            () => signer.SignInventoryRefreshAsync(new DeviceId(Guid.Empty)));
        Assert.Equal(0, handler.CallCount);
    }

    private static OpenBaoCommandSigner CreateSigner(ECDsa key, HttpMessageHandler handler, TimeSpan? timeout = null) =>
        new(new Uri("http://127.0.0.1:8200/"), "test-token", "test-key", 2,
            key.ExportSubjectPublicKeyInfo(), allowHttpLoopback: true, handler, timeout);

    private sealed class StaticKey(byte[] publicKey) : ICommandVerificationKeys
    {
        public ValueTask<ReadOnlyMemory<byte>?> FindPublicKeyAsync(
            DeviceId targetDeviceId, string keyId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>?>(publicKey);
    }

    private sealed class OnceReplay : ICommandReplayStore
    {
        private bool _consumed;

        public ValueTask<bool> TryConsumeAsync(
            DeviceId targetDeviceId, Guid commandId, string nonce, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            var first = !_consumed;
            _consumed = true;
            return ValueTask.FromResult(first);
        }
    }
}
