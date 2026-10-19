using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
        using var handler = new TransitHandler(key);
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
        using var handler = new TransitHandler(key) { Replacement = replacement };
        using var signer = CreateSigner(key, handler);

        await Assert.ThrowsAsync<CryptographicException>(
            () => signer.SignInventoryRefreshAsync(Device));
    }

    [Fact]
    public async Task Mismatched_public_key_and_redirect_fail_closed()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitHandler(key);
        using var signer = CreateSigner(other, handler);
        await Assert.ThrowsAsync<CryptographicException>(
            () => signer.SignInventoryRefreshAsync(Device));

        handler.Redirect = true;
        using var redirectedSigner = CreateSigner(key, handler);
        await Assert.ThrowsAsync<HttpRequestException>(
            () => redirectedSigner.SignInventoryRefreshAsync(Device));
    }

    [Fact]
    public async Task Invalid_configuration_or_target_never_calls_transit()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var handler = new TransitHandler(key);
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

    private static OpenBaoCommandSigner CreateSigner(ECDsa key, HttpMessageHandler handler) =>
        new(new Uri("http://127.0.0.1:8200/"), "test-token", "test-key", 2,
            key.ExportSubjectPublicKeyInfo(), allowHttpLoopback: true, handler);

    private sealed class TransitHandler(ECDsa key) : HttpMessageHandler
    {
        public string? Replacement { get; set; }
        public bool Redirect { get; set; }
        public string? Token { get; private set; }
        public int RequestedVersion { get; private set; }
        public int CallCount { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            Token = request.Headers.GetValues("X-Vault-Token").Single();
            Assert.Equal("/v1/transit/sign/test-key/sha2-256", request.RequestUri?.AbsolutePath);
            if (Redirect)
            {
                return new HttpResponseMessage(HttpStatusCode.Redirect)
                {
                    Headers = { Location = new Uri("https://evil.example/") }
                };
            }

            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            RequestedVersion = body.RootElement.GetProperty("key_version").GetInt32();
            Assert.Equal("jws", body.RootElement.GetProperty("marshaling_algorithm").GetString());
            var input = Convert.FromBase64String(body.RootElement.GetProperty("input").GetString()!);
            var signature = key.SignData(input, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var encoded = Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var value = Replacement ?? $"vault:v2:{encoded}";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { data = new { signature = value } }),
                    Encoding.UTF8, "application/json")
            };
        }
    }

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
