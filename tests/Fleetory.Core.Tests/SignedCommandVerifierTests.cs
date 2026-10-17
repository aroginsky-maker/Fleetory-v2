using System.Security.Cryptography;
using System.Text;
using Fleetory.Agent.Security;
using Fleetory.Core.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Core.Tests;

public sealed class SignedCommandVerifierTests
{
    private static readonly DeviceId Device = new(Guid.Parse("be7675ae-712f-4886-b729-9f3a89df70d1"));
    private static readonly DateTimeOffset Now = new(2026, 10, 16, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Payload = "{\"requested\":true}"u8.ToArray();
    private const string Nonce = "unique-nonce-123456789";

    [Fact]
    public async Task Valid_targeted_signed_command_is_accepted_once()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        var command = CreateSigned(signer);

        var first = await fixture.Verifier.VerifyAsync(command, Device);
        var second = await fixture.Verifier.VerifyAsync(command, Device);

        Assert.Equal(CommandVerificationStatus.Accepted, first.Status);
        Assert.Equal(Payload, first.Command?.Payload.ToArray());
        Assert.Equal(CommandVerificationStatus.Replay, second.Status);
        Assert.Null(second.Command);
        Assert.Equal(1, fixture.ReplayStore.ConsumedCount);
    }

    [Fact]
    public async Task Reusing_nonce_with_a_new_command_id_is_rejected()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);

        var first = await fixture.Verifier.VerifyAsync(CreateSigned(signer), Device);
        var second = await fixture.Verifier.VerifyAsync(CreateSigned(signer), Device);

        Assert.Equal(CommandVerificationStatus.Accepted, first.Status);
        Assert.Equal(CommandVerificationStatus.Replay, second.Status);
    }

    [Fact]
    public async Task Command_for_another_device_is_rejected_before_key_lookup()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);

        var result = await fixture.Verifier.VerifyAsync(CreateSigned(signer), new DeviceId(Guid.NewGuid()));

        Assert.Equal(CommandVerificationStatus.WrongTarget, result.Status);
        Assert.Equal(0, fixture.Keys.LookupCount);
    }

    [Theory]
    [InlineData(-301, 1)]
    [InlineData(31, 60)]
    [InlineData(0, 301)]
    [InlineData(-120, -1)]
    public async Task Expired_future_or_overlong_commands_are_rejected(int issuedOffset, int expiryOffset)
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        var command = CreateSigned(signer,
            issuedAt: Now.AddSeconds(issuedOffset),
            expiresAt: Now.AddSeconds(expiryOffset));

        var result = await fixture.Verifier.VerifyAsync(command, Device);

        Assert.Equal(CommandVerificationStatus.OutsideValidityWindow, result.Status);
        Assert.Equal(0, fixture.ReplayStore.ConsumedCount);
    }

    [Fact]
    public async Task Payload_tampering_invalidates_signature()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        var valid = CreateSigned(signer);
        var tampered = Copy(valid, payload: "{\"requested\":false}"u8.ToArray());

        var result = await fixture.Verifier.VerifyAsync(tampered, Device);

        Assert.Equal(CommandVerificationStatus.InvalidSignature, result.Status);
        Assert.Equal(0, fixture.ReplayStore.ConsumedCount);
    }

    [Fact]
    public async Task Nonce_tampering_invalidates_signature()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        var valid = CreateSigned(signer);
        var tampered = Copy(valid, nonce: "different-nonce-123456789");

        var result = await fixture.Verifier.VerifyAsync(tampered, Device);

        Assert.Equal(CommandVerificationStatus.InvalidSignature, result.Status);
        Assert.Equal(0, fixture.ReplayStore.ConsumedCount);
    }

    [Fact]
    public async Task Key_id_tampering_or_unknown_key_is_rejected()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        var valid = CreateSigned(signer);

        var result = await fixture.Verifier.VerifyAsync(Copy(valid, keyId: "other-key"), Device);

        Assert.Equal(CommandVerificationStatus.UnknownKey, result.Status);
        Assert.Equal(0, fixture.ReplayStore.ConsumedCount);
    }

    [Fact]
    public async Task Malformed_public_key_is_rejected()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        fixture.Keys.PublicKey = [1, 2, 3];

        var result = await fixture.Verifier.VerifyAsync(CreateSigned(signer), Device);

        Assert.Equal(CommandVerificationStatus.InvalidSignature, result.Status);
    }

    [Fact]
    public async Task Local_policy_denial_prevents_nonce_consumption()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        fixture.Policy.Allow = false;

        var result = await fixture.Verifier.VerifyAsync(CreateSigned(signer), Device);

        Assert.Equal(CommandVerificationStatus.DeniedByPolicy, result.Status);
        Assert.Equal(0, fixture.ReplayStore.ConsumedCount);
    }

    [Fact]
    public async Task Replay_storage_failure_never_returns_an_accepted_command()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        fixture.ReplayStore.Fail = true;

        await Assert.ThrowsAsync<IOException>(async () =>
            await fixture.Verifier.VerifyAsync(CreateSigned(signer), Device));
    }

    [Theory]
    [InlineData("dangerous command", "unique-nonce-123456789", 1)]
    [InlineData("Inventory.Refresh", "short", 1)]
    [InlineData("Inventory.Refresh", "unique-nonce-123456789", 2)]
    public async Task Malformed_command_fields_are_rejected(string commandType, string nonce, int version)
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        var command = CreateSigned(signer,
            commandType: commandType, nonce: nonce, version: version);

        var result = await fixture.Verifier.VerifyAsync(command, Device);

        Assert.Equal(CommandVerificationStatus.InvalidEnvelope, result.Status);
    }

    [Fact]
    public async Task Oversize_payload_is_rejected_before_key_lookup()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        var command = CreateSigned(signer, payload: new byte[64 * 1024 + 1]);

        var result = await fixture.Verifier.VerifyAsync(command, Device);

        Assert.Equal(CommandVerificationStatus.InvalidEnvelope, result.Status);
        Assert.Equal(0, fixture.Keys.LookupCount);
    }

    [Fact]
    public async Task Signing_material_is_bound_to_the_original_payload_copy()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(signer);
        var mutablePayload = Payload.ToArray();
        var command = CreateSigned(signer, payload: mutablePayload);
        mutablePayload[0] = 0;

        var result = await fixture.Verifier.VerifyAsync(command, Device);

        Assert.Equal(CommandVerificationStatus.Accepted, result.Status);
        Assert.Equal(Payload, result.Command?.Payload.ToArray());
    }

    private static TestFixture CreateFixture(ECDsa signer)
    {
        var keys = new TestKeys(signer.ExportSubjectPublicKeyInfo());
        var replayStore = new TestReplayStore();
        var policy = new TestPolicy();
        var verifier = new SignedCommandVerifier(keys, replayStore, policy, new FixedClock());
        return new(verifier, keys, replayStore, policy);
    }

    private static SignedCommandEnvelope CreateSigned(
        ECDsa signer,
        byte[]? payload = null,
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null,
        string commandType = "Inventory.Refresh",
        string nonce = Nonce,
        int version = 1)
    {
        var unsigned = new SignedCommandEnvelope(
            Device, Guid.NewGuid(), commandType, payload ?? Payload,
            issuedAt ?? Now, expiresAt ?? Now.AddMinutes(1), nonce, "key-1", [], version);
        var signature = signer.SignData(
            unsigned.GetSigningBytes(), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return Copy(unsigned, signature: signature);
    }

    private static SignedCommandEnvelope Copy(
        SignedCommandEnvelope original,
        byte[]? payload = null,
        string? keyId = null,
        string? nonce = null,
        byte[]? signature = null) =>
        new(original.TargetDeviceId, original.CommandId, original.CommandType,
            payload ?? original.Payload.ToArray(), original.IssuedAt, original.ExpiresAt,
            nonce ?? original.Nonce, keyId ?? original.SigningKeyId,
            signature ?? original.Signature.ToArray(), original.FormatVersion);

    private sealed record TestFixture(
        SignedCommandVerifier Verifier,
        TestKeys Keys,
        TestReplayStore ReplayStore,
        TestPolicy Policy);

    private sealed class FixedClock : IClock
    {
        public DateTimeOffset UtcNow => Now;
    }

    private sealed class TestKeys(byte[] publicKey) : ICommandVerificationKeys
    {
        public byte[] PublicKey { get; set; } = publicKey;
        public int LookupCount { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>?> FindPublicKeyAsync(
            DeviceId targetDeviceId, string keyId, CancellationToken cancellationToken = default)
        {
            LookupCount++;
            ReadOnlyMemory<byte>? key = targetDeviceId == Device && keyId == "key-1"
                ? PublicKey : null;
            return ValueTask.FromResult(key);
        }
    }

    private sealed class TestReplayStore : ICommandReplayStore
    {
        private readonly HashSet<string> _nonces = new(StringComparer.Ordinal);
        private readonly HashSet<string> _commandIds = new(StringComparer.Ordinal);
        public int ConsumedCount => _nonces.Count;
        public bool Fail { get; set; }

        public ValueTask<bool> TryConsumeAsync(
            DeviceId targetDeviceId, Guid commandId, string nonce,
            DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
        {
            if (Fail)
            {
                throw new IOException("Replay store unavailable.");
            }

            var nonceKey = $"{targetDeviceId.Value:N}:{nonce}";
            var commandKey = $"{targetDeviceId.Value:N}:{commandId:N}";
            lock (_nonces)
            {
                if (_nonces.Contains(nonceKey) || _commandIds.Contains(commandKey))
                {
                    return ValueTask.FromResult(false);
                }

                _nonces.Add(nonceKey);
                _commandIds.Add(commandKey);
                return ValueTask.FromResult(true);
            }
        }
    }

    private sealed class TestPolicy : ICommandExecutionPolicy
    {
        public bool Allow { get; set; } = true;

        public ValueTask<bool> IsAllowedAsync(
            DeviceId targetDeviceId, string commandType, ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Allow &&
                targetDeviceId == Device &&
                commandType == "Inventory.Refresh" &&
                Encoding.UTF8.GetString(payload.Span) == Encoding.UTF8.GetString(Payload));
    }
}
