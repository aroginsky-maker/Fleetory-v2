using System.Security.Cryptography;
using Fleetory.Agent.Security;
using Fleetory.Core.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Core.Tests;

public sealed class SignedCommandDeadlineTests
{
    private static readonly DeviceId Device = new(Guid.Parse("be7675ae-712f-4886-b729-9f3a89df70d1"));
    private static readonly DateTimeOffset Now = new(2026, 10, 16, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("key", 60)]
    [InlineData("policy", 60)]
    [InlineData("replay", 60)]
    [InlineData("key", -31)]
    [InlineData("policy", -31)]
    [InlineData("replay", -31)]
    public async Task A_command_outside_its_window_after_an_async_boundary_is_not_accepted(
        string boundary, int clockOffset)
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = new DelayedSecurityBoundary(signer, boundary);
        var command = Sign(signer);
        var verification = fixture.Verifier.VerifyAsync(command, Device).AsTask();
        try
        {
            await fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            fixture.Clock.UtcNow = Now.AddSeconds(clockOffset);
            fixture.Release.TrySetResult();
            var result = await verification.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(CommandVerificationStatus.OutsideValidityWindow, result.Status);
            Assert.Null(result.Command);
            Assert.Equal(boundary == "replay" ? 1 : 0, fixture.ConsumedCount);
            if (boundary == "key") { Assert.Equal(0, fixture.PolicyCalls); }

            // A commit followed by expiry cannot be undone, even if the clock recovers.
            fixture.Clock.UtcNow = Now;
            var retry = await fixture.Verifier.VerifyAsync(command, Device);
            Assert.Equal(boundary == "replay" ? CommandVerificationStatus.Replay :
                CommandVerificationStatus.Accepted, retry.Status);
            Assert.Equal(1, fixture.ConsumedCount);
        }
        finally { fixture.Release.TrySetResult(); }
    }

    [Theory]
    [InlineData("key", 59)]
    [InlineData("policy", 59)]
    [InlineData("replay", 59)]
    [InlineData("key", -30)]
    [InlineData("policy", -30)]
    [InlineData("replay", -30)]
    public async Task A_command_still_inside_its_window_after_waiting_is_accepted_once(
        string boundary, int clockOffset)
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = new DelayedSecurityBoundary(signer, boundary);
        var command = Sign(signer);
        var verification = fixture.Verifier.VerifyAsync(command, Device).AsTask();
        try
        {
            await fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            fixture.Clock.UtcNow = Now.AddSeconds(clockOffset);
            fixture.Release.TrySetResult();
            var result = await verification.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(CommandVerificationStatus.Accepted, result.Status);
            Assert.NotNull(result.Command);
            Assert.Equal(CommandVerificationStatus.Replay,
                (await fixture.Verifier.VerifyAsync(command, Device)).Status);
            Assert.Equal(1, fixture.ConsumedCount);
        }
        finally { fixture.Release.TrySetResult(); }
    }

    private static SignedCommandEnvelope Sign(ECDsa signer)
    {
        var unsigned = new SignedCommandEnvelope(Device, Guid.NewGuid(),
            AgentCommandTypes.InventoryRefresh, [], Now, Now.AddMinutes(1),
            "deadline-test-nonce", "deadline-test-key", []);
        var signature = signer.SignData(unsigned.GetSigningBytes(), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new(Device, unsigned.CommandId, unsigned.CommandType, [], Now, unsigned.ExpiresAt,
            unsigned.Nonce, unsigned.SigningKeyId, signature);
    }

    private sealed class MutableClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = Now;
    }

    private sealed class DelayedSecurityBoundary : ICommandVerificationKeys,
        ICommandExecutionPolicy, ICommandReplayStore
    {
        private readonly string _boundary;
        private readonly byte[] _publicKey;
        private readonly HashSet<Guid> _consumed = [];

        public DelayedSecurityBoundary(ECDsa signer, string boundary)
        {
            _boundary = boundary;
            _publicKey = signer.ExportSubjectPublicKeyInfo();
            Verifier = new SignedCommandVerifier(this, this, this, Clock);
        }

        public MutableClock Clock { get; } = new();
        public SignedCommandVerifier Verifier { get; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int ConsumedCount => _consumed.Count;
        public int PolicyCalls { get; private set; }

        public async ValueTask<ReadOnlyMemory<byte>?> FindPublicKeyAsync(
            DeviceId targetDeviceId, string keyId, CancellationToken cancellationToken = default)
        {
            await PauseAsync("key", cancellationToken);
            return _publicKey;
        }

        public async ValueTask<bool> IsAllowedAsync(DeviceId targetDeviceId,
            string commandType, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
        {
            PolicyCalls++;
            await PauseAsync("policy", cancellationToken);
            return true;
        }

        public async ValueTask<bool> TryConsumeAsync(DeviceId targetDeviceId,
            Guid commandId, string nonce, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            if (!_consumed.Add(commandId)) { return false; }
            await PauseAsync("replay", cancellationToken);
            return true;
        }

        private async Task PauseAsync(string boundary, CancellationToken cancellationToken)
        {
            if (_boundary != boundary) { return; }
            Entered.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
        }
    }
}
