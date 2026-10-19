using System.Security.Cryptography;
using Fleetory.Agent.Security;
using Fleetory.Core.Contracts;
using Fleetory.SharedKernel;

namespace Fleetory.Core.Tests;

public sealed class AgentCommandExecutionGateTests
{
    [Fact]
    public async Task Verified_command_reaches_handler_once_even_after_gate_restart()
    {
        using var fixture = new GateFixture();
        var envelope = fixture.Sign();

        Assert.Equal(CommandVerificationStatus.Accepted,
            await fixture.Gate.ExecuteAsync(envelope));
        Assert.Equal([envelope.CommandId], fixture.Handler.CommandIds);
        Assert.Equal(CommandVerificationStatus.Replay,
            await fixture.Gate.ExecuteAsync(envelope));

        var restarted = fixture.CreateGate();
        Assert.Equal(CommandVerificationStatus.Replay,
            await restarted.ExecuteAsync(envelope));
        Assert.Single(fixture.Handler.CommandIds);
    }

    [Fact]
    public async Task Invalid_target_signature_key_and_policy_never_reach_handler()
    {
        using var fixture = new GateFixture();
        Assert.Equal(CommandVerificationStatus.WrongTarget,
            await fixture.Gate.ExecuteAsync(fixture.Sign(target: new DeviceId(Guid.NewGuid()))));
        Assert.Equal(CommandVerificationStatus.InvalidSignature,
            await fixture.Gate.ExecuteAsync(fixture.Sign(tamperSignature: true)));
        Assert.Equal(CommandVerificationStatus.DeniedByPolicy,
            await fixture.Gate.ExecuteAsync(fixture.Sign(payload: "{}"u8.ToArray())));
        Assert.Equal(CommandVerificationStatus.DeniedByPolicy,
            await fixture.Gate.ExecuteAsync(fixture.Sign(commandType: "Shell.Execute")));

        File.Delete(fixture.TrustPath);
        Assert.Equal(CommandVerificationStatus.UnknownKey,
            await fixture.Gate.ExecuteAsync(fixture.Sign()));
        Assert.Empty(fixture.Handler.CommandIds);
    }

    [Fact]
    public async Task Handler_failure_propagates_and_consumed_command_cannot_execute_again()
    {
        using var fixture = new GateFixture();
        fixture.Handler.Fail = true;
        var envelope = fixture.Sign();

        await Assert.ThrowsAsync<IOException>(async () =>
            await fixture.Gate.ExecuteAsync(envelope));
        fixture.Handler.Fail = false;
        Assert.Equal(CommandVerificationStatus.Replay,
            await fixture.Gate.ExecuteAsync(envelope));
        Assert.Equal([envelope.CommandId], fixture.Handler.CommandIds);
    }

    private sealed class GateFixture : IDisposable
    {
        private readonly ECDsa _signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(), $"fleetory-command-gate-{Guid.NewGuid():N}");
        private readonly string _replayPath;
        private readonly string _trustDirectory;

        public GateFixture()
        {
            Device = new DeviceId(Guid.NewGuid());
            _trustDirectory = Path.Combine(_directory, "trust");
            _replayPath = Path.Combine(_directory, "replay.db");
            Directory.CreateDirectory(_trustDirectory);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(_directory,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                File.SetUnixFileMode(_trustDirectory,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            TrustPath = Path.Combine(_trustDirectory, $"{Device.Value:N}-test-v1.spki");
            File.WriteAllBytes(TrustPath, _signer.ExportSubjectPublicKeyInfo());
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(TrustPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            Handler = new TestHandler();
            Gate = CreateGate();
        }

        public DeviceId Device { get; }
        public string TrustPath { get; }
        public TestHandler Handler { get; }
        public AgentCommandExecutionGate Gate { get; }

        public AgentCommandExecutionGate CreateGate() => AgentCommandExecutionGate.Create(
            Device, _trustDirectory, _replayPath, new SystemClock(), Handler);

        public SignedCommandEnvelope Sign(
            DeviceId? target = null,
            byte[]? payload = null,
            string commandType = AgentCommandTypes.InventoryRefresh,
            bool tamperSignature = false)
        {
            var now = DateTimeOffset.UtcNow;
            var unsigned = new SignedCommandEnvelope(
                target ?? Device, Guid.NewGuid(), commandType, payload ?? [],
                now, now.AddMinutes(1), Guid.NewGuid().ToString("N"), "test-v1", []);
            var signature = _signer.SignData(
                unsigned.GetSigningBytes(), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (tamperSignature) { signature[0] ^= 0xff; }
            return new SignedCommandEnvelope(
                unsigned.TargetDeviceId, unsigned.CommandId, unsigned.CommandType,
                unsigned.Payload.Span, unsigned.IssuedAt, unsigned.ExpiresAt,
                unsigned.Nonce, unsigned.SigningKeyId, signature);
        }

        public void Dispose()
        {
            _signer.Dispose();
            var target = Path.GetFullPath(_directory);
            var tempRoot = Path.GetFullPath(Path.GetTempPath());
            if (!target.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(target).StartsWith("fleetory-command-gate-", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Test cleanup escaped its temporary directory.");
            }

            Directory.Delete(target, recursive: true);
        }
    }

    private sealed class TestHandler : IAgentInventoryRefreshHandler
    {
        public List<Guid> CommandIds { get; } = [];
        public bool Fail { get; set; }

        public ValueTask RefreshAsync(Guid commandId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CommandIds.Add(commandId);
            if (Fail) { throw new IOException("Inventory handler failed."); }
            return ValueTask.CompletedTask;
        }
    }
}
