using Fleetory.Agent.Security;
using Fleetory.CommandSigning;
using Fleetory.Core.Contracts;
using Fleetory.SharedKernel;
using Npgsql;

namespace Fleetory.Core.Tests;

public sealed class CommandEnvelopeBoundsTests
{
    private static readonly DeviceId Device = new(Guid.Parse("74fe4079-b2d7-4c1f-b349-a5c12d39b167"));
    private static readonly DateTimeOffset Now = new(2026, 10, 31, 18, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(8 * 1024 * 1024, 64)]
    [InlineData(0, 8 * 1024 * 1024)]
    public async Task Agent_rejects_oversized_fields_without_copying_them(int payloadLength, int signatureLength)
    {
        var boundary = new UnexpectedBoundary();
        var verifier = new SignedCommandVerifier(boundary, boundary, boundary, boundary);
        Assert.Equal(CommandVerificationStatus.InvalidEnvelope,
            (await verifier.VerifyAsync(Envelope(0, 0), Device)).Status);
        var envelope = Envelope(payloadLength, signatureLength);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var pending = verifier.VerifyAsync(envelope, Device);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(pending.IsCompletedSuccessfully);
        var result = await pending;
        Assert.Equal(CommandVerificationStatus.InvalidEnvelope, result.Status);
        Assert.Null(result.Command);
        Assert.InRange(allocated, 0L, 512 * 1024 - 1);
    }

    [Theory]
    [InlineData(8 * 1024 * 1024, 64)]
    [InlineData(0, 8 * 1024 * 1024)]
    public async Task Journal_rejects_oversized_fields_without_copying_or_opening_a_connection(int payloadLength, int signatureLength)
    {
        await using var source = NpgsqlDataSource.Create(
            "Host=127.0.0.1;Port=1;Database=unused;Username=fleetory_test;Pooling=false;Timeout=1");
        var journal = new PostgreSqlSigningRequestJournal(source);
        var request = new SigningRequest(Guid.NewGuid(), "allocation-test", new string('A', 64), Device);
        await Assert.ThrowsAsync<ArgumentException>(() => journal.CompleteAsync(request, Envelope(1, 0)));
        var envelope = Envelope(payloadLength, signatureLength);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var pending = journal.CompleteAsync(request, envelope);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        await Assert.ThrowsAsync<ArgumentException>(() => pending);
        Assert.InRange(allocated, 0L, 512 * 1024 - 1);
    }

    [Fact]
    public void Length_metadata_preserves_constructor_and_accessor_copy_isolation()
    {
        byte[] payload = [1, 2, 3];
        var signature = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();
        var expectedSignature = signature.ToArray();
        var envelope = new SignedCommandEnvelope(Device, Guid.NewGuid(), AgentCommandTypes.InventoryRefresh,
            payload, Now, Now.AddMinutes(1), "allocation-test-nonce", "allocation-key", signature);
        var signingBytes = envelope.GetSigningBytes();
        payload[0] = 99;
        signature[0] = 99;
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(envelope.Payload, out var payloadCopy));
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(envelope.Signature, out var signatureCopy));
        payloadCopy.Array![payloadCopy.Offset] = 88;
        signatureCopy.Array![signatureCopy.Offset] = 88;

        Assert.Equal(3, envelope.PayloadLength);
        Assert.Equal(64, envelope.SignatureLength);
        Assert.Equal(new byte[] { 1, 2, 3 }, envelope.Payload.ToArray());
        Assert.Equal(expectedSignature, envelope.Signature.ToArray());
        Assert.Equal(signingBytes, envelope.GetSigningBytes());
    }

    private static SignedCommandEnvelope Envelope(int payloadLength, int signatureLength) =>
        new(Device, Guid.NewGuid(), AgentCommandTypes.InventoryRefresh, new byte[payloadLength],
            Now, Now.AddMinutes(1), "allocation-test-nonce", "allocation-key", new byte[signatureLength]);

    private sealed class UnexpectedBoundary : ICommandVerificationKeys, ICommandExecutionPolicy, ICommandReplayStore, IClock
    {
        public DateTimeOffset UtcNow => Now;

        public ValueTask<ReadOnlyMemory<byte>?> FindPublicKeyAsync(DeviceId targetDeviceId, string keyId,
            CancellationToken cancellationToken = default) => throw Unexpected();

        public ValueTask<bool> IsAllowedAsync(DeviceId targetDeviceId, string commandType, ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken = default) => throw Unexpected();

        public ValueTask<bool> TryConsumeAsync(DeviceId targetDeviceId, Guid commandId, string nonce,
            DateTimeOffset expiresAt, CancellationToken cancellationToken = default) => throw Unexpected();

        private static InvalidOperationException Unexpected() => new("Malformed input reached a security dependency.");
    }
}
