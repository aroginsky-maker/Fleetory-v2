using Fleetory.Agent.Security;

namespace Fleetory.Core.Tests;

public sealed class AgentTrustKeyReadTests
{
    [Fact]
    public async Task Exact_limit_is_read_across_short_reads_without_owning_the_stream()
    {
        using var stream = new GrowingTrustStream(1024);

        var bytes = await DirectoryCommandVerificationKeys.ReadPublicKeyBytesAsync(stream);

        Assert.Equal(Enumerable.Repeat((byte)0x5A, 1024), bytes);
        Assert.Equal(1024, stream.BytesRead);
        Assert.True(stream.ReadCalls > 1);
        Assert.True(stream.CanRead);
    }

    [Fact]
    public async Task Growth_beyond_declared_length_stops_after_one_overflow_byte()
    {
        using var stream = new GrowingTrustStream(16 * 1024);
        Assert.Equal(1, stream.Length);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await DirectoryCommandVerificationKeys.ReadPublicKeyBytesAsync(stream));

        Assert.Equal(1025, stream.BytesRead);
        Assert.InRange(stream.LargestRequest, 1, 1025);
        Assert.True(stream.CanRead);
    }

    [Fact]
    public async Task Empty_content_fails_without_disposing_the_callers_stream()
    {
        using var stream = new GrowingTrustStream(0);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await DirectoryCommandVerificationKeys.ReadPublicKeyBytesAsync(stream));

        Assert.Equal(0, stream.BytesRead);
        Assert.True(stream.CanRead);
    }

    [Fact]
    public async Task Already_cancelled_reads_do_not_consume_content()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        using var stream = new GrowingTrustStream(32);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await DirectoryCommandVerificationKeys.ReadPublicKeyBytesAsync(stream, cancellation.Token));

        Assert.Equal(0, stream.ReadCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancellation_during_a_read_or_at_eof_withholds_key_bytes(bool atEnd)
    {
        using var cancellation = new CancellationTokenSource();
        using var stream = new GrowingTrustStream(32, eof =>
        {
            if (eof == atEnd) { cancellation.Cancel(); }
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await DirectoryCommandVerificationKeys.ReadPublicKeyBytesAsync(stream, cancellation.Token));

        Assert.True(cancellation.IsCancellationRequested);
        Assert.True(stream.CanRead);
    }

    // Models a file which grew after metadata inspection, short reads and an I/O
    // implementation that does not itself honor the supplied cancellation token.
    private sealed class GrowingTrustStream(int actualLength, Action<bool>? observedRead = null) : Stream
    {
        private bool _disposed;
        public int BytesRead { get; private set; }
        public int ReadCalls { get; private set; }
        public int LargestRequest { get; private set; }
        public override bool CanRead => !_disposed;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => 1;
        public override long Position { get => BytesRead; set => throw new NotSupportedException(); }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ReadCalls++;
            LargestRequest = Math.Max(LargestRequest, buffer.Length);
            var count = Math.Min(Math.Min(buffer.Length, 7), actualLength - BytesRead);
            buffer.Span[..count].Fill(0x5A);
            BytesRead += count;
            observedRead?.Invoke(count == 0);
            return ValueTask.FromResult(count);
        }

        protected override void Dispose(bool disposing) { _disposed = true; base.Dispose(disposing); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
