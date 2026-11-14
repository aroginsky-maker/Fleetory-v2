#requires -Version 7.3
# Disposable fixture process capture only. No captured content is included in errors.
if ($null -eq ('Fleetory.Tests.PilotCaptureStream' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Fleetory.Tests
{
    public sealed class PilotCaptureStream : MemoryStream
    {
        private readonly long limit;
        public PilotCaptureStream(long maxBytes)
        {
            if (maxBytes < 1 || maxBytes > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(maxBytes), "Invalid capture limit.");
            limit = maxBytes;
        }

        private void Check(int count)
        {
            if (count < 0 || Position > limit - count)
                throw new IOException("Fixture capture limit exceeded.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Check(count);
            base.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Check(buffer.Length);
            base.Write(buffer);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override void WriteByte(byte value)
        {
            Check(1);
            base.WriteByte(value);
        }

        public override void SetLength(long value)
        {
            if (value < 0 || value > limit)
                throw new IOException("Fixture capture limit exceeded.");
            base.SetLength(value);
        }

        public override int Capacity
        {
            get => base.Capacity;
            set
            {
                if (value < 0)
                    throw new IOException("Fixture capture limit exceeded.");
                base.Capacity = (int)Math.Min(value, limit);
            }
        }
    }
}
"@
}
