namespace Fleetory.ModuleAbstractions;

/// <summary>Returns bounded bytes, or null on overflow, without owning the input stream.</summary>
public static class BoundedStreamReader
{
    public static async Task<byte[]?> ReadAsync(Stream stream, long maximumBytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegative(maximumBytes);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = maximumBytes - buffer.Length;
            var readSize = (int)Math.Min(chunk.Length, Math.Max(1, remaining));
            var count = await stream.ReadAsync(chunk.AsMemory(0, readSize), cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return buffer.ToArray();
            }
            if (count > remaining) { return null; }
            await buffer.WriteAsync(chunk.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
        }
    }
}
