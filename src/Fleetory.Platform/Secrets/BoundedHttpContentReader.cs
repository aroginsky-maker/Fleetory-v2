namespace Fleetory.Platform.Secrets;

/// <summary>Bounds external response bytes while honoring the caller's complete operation deadline.</summary>
internal static class BoundedHttpContentReader
{
    public static async Task<byte[]> ReadAsync(HttpContent content, int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) != 0)
        {
            if (buffer.Length + count > maximumBytes)
            {
                throw new InvalidOperationException("External service response is too large.");
            }
            await buffer.WriteAsync(chunk.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
        }
        cancellationToken.ThrowIfCancellationRequested();
        return buffer.ToArray();
    }
}
