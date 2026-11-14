using Fleetory.ModuleAbstractions;

namespace Fleetory.Platform.Secrets;

/// <summary>Bounds external response bytes while honoring the caller's complete operation deadline.</summary>
internal static class BoundedHttpContentReader
{
    public static async Task<byte[]> ReadAsync(HttpContent content, int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return await BoundedStreamReader.ReadAsync(stream, maximumBytes, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("External service response is too large.");
    }
}
