namespace Fleetory.CommandSigning;

/// <summary>Reads current certificate revocations without caching; read failures must prevent signing.</summary>
public interface ISigningClientRevocations
{
    Task EnsureNotRevokedAsync(string certificateSha256, CancellationToken cancellationToken = default);
}
