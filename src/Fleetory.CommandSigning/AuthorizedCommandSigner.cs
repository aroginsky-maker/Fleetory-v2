using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;

namespace Fleetory.CommandSigning;

public sealed record AuthorizedCommandSignature(string CallerId, SignedCommandEnvelope Envelope);

/// <summary>Applies the pinned caller and target policy before Transit access and envelope release.</summary>
public sealed class AuthorizedCommandSigner(
    SigningClientAuthorizationPolicy authorization,
    OpenBaoCommandSigner signer)
{
    public async Task<AuthorizedCommandSignature> SignInventoryRefreshAsync(
        X509Certificate2? authenticatedClientCertificate,
        DeviceId targetDeviceId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var caller = authorization.GetAuthorizedInventoryRefreshCaller(authenticatedClientCertificate, targetDeviceId)
            ?? throw new UnauthorizedAccessException("Signing caller or target is not authorized.");
        var envelope = await signer.SignInventoryRefreshAsync(targetDeviceId, cancellationToken);
        if (authorization.GetAuthorizedInventoryRefreshCaller(authenticatedClientCertificate, targetDeviceId) != caller)
        {
            throw new UnauthorizedAccessException("Signing authorization expired before envelope release.");
        }
        cancellationToken.ThrowIfCancellationRequested();
        return new AuthorizedCommandSignature(caller, envelope);
    }
}
