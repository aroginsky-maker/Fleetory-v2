using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fleetory.Core.Contracts;

namespace Fleetory.CommandSigning;

public sealed record AuthorizedCommandSignature(string CallerId, SignedCommandEnvelope Envelope);

/// <summary>Applies the pinned caller and target policy before Transit access and envelope release.</summary>
public sealed class AuthorizedCommandSigner(
    SigningClientAuthorizationPolicy authorization,
    OpenBaoCommandSigner signer,
    ISigningRequestJournal journal,
    ISigningClientRevocations revocations)
{
    public async Task<AuthorizedCommandSignature> SignInventoryRefreshAsync(
        Guid requestId,
        X509Certificate2? authenticatedClientCertificate,
        DeviceId targetDeviceId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException("A signing RequestId is required.", nameof(requestId));
        }
        var caller = authorization.GetAuthorizedInventoryRefreshCaller(authenticatedClientCertificate, targetDeviceId)
            ?? throw new UnauthorizedAccessException("Signing caller or target is not authorized.");
        var request = new SigningRequest(requestId, caller,
            authenticatedClientCertificate!.GetCertHashString(HashAlgorithmName.SHA256), targetDeviceId);
        await revocations.EnsureNotRevokedAsync(request.ClientCertificateSha256, cancellationToken);
        if (!await journal.TryBeginAsync(request, cancellationToken))
        {
            throw new SigningRequestConflictException();
        }
        await EnsureAuthorizedAsync(authenticatedClientCertificate, request, cancellationToken);
        var envelope = await signer.SignInventoryRefreshAsync(targetDeviceId, cancellationToken);
        await EnsureAuthorizedAsync(authenticatedClientCertificate, request, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        await journal.CompleteAsync(request, envelope, cancellationToken);
        await EnsureAuthorizedAsync(authenticatedClientCertificate, request, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return new AuthorizedCommandSignature(caller, envelope);
    }

    private async Task EnsureAuthorizedAsync(X509Certificate2? certificate, SigningRequest request,
        CancellationToken cancellationToken)
    {
        if (authorization.GetAuthorizedInventoryRefreshCaller(certificate, request.TargetDeviceId) != request.CallerId)
        {
            throw new UnauthorizedAccessException("Signing authorization expired before envelope release.");
        }
        await revocations.EnsureNotRevokedAsync(request.ClientCertificateSha256, cancellationToken);
    }
}
