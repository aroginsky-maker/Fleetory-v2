using Fleetory.Core.Contracts;

namespace Fleetory.CommandSigning;

public sealed record SigningRequest(
    Guid RequestId, string CallerId, string ClientCertificateSha256, DeviceId TargetDeviceId);

/// <summary>Durable reservation and completion. An unfinished reservation must never be retried automatically.</summary>
public interface ISigningRequestJournal
{
    Task<bool> TryBeginAsync(SigningRequest request, CancellationToken cancellationToken = default);
    Task CompleteAsync(SigningRequest request, SignedCommandEnvelope envelope, CancellationToken cancellationToken = default);
}
