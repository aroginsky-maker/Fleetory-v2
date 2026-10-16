using Fleetory.SharedKernel;

namespace Fleetory.Platform.Contracts;

public sealed record AuditTarget(
    string Type,
    string Id);

public sealed record AuditRecord(
    ActorReference Actor,
    string Action,
    AuditTarget? Target,
    CorrelationId CorrelationId,
    DateTimeOffset OccurredAt,
    IReadOnlyDictionary<string, string>? Context = null);

public interface IAuditWriter
{
    ValueTask WriteAsync(
        AuditRecord record,
        CancellationToken cancellationToken = default);
}
