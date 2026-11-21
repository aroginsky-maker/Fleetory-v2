namespace Fleetory.Platform.Contracts;

public sealed record AuditExportEvent(
    Guid EventId,
    AuditRecord Record,
    DateTimeOffset RecordedAt);

/// <summary>
/// The sink must durably accept an event before returning and deduplicate by EventId.
/// A failed or uncertain delivery is retried with the same EventId.
/// </summary>
public interface IAuditExportSink
{
    ValueTask PublishAsync(
        AuditExportEvent auditEvent,
        CancellationToken cancellationToken = default);
}
