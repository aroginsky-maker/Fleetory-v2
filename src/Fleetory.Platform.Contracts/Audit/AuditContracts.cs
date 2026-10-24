using System.Data.Common;
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

    /// <summary>
    /// Appends the event and export entry to the caller's active PostgreSQL transaction.
    /// The caller owns the commit or rollback.
    /// </summary>
    ValueTask WriteInTransactionAsync(
        AuditRecord record,
        DbTransaction transaction,
        CancellationToken cancellationToken = default);
}
