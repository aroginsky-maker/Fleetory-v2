namespace Fleetory.SharedKernel;

public sealed record DataProvenance(
    string SourceSystem,
    string? SourceRecordId,
    DateTimeOffset ObservedAt,
    DateTimeOffset? ReceivedAt,
    string Authority);
