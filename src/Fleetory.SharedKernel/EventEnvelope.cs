namespace Fleetory.SharedKernel;

public sealed record EventSubject(string Type, string Id);

public sealed record EventEnvelope
{
    public required Guid EventId { get; init; }

    public required string EventType { get; init; }

    public required int SchemaVersion { get; init; }

    public required DateTimeOffset OccurredAt { get; init; }

    public required CorrelationId CorrelationId { get; init; }

    public Guid? CausationId { get; init; }

    public required string Producer { get; init; }

    public EventSubject? Subject { get; init; }
}
