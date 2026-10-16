namespace Fleetory.Platform.Contracts;

public enum ActorKind
{
    Anonymous = 0,
    Person = 1,
    System = 2,
    Service = 3
}

public sealed record ActorReference(
    string SubjectId,
    ActorKind Kind,
    string? DisplayName = null,
    PersonId? PersonId = null);

public interface ICurrentActorAccessor
{
    ActorReference Current { get; }
}
