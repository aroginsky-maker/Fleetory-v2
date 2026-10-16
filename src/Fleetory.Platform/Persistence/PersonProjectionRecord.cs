using Fleetory.Platform.Contracts;

namespace Fleetory.Platform.Persistence;

internal sealed class PersonProjectionRecord
{
    private PersonProjectionRecord()
    {
    }

    private PersonProjectionRecord(
        PersonId personId,
        string displayName,
        DateTimeOffset updatedAt)
    {
        PersonId = personId;
        DisplayName = displayName;
        UpdatedAt = updatedAt.ToUniversalTime();
        Revision = 1;
    }

    public PersonId PersonId { get; private set; }

    public string DisplayName { get; private set; } = string.Empty;

    public DateTimeOffset UpdatedAt { get; private set; }

    public long Revision { get; private set; }

    public static PersonProjectionRecord Create(
        PersonId personId,
        string displayName,
        DateTimeOffset updatedAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        return new PersonProjectionRecord(personId, displayName, updatedAt);
    }

    public void UpdateDisplayName(string displayName, DateTimeOffset updatedAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        DisplayName = displayName;
        UpdatedAt = updatedAt.ToUniversalTime();
        Revision = checked(Revision + 1);
    }
}
