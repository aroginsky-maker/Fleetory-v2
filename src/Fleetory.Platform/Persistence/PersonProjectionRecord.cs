using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Fleetory.Platform.Contracts;

namespace Fleetory.Platform.Persistence;

[Table("person_projections", Schema = PlatformDbContext.SchemaName)]
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

    [Key]
    [Column("person_id", TypeName = "uuid")]
    public PersonId PersonId { get; private set; }

    [Required]
    [MaxLength(256)]
    [Column("display_name")]
    public string DisplayName { get; private set; } = string.Empty;

    [Required]
    [Column("updated_at", TypeName = "timestamp with time zone")]
    public DateTimeOffset UpdatedAt { get; private set; }

    [ConcurrencyCheck]
    [Column("revision")]
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
