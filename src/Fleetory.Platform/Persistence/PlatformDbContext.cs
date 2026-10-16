using Fleetory.Platform.Contracts;
using Microsoft.EntityFrameworkCore;

namespace Fleetory.Platform.Persistence;

public sealed class PlatformDbContext(DbContextOptions<PlatformDbContext> options) : DbContext(options)
{
    public const string SchemaName = "platform";

    internal DbSet<PersonProjectionRecord> People => Set<PersonProjectionRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.HasDefaultSchema(SchemaName);

        modelBuilder.Entity<PersonProjectionRecord>(entity =>
        {
            entity.Property(record => record.PersonId)
                .HasConversion(
                    id => id.Value,
                    value => new PersonId(value))
                .ValueGeneratedNever();

            entity.Property(record => record.Revision)
                .HasDefaultValue(1L);
        });
    }
}
