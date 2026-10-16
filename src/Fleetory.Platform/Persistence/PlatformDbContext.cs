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
            entity.ToTable("person_projections", SchemaName);
            entity.HasKey(record => record.PersonId);

            entity.Property(record => record.PersonId)
                .HasConversion(
                    id => id.Value,
                    value => new PersonId(value))
                .ValueGeneratedNever()
                .HasColumnName("person_id")
                .HasColumnType("uuid");

            entity.Property(record => record.DisplayName)
                .IsRequired()
                .HasMaxLength(256)
                .HasColumnName("display_name");

            entity.Property(record => record.UpdatedAt)
                .IsRequired()
                .HasColumnName("updated_at")
                .HasColumnType("timestamp with time zone");

            entity.Property(record => record.Revision)
                .IsConcurrencyToken()
                .HasDefaultValue(1L)
                .HasColumnName("revision");
        });
    }
}
