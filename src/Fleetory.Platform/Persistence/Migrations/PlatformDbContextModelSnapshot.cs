using Fleetory.Platform.Contracts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
public sealed class PlatformDbContextModelSnapshot : ModelSnapshot
{
    protected override void BuildModel(ModelBuilder modelBuilder)
    {
        modelBuilder.HasAnnotation("ProductVersion", "10.0.12");
        modelBuilder.HasDefaultSchema(PlatformDbContext.SchemaName);

        modelBuilder.Entity<PersonProjectionRecord>(entity =>
        {
            entity.ToTable("person_projections", PlatformDbContext.SchemaName);
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
