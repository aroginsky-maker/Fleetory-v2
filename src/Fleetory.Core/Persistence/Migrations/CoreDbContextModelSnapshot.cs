using Fleetory.Core.Contracts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Core.Persistence.Migrations;

[DbContext(typeof(CoreDbContext))]
public sealed class CoreDbContextModelSnapshot : ModelSnapshot
{
    protected override void BuildModel(ModelBuilder modelBuilder)
    {
        modelBuilder.HasAnnotation("ProductVersion", "10.0.12");
        modelBuilder.HasDefaultSchema(CoreDbContext.SchemaName);

        modelBuilder.Entity<DeviceRecord>(entity =>
        {
            entity.ToTable("devices", CoreDbContext.SchemaName);
            entity.HasKey(record => record.DeviceId);

            entity.Property(record => record.DeviceId)
                .HasConversion(
                    id => id.Value,
                    value => new DeviceId(value))
                .ValueGeneratedNever()
                .HasColumnName("device_id")
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
