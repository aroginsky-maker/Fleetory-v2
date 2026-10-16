using Fleetory.Core.Contracts;
using Microsoft.EntityFrameworkCore;

namespace Fleetory.Core.Persistence;

public sealed class CoreDbContext(DbContextOptions<CoreDbContext> options) : DbContext(options)
{
    public const string SchemaName = "core";

    internal DbSet<DeviceRecord> Devices => Set<DeviceRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.HasDefaultSchema(SchemaName);

        modelBuilder.Entity<DeviceRecord>(entity =>
        {
            entity.ToTable("devices", SchemaName);
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
