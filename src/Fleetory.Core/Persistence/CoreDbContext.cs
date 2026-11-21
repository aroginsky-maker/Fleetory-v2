using Fleetory.Core.Contracts;
using Microsoft.EntityFrameworkCore;

namespace Fleetory.Core.Persistence;

public sealed class CoreDbContext(DbContextOptions<CoreDbContext> options) : DbContext(options)
{
    public const string SchemaName = "core";

    internal DbSet<DeviceRecord> Devices => Set<DeviceRecord>();
    internal DbSet<AgentCertificateRecord> AgentCertificates => Set<AgentCertificateRecord>();
    internal DbSet<AgentEnrollmentGrantRecord> AgentEnrollmentGrants => Set<AgentEnrollmentGrantRecord>();
    internal DbSet<AgentRotationIntentRecord> AgentRotationIntents => Set<AgentRotationIntentRecord>();
    internal DbSet<AgentCertificateRecoveryRecord> AgentCertificateRecoveries =>
        Set<AgentCertificateRecoveryRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.HasDefaultSchema(SchemaName);

        modelBuilder.Entity<DeviceRecord>(entity =>
        {
            entity.Property(record => record.DeviceId)
                .HasConversion(
                    id => id.Value,
                    value => new DeviceId(value))
                .ValueGeneratedNever();

            entity.Property(record => record.Revision)
                .HasDefaultValue(1L);
        });

        modelBuilder.Entity<AgentCertificateRecord>(entity =>
        {
            entity.Property(record => record.DeviceId)
                .HasConversion(
                    id => id.Value,
                    value => new DeviceId(value))
                .ValueGeneratedNever();

            entity.HasOne<DeviceRecord>()
                .WithMany()
                .HasForeignKey(record => record.DeviceId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<AgentEnrollmentGrantRecord>(entity =>
        {
            entity.Property(record => record.DeviceId)
                .HasConversion(
                    id => id.Value,
                    value => new DeviceId(value))
                .ValueGeneratedNever();

            entity.HasOne<DeviceRecord>()
                .WithMany()
                .HasForeignKey(record => record.DeviceId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne<AgentCertificateRecoveryRecord>()
                .WithMany()
                .HasForeignKey(record => record.RecoveryRequestId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(record => record.ExpiresAt);
        });

        modelBuilder.Entity<AgentRotationIntentRecord>(entity =>
        {
            entity.Property(record => record.DeviceId)
                .HasConversion(id => id.Value, value => new DeviceId(value))
                .ValueGeneratedNever();

            entity.HasOne<DeviceRecord>()
                .WithMany()
                .HasForeignKey(record => record.DeviceId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(record => record.ExpiresAt);
        });

        modelBuilder.Entity<AgentCertificateRecoveryRecord>(entity =>
        {
            entity.Property(record => record.DeviceId)
                .HasConversion(id => id.Value, value => new DeviceId(value))
                .ValueGeneratedNever();

            entity.HasOne<DeviceRecord>()
                .WithMany()
                .HasForeignKey(record => record.DeviceId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(record => record.ExpiresAt);
        });
    }
}
