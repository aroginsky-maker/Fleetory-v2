using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
[Migration("202610160003_AddAuditExportLease")]
public sealed class AddAuditExportLease : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<int>(
            name: "attempt_count",
            schema: PlatformDbContext.SchemaName,
            table: "audit_export_queue",
            type: "integer",
            nullable: false,
            defaultValue: 0);

        migrationBuilder.AddColumn<DateTimeOffset>(
            name: "next_attempt_at",
            schema: PlatformDbContext.SchemaName,
            table: "audit_export_queue",
            type: "timestamp with time zone",
            nullable: false,
            defaultValueSql: "CURRENT_TIMESTAMP");

        migrationBuilder.AddColumn<Guid>(
            name: "lease_id",
            schema: PlatformDbContext.SchemaName,
            table: "audit_export_queue",
            type: "uuid",
            nullable: true);

        migrationBuilder.AddColumn<DateTimeOffset>(
            name: "leased_until",
            schema: PlatformDbContext.SchemaName,
            table: "audit_export_queue",
            type: "timestamp with time zone",
            nullable: true);

        migrationBuilder.CreateIndex(
            name: "IX_audit_export_queue_due",
            schema: PlatformDbContext.SchemaName,
            table: "audit_export_queue",
            columns: ["next_attempt_at", "enqueued_at"]);

        migrationBuilder.AddCheckConstraint(
            name: "CK_audit_export_queue_lease_pair",
            schema: PlatformDbContext.SchemaName,
            table: "audit_export_queue",
            sql: "(lease_id IS NULL) = (leased_until IS NULL)");

        migrationBuilder.AddCheckConstraint(
            name: "CK_audit_export_queue_attempt_count",
            schema: PlatformDbContext.SchemaName,
            table: "audit_export_queue",
            sql: "attempt_count >= 0");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex("IX_audit_export_queue_due", "audit_export_queue", PlatformDbContext.SchemaName);
        migrationBuilder.DropCheckConstraint("CK_audit_export_queue_lease_pair", "audit_export_queue", PlatformDbContext.SchemaName);
        migrationBuilder.DropCheckConstraint("CK_audit_export_queue_attempt_count", "audit_export_queue", PlatformDbContext.SchemaName);
        migrationBuilder.DropColumn("attempt_count", "audit_export_queue", PlatformDbContext.SchemaName);
        migrationBuilder.DropColumn("next_attempt_at", "audit_export_queue", PlatformDbContext.SchemaName);
        migrationBuilder.DropColumn("lease_id", "audit_export_queue", PlatformDbContext.SchemaName);
        migrationBuilder.DropColumn("leased_until", "audit_export_queue", PlatformDbContext.SchemaName);
    }
}
