using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
[Migration("202610160001_AddPlatformAuditOutbox")]
public sealed class AddPlatformAuditOutbox : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "audit_events",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                event_id = table.Column<Guid>(type: "uuid", nullable: false),
                actor_subject_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                actor_kind = table.Column<int>(type: "integer", nullable: false),
                action = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                target_type = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                target_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                correlation_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                recorded_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                context_json = table.Column<string>(type: "jsonb", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_audit_events", row => row.event_id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_audit_events_occurred_at",
            schema: PlatformDbContext.SchemaName,
            table: "audit_events",
            column: "occurred_at");

        migrationBuilder.CreateTable(
            name: "audit_export_queue",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                audit_event_id = table.Column<Guid>(type: "uuid", nullable: false),
                enqueued_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_audit_export_queue", row => row.audit_event_id);
                table.ForeignKey(
                    name: "FK_audit_export_queue_audit_events_audit_event_id",
                    column: row => row.audit_event_id,
                    principalSchema: PlatformDbContext.SchemaName,
                    principalTable: "audit_events",
                    principalColumn: "event_id",
                    onDelete: ReferentialAction.Restrict);
            });

        migrationBuilder.CreateIndex(
            name: "IX_audit_export_queue_enqueued_at",
            schema: PlatformDbContext.SchemaName,
            table: "audit_export_queue",
            column: "enqueued_at");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable("audit_export_queue", PlatformDbContext.SchemaName);
        migrationBuilder.DropTable("audit_events", PlatformDbContext.SchemaName);
    }
}
