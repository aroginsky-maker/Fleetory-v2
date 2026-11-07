using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
[Migration("202610210002_AddAdminCertificateRegistrations")]
public sealed class AddAdminCertificateRegistrations : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "admin_certificate_registrations",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                certificate_sha256 = table.Column<string>(type: "character varying(64)",
                    maxLength: 64, nullable: false),
                actor_subject_id = table.Column<string>(type: "character varying(128)",
                    maxLength: 128, nullable: false),
                registered_at = table.Column<DateTimeOffset>(type: "timestamp with time zone",
                    nullable: false),
                overlap_ends_at = table.Column<DateTimeOffset>(type: "timestamp with time zone",
                    nullable: true),
                previous_certificate_sha256 = table.Column<string>(type: "character varying(64)",
                    maxLength: 64, nullable: true),
                incident_reference = table.Column<string>(type: "character varying(128)",
                    maxLength: 128, nullable: false),
                operator_reference = table.Column<string>(type: "character varying(128)",
                    maxLength: 128, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_admin_certificate_registrations",
                    row => row.certificate_sha256);
                table.CheckConstraint("CK_admin_certificate_registrations_sha256",
                    "certificate_sha256 ~ '^[0-9A-F]{64}$'");
                table.CheckConstraint("CK_admin_certificate_registrations_actor",
                    "actor_subject_id ~ '^person:[0-9a-f]{32}$'");
                table.CheckConstraint("CK_admin_certificate_registrations_previous",
                    "previous_certificate_sha256 IS NULL OR " +
                    "previous_certificate_sha256 ~ '^[0-9A-F]{64}$'");
            });

        migrationBuilder.CreateIndex(
            name: "IX_admin_certificate_registrations_actor_subject_id",
            schema: PlatformDbContext.SchemaName,
            table: "admin_certificate_registrations",
            column: "actor_subject_id");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable("admin_certificate_registrations",
            PlatformDbContext.SchemaName);
    }
}
