using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
[Migration("202610210001_AddAdminCertificateRevocations")]
public sealed class AddAdminCertificateRevocations : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "admin_certificate_revocations",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                certificate_sha256 = table.Column<string>(type: "character varying(64)",
                    maxLength: 64, nullable: false),
                revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone",
                    nullable: false),
                incident_reference = table.Column<string>(type: "character varying(128)",
                    maxLength: 128, nullable: false),
                operator_reference = table.Column<string>(type: "character varying(128)",
                    maxLength: 128, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_admin_certificate_revocations",
                    row => row.certificate_sha256);
                table.CheckConstraint("CK_admin_certificate_revocations_sha256",
                    "certificate_sha256 ~ '^[0-9A-F]{64}$'");
            });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable("admin_certificate_revocations", PlatformDbContext.SchemaName);
    }
}
