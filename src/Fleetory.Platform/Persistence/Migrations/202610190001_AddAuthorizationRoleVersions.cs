using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
[Migration("202610190001_AddAuthorizationRoleVersions")]
public sealed class AddAuthorizationRoleVersions : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "authorization_role_versions",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                role_id = table.Column<Guid>(type: "uuid", nullable: false),
                predecessor_role_id = table.Column<Guid>(type: "uuid", nullable: true),
                name = table.Column<string>(type: "character varying(128)", maxLength: 128,
                    nullable: false),
                permissions = table.Column<string[]>(type: "text[]", nullable: false),
                recorded_at = table.Column<DateTimeOffset>(type: "timestamp with time zone",
                    nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_authorization_role_versions", row => row.role_id);
                table.CheckConstraint("CK_authorization_role_versions_not_self",
                    "predecessor_role_id IS NULL OR predecessor_role_id <> role_id");
            });

        migrationBuilder.CreateIndex(
            name: "IX_authorization_role_versions_predecessor_role_id",
            schema: PlatformDbContext.SchemaName,
            table: "authorization_role_versions",
            column: "predecessor_role_id");

        migrationBuilder.Sql("""
            INSERT INTO platform.authorization_role_versions
                (role_id, predecessor_role_id, name, permissions, recorded_at)
            SELECT role.role_id, NULL, role.name,
                   ARRAY(SELECT permission.permission
                         FROM platform.authorization_role_permissions AS permission
                         WHERE permission.role_id = role.role_id
                         ORDER BY permission.permission),
                   clock_timestamp()
            FROM platform.authorization_roles AS role
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable("authorization_role_versions", PlatformDbContext.SchemaName);
    }
}
