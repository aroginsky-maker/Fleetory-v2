using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
[Migration("202610190002_AddAuthorizationScopeVersions")]
public sealed class AddAuthorizationScopeVersions : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "authorization_scope_versions",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                scope_id = table.Column<Guid>(type: "uuid", nullable: false),
                revision = table.Column<int>(type: "integer", nullable: false),
                parent_scope_id = table.Column<Guid>(type: "uuid", nullable: true),
                name = table.Column<string>(type: "character varying(128)", maxLength: 128,
                    nullable: false),
                recorded_at = table.Column<DateTimeOffset>(type: "timestamp with time zone",
                    nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_authorization_scope_versions",
                    row => new { row.scope_id, row.revision });
                table.CheckConstraint("CK_authorization_scope_versions_revision",
                    "revision > 0");
            });

        migrationBuilder.Sql("""
            INSERT INTO platform.authorization_scope_versions
                (scope_id, revision, parent_scope_id, name, recorded_at)
            SELECT scope_id, 1, parent_scope_id, name, clock_timestamp()
            FROM platform.authorization_scopes
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable("authorization_scope_versions", PlatformDbContext.SchemaName);
    }
}
