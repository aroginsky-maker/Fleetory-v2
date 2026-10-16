using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
[Migration("202609280001_InitialPlatformPersistence")]
public sealed class InitialPlatformPersistence : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.EnsureSchema(name: PlatformDbContext.SchemaName);

        migrationBuilder.CreateTable(
            name: "person_projections",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                person_id = table.Column<Guid>(type: "uuid", nullable: false),
                display_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                revision = table.Column<long>(type: "bigint", nullable: false, defaultValue: 1L)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_person_projections", record => record.person_id);
            });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "person_projections",
            schema: PlatformDbContext.SchemaName);
    }
}
