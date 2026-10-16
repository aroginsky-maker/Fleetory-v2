using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Core.Persistence.Migrations;

[DbContext(typeof(CoreDbContext))]
[Migration("202609280002_InitialCorePersistence")]
public sealed class InitialCorePersistence : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.EnsureSchema(name: CoreDbContext.SchemaName);

        migrationBuilder.CreateTable(
            name: "devices",
            schema: CoreDbContext.SchemaName,
            columns: table => new
            {
                device_id = table.Column<Guid>(type: "uuid", nullable: false),
                display_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                revision = table.Column<long>(type: "bigint", nullable: false, defaultValue: 1L)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_devices", record => record.device_id);
            });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "devices",
            schema: CoreDbContext.SchemaName);
    }
}
