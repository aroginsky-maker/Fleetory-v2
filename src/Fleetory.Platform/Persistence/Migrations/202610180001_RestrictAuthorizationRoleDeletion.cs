using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
[Migration("202610180001_RestrictAuthorizationRoleDeletion")]
public sealed class RestrictAuthorizationRoleDeletion : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropForeignKey(
            name: "FK_authorization_assignments_role",
            schema: PlatformDbContext.SchemaName,
            table: "authorization_assignments");
        migrationBuilder.AddForeignKey(
            name: "FK_authorization_assignments_role",
            schema: PlatformDbContext.SchemaName,
            table: "authorization_assignments",
            column: "role_id",
            principalSchema: PlatformDbContext.SchemaName,
            principalTable: "authorization_roles",
            principalColumn: "role_id",
            onDelete: ReferentialAction.Restrict);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropForeignKey(
            name: "FK_authorization_assignments_role",
            schema: PlatformDbContext.SchemaName,
            table: "authorization_assignments");
        migrationBuilder.AddForeignKey(
            name: "FK_authorization_assignments_role",
            schema: PlatformDbContext.SchemaName,
            table: "authorization_assignments",
            column: "role_id",
            principalSchema: PlatformDbContext.SchemaName,
            principalTable: "authorization_roles",
            principalColumn: "role_id",
            onDelete: ReferentialAction.Cascade);
    }
}
