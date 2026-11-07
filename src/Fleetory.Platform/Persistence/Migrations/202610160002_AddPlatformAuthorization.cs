using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Fleetory.Platform.Persistence.Migrations;

[DbContext(typeof(PlatformDbContext))]
[Migration("202610160002_AddPlatformAuthorization")]
public sealed class AddPlatformAuthorization : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "authorization_scopes",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                scope_id = table.Column<Guid>(type: "uuid", nullable: false),
                parent_scope_id = table.Column<Guid>(type: "uuid", nullable: true),
                name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_authorization_scopes", row => row.scope_id);
                table.ForeignKey(
                    name: "FK_authorization_scopes_parent",
                    column: row => row.parent_scope_id,
                    principalSchema: PlatformDbContext.SchemaName,
                    principalTable: "authorization_scopes",
                    principalColumn: "scope_id",
                    onDelete: ReferentialAction.Restrict);
                table.CheckConstraint("CK_authorization_scopes_not_self_parent",
                    "parent_scope_id IS NULL OR parent_scope_id <> scope_id");
            });

        migrationBuilder.CreateIndex(
            name: "IX_authorization_scopes_parent_scope_id",
            schema: PlatformDbContext.SchemaName,
            table: "authorization_scopes",
            column: "parent_scope_id");

        migrationBuilder.CreateTable(
            name: "authorization_roles",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                role_id = table.Column<Guid>(type: "uuid", nullable: false),
                name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_authorization_roles", row => row.role_id));

        migrationBuilder.CreateTable(
            name: "authorization_role_permissions",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                role_id = table.Column<Guid>(type: "uuid", nullable: false),
                permission = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_authorization_role_permissions", row => new { row.role_id, row.permission });
                table.ForeignKey(
                    name: "FK_authorization_role_permissions_role",
                    column: row => row.role_id,
                    principalSchema: PlatformDbContext.SchemaName,
                    principalTable: "authorization_roles",
                    principalColumn: "role_id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "authorization_assignments",
            schema: PlatformDbContext.SchemaName,
            columns: table => new
            {
                assignment_id = table.Column<Guid>(type: "uuid", nullable: false),
                actor_subject_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                actor_kind = table.Column<int>(type: "integer", nullable: false),
                role_id = table.Column<Guid>(type: "uuid", nullable: false),
                scope_id = table.Column<Guid>(type: "uuid", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_authorization_assignments", row => row.assignment_id);
                table.ForeignKey(
                    name: "FK_authorization_assignments_role",
                    column: row => row.role_id,
                    principalSchema: PlatformDbContext.SchemaName,
                    principalTable: "authorization_roles",
                    principalColumn: "role_id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_authorization_assignments_scope",
                    column: row => row.scope_id,
                    principalSchema: PlatformDbContext.SchemaName,
                    principalTable: "authorization_scopes",
                    principalColumn: "scope_id",
                    onDelete: ReferentialAction.Restrict);
            });

        migrationBuilder.CreateIndex(
            name: "IX_authorization_assignments_actor_role_scope",
            schema: PlatformDbContext.SchemaName,
            table: "authorization_assignments",
            columns: ["actor_subject_id", "actor_kind", "role_id", "scope_id"]);
        migrationBuilder.CreateIndex(
            name: "IX_authorization_assignments_role_id",
            schema: PlatformDbContext.SchemaName,
            table: "authorization_assignments",
            column: "role_id");
        migrationBuilder.CreateIndex(
            name: "IX_authorization_assignments_scope_id",
            schema: PlatformDbContext.SchemaName,
            table: "authorization_assignments",
            column: "scope_id");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable("authorization_assignments", PlatformDbContext.SchemaName);
        migrationBuilder.DropTable("authorization_role_permissions", PlatformDbContext.SchemaName);
        migrationBuilder.DropTable("authorization_roles", PlatformDbContext.SchemaName);
        migrationBuilder.DropTable("authorization_scopes", PlatformDbContext.SchemaName);
    }
}
