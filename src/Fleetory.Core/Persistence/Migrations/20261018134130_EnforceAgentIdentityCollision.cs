using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Fleetory.Core.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EnforceAgentIdentityCollision : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "expected_certificate_sha256",
                schema: "core",
                table: "agent_enrollment_grants",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "expected_certificate_sha256",
                schema: "core",
                table: "agent_enrollment_grants");
        }
    }
}
