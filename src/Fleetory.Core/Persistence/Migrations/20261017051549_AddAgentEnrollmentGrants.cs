using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Fleetory.Core.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAgentEnrollmentGrants : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "agent_enrollment_grants",
                schema: "core",
                columns: table => new
                {
                    token_sha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    device_id = table.Column<Guid>(type: "uuid", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    consumed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_agent_enrollment_grants", x => x.token_sha256);
                    table.ForeignKey(
                        name: "FK_agent_enrollment_grants_devices_device_id",
                        column: x => x.device_id,
                        principalSchema: "core",
                        principalTable: "devices",
                        principalColumn: "device_id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_agent_enrollment_grants_device_id",
                schema: "core",
                table: "agent_enrollment_grants",
                column: "device_id");

            migrationBuilder.CreateIndex(
                name: "IX_agent_enrollment_grants_expires_at",
                schema: "core",
                table: "agent_enrollment_grants",
                column: "expires_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "agent_enrollment_grants",
                schema: "core");
        }
    }
}
