using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Fleetory.Core.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAgentRotationIntents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "replacement_certificate_sha256",
                schema: "core",
                table: "agent_enrollment_grants",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            // Rotation grants issued by older code lack a replacement fingerprint and
            // must not remain redeemable after the new proof-of-possession rule starts.
            migrationBuilder.Sql("""
                DELETE FROM core.agent_enrollment_grants
                WHERE expected_certificate_sha256 IS NOT NULL AND consumed_at IS NULL
                """);

            migrationBuilder.CreateTable(
                name: "agent_rotation_intents",
                schema: "core",
                columns: table => new
                {
                    intent_id = table.Column<Guid>(type: "uuid", nullable: false),
                    device_id = table.Column<Guid>(type: "uuid", nullable: false),
                    current_certificate_sha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    replacement_certificate_sha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    claimed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_agent_rotation_intents", x => x.intent_id);
                    table.ForeignKey(
                        name: "FK_agent_rotation_intents_devices_device_id",
                        column: x => x.device_id,
                        principalSchema: "core",
                        principalTable: "devices",
                        principalColumn: "device_id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_agent_rotation_intents_device_id",
                schema: "core",
                table: "agent_rotation_intents",
                column: "device_id");

            migrationBuilder.CreateIndex(
                name: "IX_agent_rotation_intents_expires_at",
                schema: "core",
                table: "agent_rotation_intents",
                column: "expires_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "agent_rotation_intents",
                schema: "core");

            migrationBuilder.DropColumn(
                name: "replacement_certificate_sha256",
                schema: "core",
                table: "agent_enrollment_grants");
        }
    }
}
