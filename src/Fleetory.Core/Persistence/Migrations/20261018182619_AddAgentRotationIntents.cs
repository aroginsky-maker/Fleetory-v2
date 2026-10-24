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

            migrationBuilder.Sql("""
                CREATE TABLE core.agent_rotation_intents (
                    intent_id uuid NOT NULL,
                    device_id uuid NOT NULL,
                    current_certificate_sha256 varchar(64) NOT NULL,
                    replacement_certificate_sha256 varchar(64) NOT NULL,
                    expires_at timestamptz NOT NULL,
                    claimed_at timestamptz NULL,
                    CONSTRAINT "PK_agent_rotation_intents" PRIMARY KEY (intent_id),
                    CONSTRAINT "FK_agent_rotation_intents_devices_device_id"
                        FOREIGN KEY (device_id) REFERENCES core.devices (device_id)
                        ON DELETE RESTRICT
                );
                CREATE INDEX "IX_agent_rotation_intents_device_id"
                    ON core.agent_rotation_intents (device_id);
                CREATE INDEX "IX_agent_rotation_intents_expires_at"
                    ON core.agent_rotation_intents (expires_at);
                """);
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
