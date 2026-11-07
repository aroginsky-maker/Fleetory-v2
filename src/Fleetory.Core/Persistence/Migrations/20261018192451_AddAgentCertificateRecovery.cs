using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Fleetory.Core.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAgentCertificateRecovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "recovery_request_id",
                schema: "core",
                table: "agent_enrollment_grants",
                type: "uuid",
                nullable: true);

            migrationBuilder.Sql("""
                CREATE TABLE core.agent_certificate_recoveries (
                    recovery_id uuid NOT NULL,
                    device_id uuid NOT NULL,
                    requester_subject_id varchar(128) NOT NULL,
                    expected_certificate_sha256 varchar(64) NOT NULL,
                    replacement_certificate_sha256 varchar(64) NOT NULL,
                    evidence_sha256 varchar(64) NOT NULL,
                    incident_reference varchar(128) NOT NULL,
                    expires_at timestamptz NOT NULL,
                    approved_at timestamptz NULL,
                    approver_subject_id varchar(128) NULL,
                    CONSTRAINT "PK_agent_certificate_recoveries" PRIMARY KEY (recovery_id),
                    CONSTRAINT "FK_agent_certificate_recoveries_devices_device_id"
                        FOREIGN KEY (device_id) REFERENCES core.devices (device_id)
                        ON DELETE RESTRICT
                );
                """);

            migrationBuilder.CreateIndex(
                name: "IX_agent_enrollment_grants_recovery_request_id",
                schema: "core",
                table: "agent_enrollment_grants",
                column: "recovery_request_id");

            migrationBuilder.CreateIndex(
                name: "IX_agent_certificate_recoveries_device_id",
                schema: "core",
                table: "agent_certificate_recoveries",
                column: "device_id");

            migrationBuilder.CreateIndex(
                name: "IX_agent_certificate_recoveries_expires_at",
                schema: "core",
                table: "agent_certificate_recoveries",
                column: "expires_at");

            migrationBuilder.AddForeignKey(
                name: "FK_agent_enrollment_grants_agent_certificate_recoveries_recove~",
                schema: "core",
                table: "agent_enrollment_grants",
                column: "recovery_request_id",
                principalSchema: "core",
                principalTable: "agent_certificate_recoveries",
                principalColumn: "recovery_id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_agent_enrollment_grants_agent_certificate_recoveries_recove~",
                schema: "core",
                table: "agent_enrollment_grants");

            migrationBuilder.DropTable(
                name: "agent_certificate_recoveries",
                schema: "core");

            migrationBuilder.DropIndex(
                name: "IX_agent_enrollment_grants_recovery_request_id",
                schema: "core",
                table: "agent_enrollment_grants");

            migrationBuilder.DropColumn(
                name: "recovery_request_id",
                schema: "core",
                table: "agent_enrollment_grants");
        }
    }
}
