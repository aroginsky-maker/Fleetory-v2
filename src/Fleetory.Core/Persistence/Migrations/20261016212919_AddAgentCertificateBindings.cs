using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Fleetory.Core.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAgentCertificateBindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "agent_certificates",
                schema: "core",
                columns: table => new
                {
                    certificate_sha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    device_id = table.Column<Guid>(type: "uuid", nullable: false),
                    not_before = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    not_after = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_agent_certificates", x => x.certificate_sha256);
                    table.ForeignKey(
                        name: "FK_agent_certificates_devices_device_id",
                        column: x => x.device_id,
                        principalSchema: "core",
                        principalTable: "devices",
                        principalColumn: "device_id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_agent_certificates_device_id",
                schema: "core",
                table: "agent_certificates",
                column: "device_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "agent_certificates",
                schema: "core");
        }
    }
}
