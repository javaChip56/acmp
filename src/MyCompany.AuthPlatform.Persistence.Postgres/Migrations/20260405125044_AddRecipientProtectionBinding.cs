using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MyCompany.AuthPlatform.Persistence.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddRecipientProtectionBinding : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RecipientProtectionBinding",
                columns: table => new
                {
                    BindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<Guid>(type: "uuid", nullable: false),
                    BindingName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    BindingType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Algorithm = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    PublicKeyPem = table.Column<string>(type: "text", nullable: true),
                    PublicKeyFingerprint = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    CertificateThumbprint = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    StoreLocation = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    StoreName = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    CertificatePath = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    PrivateKeyPathHint = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    KeyId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    KeyVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    ActivatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RetiredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    Notes = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedBy = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ConcurrencyToken = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RecipientProtectionBinding", x => x.BindingId);
                    table.ForeignKey(
                        name: "FK_RecipientProtectionBinding_ServiceClient_ClientId",
                        column: x => x.ClientId,
                        principalTable: "ServiceClient",
                        principalColumn: "ClientId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RecipientProtectionBinding_BindingType_Status",
                table: "RecipientProtectionBinding",
                columns: new[] { "BindingType", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_RecipientProtectionBinding_ClientId_BindingName",
                table: "RecipientProtectionBinding",
                columns: new[] { "ClientId", "BindingName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RecipientProtectionBinding_ClientId_Status",
                table: "RecipientProtectionBinding",
                columns: new[] { "ClientId", "Status" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RecipientProtectionBinding");
        }
    }
}
