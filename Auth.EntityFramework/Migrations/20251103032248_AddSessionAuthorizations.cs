using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.EntityFramework.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionAuthorizations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "UserSessionAuthorizations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SessionId = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthorizationId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserSessionAuthorizations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserSessionAuthorizations_user_sessions_SessionId",
                        column: x => x.SessionId,
                        principalTable: "user_sessions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_UserSessionAuthorizations_AuthorizationId",
                table: "UserSessionAuthorizations",
                column: "AuthorizationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserSessionAuthorizations_SessionId_AuthorizationId",
                table: "UserSessionAuthorizations",
                columns: new[] { "SessionId", "AuthorizationId" },
                unique: true);

            migrationBuilder.Sql(@"
                INSERT INTO ""UserSessionAuthorizations"" (""Id"", ""SessionId"", ""AuthorizationId"", ""ClientId"", ""CreatedAt"")
                SELECT ""Id"", ""Id"", ""AuthorizationId"", ""ClientId"", NOW()
                FROM ""user_sessions""
                WHERE ""AuthorizationId"" IS NOT NULL;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserSessionAuthorizations");
        }
    }
}
