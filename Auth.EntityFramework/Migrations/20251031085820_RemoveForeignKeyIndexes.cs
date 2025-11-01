using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.EntityFramework.Migrations
{
    /// <inheritdoc />
    public partial class RemoveForeignKeyIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_OpenIddictTokens_ApplicationId",
                table: "OpenIddictTokens");

            migrationBuilder.DropIndex(
                name: "IX_OpenIddictAuthorizations_ApplicationId",
                table: "OpenIddictAuthorizations");

            migrationBuilder.DropIndex(
                name: "IX_AspNetUserTokens_UserId",
                table: "AspNetUserTokens");

            migrationBuilder.DropIndex(
                name: "IX_AspNetUserRoles_UserId",
                table: "AspNetUserRoles");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictTokens_ApplicationId",
                table: "OpenIddictTokens",
                column: "ApplicationId");

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictAuthorizations_ApplicationId",
                table: "OpenIddictAuthorizations",
                column: "ApplicationId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserTokens_UserId",
                table: "AspNetUserTokens",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserRoles_UserId",
                table: "AspNetUserRoles",
                column: "UserId");
        }
    }
}
