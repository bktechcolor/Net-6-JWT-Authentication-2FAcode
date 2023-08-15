using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace UserManagement.API.Migrations
{
    /// <inheritdoc />
    public partial class updateNewUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "1899c052-18bc-4c4c-9d9b-5e71f8b3445b", "2", "HR", "HR" },
                    { "baac91b6-a144-4110-9eab-4eba9116bcaa", "2", "User", "User" },
                    { "d51e074a-801e-4175-8779-27fb25b8b210", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "1899c052-18bc-4c4c-9d9b-5e71f8b3445b");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "baac91b6-a144-4110-9eab-4eba9116bcaa");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "d51e074a-801e-4175-8779-27fb25b8b210");
        }
    }
}
