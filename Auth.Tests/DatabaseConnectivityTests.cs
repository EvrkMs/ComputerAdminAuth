using System;
using System.Threading.Tasks;
using Npgsql;
using Xunit;

namespace Auth.Tests;

public class DatabaseConnectivityTests
{
    private static readonly bool ShouldSkip = string.Equals(
        Environment.GetEnvironmentVariable("SKIP_DB_TESTS"),
        "true",
        StringComparison.OrdinalIgnoreCase);

    [Fact(DisplayName = "ConnectionStrings__DefaultConnection allows opening a PostgreSQL connection"), Trait("Category", "DatabaseConnectivity")]
    public async Task ConnectionString_AllowsOpeningConnection()
    {
        if (ShouldSkip)
        {
            Console.WriteLine("DatabaseConnectivityTests skipped because SKIP_DB_TESTS=true.");
            return;
        }

        var connectionString =
            Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection") ??
            Environment.GetEnvironmentVariable("CONNECTIONSTRINGS__DEFAULTCONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Environment variable 'ConnectionStrings__DefaultConnection' must be provided. " +
                "Set SKIP_DB_TESTS=true locally if you need to bypass DB smoke tests.");
        }

        await using var connection = new NpgsqlConnection(connectionString);
        try
        {
            await connection.OpenAsync();
            await using var cmd = new NpgsqlCommand("SELECT 1", connection);
            var result = await cmd.ExecuteScalarAsync();
            Assert.Equal(1, Convert.ToInt32(result));
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to connect to PostgreSQL using ConnectionStrings__DefaultConnection.", ex);
        }
    }
}
