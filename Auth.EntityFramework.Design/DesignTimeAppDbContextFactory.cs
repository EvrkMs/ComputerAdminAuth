using Auth.EntityFramework.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Auth.EntityFramework.Design;

public sealed class DesignTimeAppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("CONNECTIONSTRINGS__DEFAULTCONNECTION")
            ?? throw new InvalidOperationException("Database connection string not found in configuration or environment.");

        var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();
        optionsBuilder.UseNpgsql(connection);

        return new AppDbContext(optionsBuilder.Options);
    }
}
