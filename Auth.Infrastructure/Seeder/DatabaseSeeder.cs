using System;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Auth.Domain.Entities;
using Auth.EntityFramework.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Auth.Infrastructure.Seeder;

public static class DatabaseSeeder
{
    private static readonly TimeSpan[] RetrySchedule =
    {
        TimeSpan.Zero,
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(10),
        TimeSpan.FromSeconds(20),
        TimeSpan.FromSeconds(30)
    };

    public static async Task ApplyMigrationsAndSeedAsync(this IServiceProvider sp, CancellationToken cancellationToken = default)
    {
        var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("DatabaseSeeder");

        await EnsureDatabaseReadyAsync(sp, logger, cancellationToken);

        await SeedWithRetryAsync("roles seeding", sp, logger, SeedRolesAsync, cancellationToken);
        await SeedWithRetryAsync("default user seeding", sp, logger, SeedDefaultUserAsync, cancellationToken);
        await SeedWithRetryAsync("OpenIddict seeding", sp, logger, OpenIddictSeeder.SeedAsync, cancellationToken);
    }

    private static async Task EnsureDatabaseReadyAsync(IServiceProvider sp, ILogger logger, CancellationToken cancellationToken)
    {
        foreach (var delay in RetrySchedule)
        {
            if (delay > TimeSpan.Zero)
            {
                logger.LogInformation("Waiting {Delay} before next database readiness check.", delay);
                await Task.Delay(delay, cancellationToken);
            }

            try
            {
                using var scope = sp.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                logger.LogInformation("Checking database connectivity...");
                if (!await db.Database.CanConnectAsync(cancellationToken))
                {
                    logger.LogWarning("Database connectivity test returned false. Retrying.");
                    continue;
                }

                logger.LogInformation("Applying pending migrations...");
                await db.Database.MigrateAsync(cancellationToken);
                logger.LogInformation("Database migrations applied successfully.");
                return;
            }
            catch (Exception ex) when (IsTransient(ex))
            {
                logger.LogWarning(ex, "Transient database error encountered while applying migrations. Retrying.");
            }
        }

        using var finalScope = sp.CreateScope();
        var finalDb = finalScope.ServiceProvider.GetRequiredService<AppDbContext>();
        await finalDb.Database.MigrateAsync(cancellationToken);
    }

    private static async Task SeedWithRetryAsync(
        string operationName,
        IServiceProvider sp,
        ILogger logger,
        Func<IServiceProvider, Task> operation,
        CancellationToken cancellationToken)
    {
        foreach (var delay in RetrySchedule)
        {
            if (delay > TimeSpan.Zero)
            {
                logger.LogInformation("Waiting {Delay} before retrying {Operation}.", delay, operationName);
                await Task.Delay(delay, cancellationToken);
            }

            try
            {
                using var scope = sp.CreateScope();
                await operation(scope.ServiceProvider);
                logger.LogInformation("Completed {Operation}.", operationName);
                return;
            }
            catch (Exception ex) when (IsTransient(ex))
            {
                logger.LogWarning(ex, "Transient failure encountered during {Operation}. Retrying.", operationName);
            }
        }

        using var finalScope = sp.CreateScope();
        await operation(finalScope.ServiceProvider);
    }

    private static async Task SeedRolesAsync(IServiceProvider sp)
    {
        var roleMgr = sp.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        string[] roles = { "Admin", "Operator", "Root" };

        foreach (var r in roles)
            if (!await roleMgr.RoleExistsAsync(r))
                await roleMgr.CreateAsync(new IdentityRole<Guid>(r));
    }

    private static async Task SeedDefaultUserAsync(IServiceProvider sp)
    {
        var userMgr = sp.GetRequiredService<UserManager<UserEntity>>();
        var existing = await userMgr.FindByNameAsync("root");
        if (existing != null) return;
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("AUTH_ROOT_PASSWORD")))
            return;

        var user = new UserEntity
        {
            UserName = "root",
            FullName = "Полный доступ"
        };

        var password = Environment.GetEnvironmentVariable("AUTH_ROOT_PASSWORD")!;
        var result = await userMgr.CreateAsync(user, password);
        if (result.Succeeded)
        {
            await userMgr.AddToRoleAsync(user, "Root");
        }
        else
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new Exception("Не удалось создать пользователя root: " + errors);
        }
    }

    private static bool IsTransient(Exception exception)
    {
        return exception switch
        {
            AggregateException aggregate => aggregate.InnerExceptions.Any(IsTransient),
            DbUpdateException dbUpdate when dbUpdate.InnerException is not null => IsTransient(dbUpdate.InnerException),
            InvalidOperationException invalidOp when invalidOp.InnerException is not null => IsTransient(invalidOp.InnerException),
            NpgsqlException => true,
            SocketException socket when socket.SocketErrorCode is
                SocketError.TryAgain or
                SocketError.TimedOut or
                SocketError.NetworkDown or
                SocketError.NetworkUnreachable or
                SocketError.ConnectionRefused or
                SocketError.HostDown or
                SocketError.HostUnreachable =>
                true,
            TimeoutException => true,
            _ => false
        };
    }
}
