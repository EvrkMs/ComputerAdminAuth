using System;
using System.Threading;
using System.Threading.Tasks;
using Auth.Application.Interfaces;
using Auth.EntityFramework.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Periodically removes revoked sessions from the persistence store to avoid unbounded growth.
/// Runs best-effort cleanup every hour and logs failures without interrupting the host.
/// </summary>
public sealed class RevokedSessionCleanupService : BackgroundService
{
    private static readonly TimeSpan SweepInterval = TimeSpan.FromHours(1);
    private static readonly TimeSpan RevokedOpenIddictRetention = TimeSpan.FromDays(1);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<RevokedSessionCleanupService> _logger;

    public RevokedSessionCleanupService(IServiceScopeFactory scopeFactory, ILogger<RevokedSessionCleanupService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Run an initial cleanup shortly after startup, then continue on a fixed cadence.
        await CleanupAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(SweepInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            await CleanupAsync(stoppingToken);
        }
    }

    private async Task CleanupAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<ISessionRepository>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        try
        {
            var removed = await repo.DeleteRevokedAsync(ct);
            if (removed > 0)
            {
                _logger.LogInformation("Purged {Count} revoked user sessions.", removed);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to purge revoked user sessions.");
        }

        try
        {
            var revokedStatus = OpenIddictConstants.Statuses.Revoked;
            FormattableString tokenSql;
            FormattableString authorizationSql;

            if (RevokedOpenIddictRetention > TimeSpan.Zero)
            {
                var cutoff = DateTime.UtcNow.Subtract(RevokedOpenIddictRetention);
                tokenSql = $@"
                    DELETE FROM ""OpenIddictTokens""
                    WHERE ""Status"" = {revokedStatus}
                      AND (""CreationDate"" IS NULL OR ""CreationDate"" <= {cutoff});";
                authorizationSql = $@"
                    DELETE FROM ""OpenIddictAuthorizations""
                    WHERE ""Status"" = {revokedStatus}
                      AND (""CreationDate"" IS NULL OR ""CreationDate"" <= {cutoff});";
            }
            else
            {
                tokenSql = $@"
                    DELETE FROM ""OpenIddictTokens""
                    WHERE ""Status"" = {revokedStatus};";
                authorizationSql = $@"
                    DELETE FROM ""OpenIddictAuthorizations""
                    WHERE ""Status"" = {revokedStatus};";
            }

            var tokensRemoved = await dbContext.Database.ExecuteSqlInterpolatedAsync(tokenSql, ct);
            var authorizationsRemoved = await dbContext.Database.ExecuteSqlInterpolatedAsync(authorizationSql, ct);

            if (tokensRemoved > 0)
            {
                _logger.LogInformation("Purged {Count} revoked OpenIddict tokens.", tokensRemoved);
            }

            if (authorizationsRemoved > 0)
            {
                _logger.LogInformation("Purged {Count} revoked OpenIddict authorizations.", authorizationsRemoved);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to purge revoked OpenIddict tokens.");
        }
    }
}
