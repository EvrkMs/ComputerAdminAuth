using Auth.Application.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services.TokenRevocation;

internal sealed class RevocationPublisherWarmupService : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<RevocationPublisherWarmupService> _logger;

    public RevocationPublisherWarmupService(IServiceProvider serviceProvider, ILogger<RevocationPublisherWarmupService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();
        try
        {
            var publisher = scope.ServiceProvider.GetRequiredService<ITokenRevocationPublisher>();
            _logger.LogInformation("Token revocation publisher resolved: {Type}.", publisher.GetType().Name);
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Failed to initialize token revocation publisher.");
            throw;
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
