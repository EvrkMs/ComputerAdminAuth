using Auth.Application.Interfaces;

namespace Auth.Infrastructure.Services.TokenRevocation;

public sealed class NullTokenRevocationPublisher : ITokenRevocationPublisher
{
    public Task PublishAsync(IEnumerable<RevokedTokenNotification> notifications, CancellationToken ct = default)
        => Task.CompletedTask;
}
