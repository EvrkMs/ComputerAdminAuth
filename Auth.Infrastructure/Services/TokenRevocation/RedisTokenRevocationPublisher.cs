using Auth.Application.Interfaces;
using Auth.Infrastructure.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using System.Text.Json;

namespace Auth.Infrastructure.Services.TokenRevocation;

public sealed class RedisTokenRevocationPublisher : ITokenRevocationPublisher, IDisposable
{
    private readonly ILogger<RedisTokenRevocationPublisher> _logger;
    private readonly RedisRevocationOptions _options;
    private readonly ConnectionMultiplexer _connection;
    private readonly JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.Web);
    private bool _disposed;

    public RedisTokenRevocationPublisher(
        IOptions<RedisRevocationOptions> options,
        ILogger<RedisTokenRevocationPublisher> logger)
    {
        _logger = logger;
        _options = options.Value ?? new RedisRevocationOptions();

        if (string.IsNullOrWhiteSpace(_options.ConnectionString))
            throw new InvalidOperationException("Redis connection string is required.");

        try
        {
            _logger.LogInformation("Connecting to Redis at {ConnectionString} for token revocation notifications...", _options.ConnectionString);
            _connection = ConnectionMultiplexer.Connect(_options.ConnectionString);
            if (!_connection.IsConnected)
                throw new InvalidOperationException("Redis connection established but not connected.");
            _logger.LogInformation("Connected to Redis. Publishing revocation messages to channel {Channel}.", _options.ChannelName);
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Failed to connect to Redis at startup using connection string {ConnectionString}.", _options.ConnectionString);
            throw;
        }
    }

    public async Task PublishAsync(IEnumerable<RevokedTokenNotification> notifications, CancellationToken ct = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(RedisTokenRevocationPublisher));

        var payload = JsonSerializer.Serialize(notifications, _serializerOptions);
        try
        {
            var db = _connection.GetSubscriber();
            await db.PublishAsync(_options.ChannelName, payload);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to publish revoked token payload to Redis channel {Channel}.", _options.ChannelName);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _connection.Dispose();
        _disposed = true;
    }
}
