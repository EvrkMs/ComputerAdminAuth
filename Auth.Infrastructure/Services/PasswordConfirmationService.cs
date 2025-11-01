using System.Security.Cryptography;
using Auth.Application.Interfaces;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

// Auth.Infrastructure/Services/PasswordConfirmationService.cs
public sealed class PasswordConfirmationService : IPasswordConfirmationService
{
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(5);
    private readonly IMemoryCache _cache;
    private readonly ILogger<PasswordConfirmationService> _logger;

    public PasswordConfirmationService(IMemoryCache cache, ILogger<PasswordConfirmationService> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public TimeSpan TokenLifetime => DefaultLifetime;

    public Task<string> CreateTokenAsync(Guid userId, string purpose, CancellationToken ct = default)
    {
        purpose = NormalizePurpose(purpose);

        var token = GenerateToken();
        var cacheKey = BuildCacheKey(userId, purpose, token);

        _cache.Set(cacheKey, true, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = DefaultLifetime,
            Priority = CacheItemPriority.High
        });

        _logger.LogDebug("Issued password confirmation token for user {UserId} purpose {Purpose}", userId, purpose);

        return Task.FromResult(token);
    }

    public Task<bool> ValidateTokenAsync(Guid userId, string purpose, string token, CancellationToken ct = default)
    {
        purpose = NormalizePurpose(purpose);

        if (string.IsNullOrWhiteSpace(token))
            return Task.FromResult(false);

        var cacheKey = BuildCacheKey(userId, purpose, token);

        if (_cache.TryGetValue(cacheKey, out _))
        {
            _cache.Remove(cacheKey);
            _logger.LogDebug("Consumed password confirmation token for user {UserId} purpose {Purpose}", userId, purpose);
            return Task.FromResult(true);
        }

        _logger.LogWarning("Invalid password confirmation token for user {UserId} purpose {Purpose}", userId, purpose);
        return Task.FromResult(false);
    }

    private static string NormalizePurpose(string purpose)
        => purpose?.Trim().ToLowerInvariant() ?? string.Empty;

    private static string BuildCacheKey(Guid userId, string purpose, string token)
        => $"pc:{userId:D}:{purpose}:{token}";

    private static string GenerateToken()
    {
        Span<byte> buffer = stackalloc byte[32];
        RandomNumberGenerator.Fill(buffer);
        return Convert.ToBase64String(buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
