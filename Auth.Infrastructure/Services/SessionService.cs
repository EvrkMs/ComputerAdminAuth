using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.EntityFramework.Data;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Server-side session registry shared by cookie + token flows.
/// Issues opaque identifiers, stores hashed browser secrets, and cascades revocations to OpenIddict artifacts.
/// </summary>
public class SessionService : ISessionService
{
    private readonly ISessionRepository _repo;
    private readonly AppDbContext _db;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly ILogger<SessionService> _logger;
    private const int ReferenceSizeBytes = 16;
    private const int SecretSizeBytes = 32;
    private const int SaltSizeBytes = 16;

    public SessionService(
        ISessionRepository repo,
        AppDbContext db,
        IUnitOfWork unitOfWork,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictTokenManager tokenManager,
        ILogger<SessionService> logger)
    {
        _repo = repo;
        _db = db;
        _unitOfWork = unitOfWork;
        _authorizationManager = authorizationManager;
        _tokenManager = tokenManager;
        _logger = logger;
    }

    public async Task<SessionIssueResult> EnsureInteractiveSessionAsync(Guid userId, string? clientId, string? ip, string? userAgent, string? device, TimeSpan? absoluteLifetime, CancellationToken ct = default)
    {
        var referenceId = GenerateReferenceId();
        var browserSecret = GenerateSecret();
        var salt = GenerateSalt();

        var session = new UserSession
        {
            UserId = userId,
            ClientId = clientId,
            Device = device,
            UserAgent = Trunc(userAgent, 500),
            IpAddress = Trunc(ip, 100),
            CreatedAt = DateTime.UtcNow,
            LastSeenAt = DateTime.UtcNow,
            ExpiresAt = absoluteLifetime.HasValue ? DateTime.UtcNow.Add(absoluteLifetime.Value) : null,
            Revoked = false,
            ReferenceId = referenceId,
            SecretSalt = salt,
            SecretHash = HashSecret(browserSecret, salt),
            SecretCreatedAt = DateTime.UtcNow
        };
        await _repo.AddAsync(session, ct);
        await _unitOfWork.SaveChangesAsync(ct);
        return new SessionIssueResult(session.ReferenceId, browserSecret, session.CreatedAt, session.ExpiresAt);
    }

    public async Task<SessionIssueResult?> RefreshBrowserSecretAsync(string referenceId, Guid expectedUserId, CancellationToken ct = default)
    {
        var session = await _repo.GetByReferenceAsync(referenceId, ct);
        if (session is null || session.UserId != expectedUserId)
            return null;

        if (!IsSessionCurrentlyActive(session))
            return null;

        var newSecret = GenerateSecret();
        var newSalt = GenerateSalt();
        session.SecretSalt = newSalt;
        session.SecretHash = HashSecret(newSecret, newSalt);
        session.SecretCreatedAt = DateTime.UtcNow;
        session.SecretExpiresAt = null;
        session.LastSeenAt = DateTime.UtcNow;
        await _repo.UpdateAsync(session, ct);
        await _unitOfWork.SaveChangesAsync(ct);
        return new SessionIssueResult(session.ReferenceId, newSecret, session.CreatedAt, session.ExpiresAt);
    }

    public async Task<bool> RevokeAsync(string referenceId, string? reason = null, string? by = null, CancellationToken ct = default)
    {
        var s = await _repo.GetByReferenceAsync(referenceId, ct);
        if (s is null || s.Revoked) return false;

        s.Revoked = true;
        s.RevokedAt = DateTime.UtcNow;
        s.RevokedBy = by;
        s.RevocationReason = reason;

        await ExecuteInTransactionAsync(async innerCt =>
        {
            await _repo.UpdateAsync(s, innerCt);
            await _unitOfWork.SaveChangesAsync(innerCt);
        }, ct);

        // Cascade revoke: if authorization id is known, use OpenIddict managers
        if (!string.IsNullOrWhiteSpace(s.AuthorizationId))
        {
            await RevokeByAuthorizationIdAsync(s.AuthorizationId!, ct);
        }
        else
        {
            // Fallback: match tokens by sid in payload (works for self-contained tokens)
            await RevokeOpenIddictTokensBySidAsync(referenceId, ct);
        }

        try
        {
            await ExecuteInTransactionAsync(async innerCt =>
            {
                await _repo.DeleteAsync(s, innerCt);
                await _unitOfWork.SaveChangesAsync(innerCt);
            }, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete revoked session {ReferenceId}", referenceId);
        }

        return true;
    }

    public async Task<bool> IsActiveAsync(string referenceId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(referenceId))
            return false;

        var session = await _repo.GetByReferenceAsync(referenceId, ct);
        return session is not null && IsSessionCurrentlyActive(session);
    }

    public async Task<SessionValidationResult?> ValidateBrowserSessionAsync(string referenceId, string secret, bool requireActive = true, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(referenceId) || string.IsNullOrWhiteSpace(secret))
            return null;

        var session = await _repo.GetByReferenceAsync(referenceId, ct);
        if (session is null)
            return null;

        if (!SlowEquals(session.SecretHash, HashSecret(secret, session.SecretSalt)))
            return null;

        if (requireActive && !IsSessionCurrentlyActive(session))
            return null;

        return new SessionValidationResult(session.Id, session.UserId, session.CreatedAt, session.ExpiresAt, session.Revoked);
    }

    private static bool IsSessionCurrentlyActive(UserSession session)
    {
        if (session.Revoked)
            return false;

        if (session.ExpiresAt is not null && session.ExpiresAt.Value <= DateTime.UtcNow)
            return false;

        return true;
    }

    private static string? Trunc(string? val, int max)
        => string.IsNullOrEmpty(val) ? val : (val!.Length <= max ? val : val.Substring(0, max));

    private async Task<int> RevokeOpenIddictTokensBySidAsync(string sid, CancellationToken ct)
    {
        // Use a parameterized raw SQL update to avoid coupling to OpenIddict EF models.
        // Note: access tokens are JWTs (not stored). They are enforced via middleware on each request.
        var revoked = OpenIddictConstants.Statuses.Revoked;
        var refreshType = "refresh_token";
        var accessType = "access_token";
        var like = $@"%""sid"":""{sid}""%";

        var refreshRevoked = await _db.Database.ExecuteSqlInterpolatedAsync($@"
            UPDATE ""OpenIddictTokens"" SET ""Status"" = {revoked}
            WHERE (""Status"" IS NULL OR ""Status"" <> {revoked})
              AND ""Type"" = {refreshType}
              AND ""Payload"" IS NOT NULL
              AND ""Payload"" LIKE {like};", ct);

        var accessRevoked = await _db.Database.ExecuteSqlInterpolatedAsync($@"
            UPDATE ""OpenIddictTokens"" SET ""Status"" = {revoked}
            WHERE (""Status"" IS NULL OR ""Status"" <> {revoked})
              AND ""Type"" = {accessType}
              AND ""Payload"" IS NOT NULL
              AND ""Payload"" LIKE {like};", ct);

        return refreshRevoked + accessRevoked;
    }

    private async Task RevokeByAuthorizationIdAsync(string authorizationId, CancellationToken ct)
    {
        var authorization = await _authorizationManager.FindByIdAsync(authorizationId, ct);
        if (authorization is not null)
        {
            try { await _authorizationManager.TryRevokeAsync(authorization!, ct); } catch { }
        }

        await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(authorizationId, ct))
        {
            try { await _tokenManager.TryRevokeAsync(token!, ct); } catch { }
        }
    }

    public async Task<bool> LinkAuthorizationAsync(string referenceId, string authorizationId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(referenceId)) return false;
        var s = await _repo.GetByReferenceAsync(referenceId, ct);
        if (s is null) return false;
        if (!string.IsNullOrEmpty(s.AuthorizationId)) return true; // already linked
        s.AuthorizationId = authorizationId;
        await _repo.UpdateAsync(s, ct);
        await _unitOfWork.SaveChangesAsync(ct);
        return true;
    }

    private static string GenerateReferenceId()
    {
        Span<byte> buffer = stackalloc byte[ReferenceSizeBytes];
        RandomNumberGenerator.Fill(buffer);
        return Convert.ToHexString(buffer).ToLowerInvariant();
    }

    private static string GenerateSecret()
    {
        Span<byte> buffer = stackalloc byte[SecretSizeBytes];
        RandomNumberGenerator.Fill(buffer);
        return Base64UrlEncode(buffer);
    }

    private static string GenerateSalt()
    {
        Span<byte> buffer = stackalloc byte[SaltSizeBytes];
        RandomNumberGenerator.Fill(buffer);
        return Base64UrlEncode(buffer);
    }

    private static string HashSecret(string secret, string salt)
    {
        using var sha = SHA256.Create();
        var payload = Encoding.UTF8.GetBytes($"{salt}:{secret}");
        return Convert.ToBase64String(sha.ComputeHash(payload));
    }

    private static bool SlowEquals(string storedHash, string computedHash)
        => CryptographicOperations.FixedTimeEquals(
            Convert.FromBase64String(storedHash),
            Convert.FromBase64String(computedHash));

    private static string Base64UrlEncode(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private async Task ExecuteInTransactionAsync(Func<CancellationToken, Task> work, CancellationToken ct)
    {
        var strategy = _db.Database.CreateExecutionStrategy();
        await strategy.ExecuteAsync(async () =>
        {
            ITransaction? tx = null;
            try
            {
                tx = await _unitOfWork.BeginTransactionAsync(ct);
                await work(ct);
                await tx.CommitAsync(ct);
            }
            catch
            {
                if (tx is not null)
                {
                    try { await tx.RollbackAsync(ct); } catch { }
                }
                throw;
            }
            finally
            {
                tx?.Dispose();
            }
        });
    }
}
