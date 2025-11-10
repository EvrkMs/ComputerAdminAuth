using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.EntityFramework.Data;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using System.Diagnostics.Metrics;

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
    private readonly ITokenRevocationPublisher _revocationPublisher;
    private const int ReferenceSizeBytes = 16;
    private const int SecretSizeBytes = 32;
    private const int SaltSizeBytes = 16;
    private static readonly TimeSpan BrowserSecretLifetime = TimeSpan.FromHours(12);
    private static readonly Meter Meter = new("Auth.Infrastructure.SessionService", "1.0.0");
    private static readonly Counter<long> SessionsIssued = Meter.CreateCounter<long>("sessions.issued");
    private static readonly Counter<long> SessionsRevoked = Meter.CreateCounter<long>("sessions.revoked");
    private static readonly Counter<long> SecretRotations = Meter.CreateCounter<long>("sessions.secret_rotations");

    public SessionService(
        ISessionRepository repo,
        AppDbContext db,
        IUnitOfWork unitOfWork,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictTokenManager tokenManager,
        ITokenRevocationPublisher revocationPublisher,
        ILogger<SessionService> logger)
    {
        _repo = repo;
        _db = db;
        _unitOfWork = unitOfWork;
        _authorizationManager = authorizationManager;
        _tokenManager = tokenManager;
        _revocationPublisher = revocationPublisher;
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
            SecretCreatedAt = DateTime.UtcNow,
            SecretExpiresAt = DateTime.UtcNow.Add(BrowserSecretLifetime)
        };
        await _repo.AddAsync(session, ct);
        await _unitOfWork.SaveChangesAsync(ct);
        SessionsIssued.Add(1);
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
        session.SecretExpiresAt = DateTime.UtcNow.Add(BrowserSecretLifetime);
        session.LastSeenAt = DateTime.UtcNow;
        await _repo.UpdateAsync(session, ct);
        await _unitOfWork.SaveChangesAsync(ct);
        SecretRotations.Add(1);
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

        var notifications = new List<RevokedTokenNotification>();
        var reasonValue = string.IsNullOrWhiteSpace(reason) ? "session_revoked" : reason!;
        var clientId = s.ClientId;

        // Cascade revoke all linked authorizations (session may be tied to multiple grants)
        var authorizationIds = new HashSet<string>(StringComparer.Ordinal);
        if (!string.IsNullOrWhiteSpace(s.AuthorizationId))
            authorizationIds.Add(s.AuthorizationId!);
        foreach (var link in s.Authorizations)
        {
            if (!string.IsNullOrWhiteSpace(link.AuthorizationId))
                authorizationIds.Add(link.AuthorizationId);
        }

        if (authorizationIds.Count > 0)
        {
            var cascadedTokens = 0;
            foreach (var authId in authorizationIds)
            {
                cascadedTokens += await RevokeByAuthorizationIdAsync(authId, reasonValue, referenceId, clientId, notifications, ct);
            }
            _logger.LogInformation("Revoked session {ReferenceId} with {AuthorizationCount} linked authorizations. Tokens revoked: {TokenCount}", referenceId, authorizationIds.Count, cascadedTokens);
        }
        else
        {
            // Fallback: match tokens by sid in payload (works for self-contained tokens)
            var tokenCount = await RevokeOpenIddictTokensBySidAsync(referenceId, reasonValue, clientId, notifications, ct);
            _logger.LogInformation("Revoked session {ReferenceId} without linked authorizations. Tokens revoked via sid sweep: {TokenCount}", referenceId, tokenCount);
        }

        if (notifications.Count > 0)
        {
            await _revocationPublisher.PublishAsync(notifications, ct);
        }

        SessionsRevoked.Add(1);
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

        if (session.SecretExpiresAt is not null && session.SecretExpiresAt <= DateTime.UtcNow)
            return null;

        if (requireActive && !IsSessionCurrentlyActive(session))
            return null;

        session.LastSeenAt = DateTime.UtcNow;
        await _repo.UpdateAsync(session, ct);
        await _unitOfWork.SaveChangesAsync(ct);

        return new SessionValidationResult(session.Id, session.UserId, session.CreatedAt, session.ExpiresAt, session.Revoked);
    }

    public async Task<string?> GetActiveReferenceByAuthorizationIdAsync(string authorizationId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(authorizationId))
            return null;

        var session = await _repo.GetByAuthorizationIdAsync(authorizationId, ct);
        if (session is null)
            return null;

        return IsSessionCurrentlyActive(session) ? session.ReferenceId : null;
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

    private async Task<int> RevokeOpenIddictTokensBySidAsync(string sid, string reason, string? clientId, List<RevokedTokenNotification> notifications, CancellationToken ct)
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

        var total = refreshRevoked + accessRevoked;

        if (total > 0)
        {
            notifications.Add(new RevokedTokenNotification(
                TokenId: null,
                AuthorizationId: null,
                SessionReferenceId: sid,
                Reason: reason,
                TimestampUtc: DateTime.UtcNow,
                ClientId: clientId,
                TokenCount: total));
        }

        return total;
    }

    private async Task<int> RevokeByAuthorizationIdAsync(
        string authorizationId,
        string reason,
        string sessionReferenceId,
        string? clientId,
        List<RevokedTokenNotification> notifications,
        CancellationToken ct)
    {
        var revokedTokens = 0;
        var authorization = await _authorizationManager.FindByIdAsync(authorizationId, ct);
        if (authorization is not null)
        {
            try { await _authorizationManager.TryRevokeAsync(authorization!, ct); } catch { }
        }

        await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(authorizationId, ct))
        {
            try
            {
                if (await _tokenManager.TryRevokeAsync(token!, ct))
                {
                    revokedTokens++;
                    var tokenId = await _tokenManager.GetIdAsync(token!, ct);
                    notifications.Add(new RevokedTokenNotification(
                        TokenId: tokenId,
                        AuthorizationId: authorizationId,
                        SessionReferenceId: sessionReferenceId,
                        Reason: reason,
                        TimestampUtc: DateTime.UtcNow,
                        ClientId: clientId));
                }
            }
            catch
            {
                // ignore individual token revocation failures
            }
        }

        return revokedTokens;
    }

    public async Task<bool> LinkAuthorizationAsync(string referenceId, string authorizationId, string? clientId = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(referenceId) || string.IsNullOrWhiteSpace(authorizationId))
            return false;

        var session = await _repo.GetByReferenceAsync(referenceId, ct);
        if (session is null) return false;

        var linkedAlready = session.Authorizations.Any(a => string.Equals(a.AuthorizationId, authorizationId, StringComparison.Ordinal));
        var newLink = linkedAlready ? null : new UserSessionAuthorization
        {
            SessionId = session.Id,
            AuthorizationId = authorizationId,
            ClientId = clientId,
            CreatedAt = DateTime.UtcNow
        };

        var touched = false;

        if (string.IsNullOrEmpty(session.AuthorizationId))
        {
            session.AuthorizationId = authorizationId;
            touched = true;
        }

        if (newLink is not null)
        {
            session.Authorizations.Add(newLink);
            _db.UserSessionAuthorizations.Add(newLink);
            touched = true;
        }

        if (!touched)
            return true;

        try
        {
            await _unitOfWork.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            if (newLink is not null)
                _db.Entry(newLink).State = EntityState.Detached;

            var refreshed = await _repo.GetByReferenceAsync(referenceId, ct);
            if (refreshed is not null &&
                (string.Equals(refreshed.AuthorizationId, authorizationId, StringComparison.Ordinal) ||
                 refreshed.Authorizations.Any(a => string.Equals(a.AuthorizationId, authorizationId, StringComparison.Ordinal))))
            {
                return true;
            }

            throw;
        }

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
