using System;

namespace Auth.Application.Interfaces;

public interface ISessionService
{
    /// <summary>
    /// Creates a new persistent interactive session and returns opaque tokens for browser + tokens.
    /// </summary>
    Task<SessionIssueResult> EnsureInteractiveSessionAsync(
        Guid userId,
        string? clientId,
        string? ip,
        string? userAgent,
        string? device,
        TimeSpan? absoluteLifetime,
        CancellationToken ct = default);

    Task<bool> RevokeAsync(string referenceId, string? reason = null, string? by = null, CancellationToken ct = default);
    Task<bool> IsActiveAsync(string referenceId, CancellationToken ct = default);
    Task<bool> LinkAuthorizationAsync(string referenceId, string authorizationId, CancellationToken ct = default);
    Task<SessionIssueResult?> RefreshBrowserSecretAsync(string referenceId, Guid expectedUserId, CancellationToken ct = default);

    /// <summary>
    /// Validates the browser cookie payload and optionally enforces active state.
    /// Returns session metadata when successful, otherwise null.
    /// </summary>
    Task<SessionValidationResult?> ValidateBrowserSessionAsync(string referenceId, string secret, bool requireActive = true, CancellationToken ct = default);
}

public readonly record struct SessionIssueResult(string ReferenceId, string BrowserSecret, DateTime CreatedAt, DateTime? ExpiresAt);
public readonly record struct SessionValidationResult(Guid SessionId, Guid UserId, DateTime CreatedAt, DateTime? ExpiresAt, bool Revoked);
