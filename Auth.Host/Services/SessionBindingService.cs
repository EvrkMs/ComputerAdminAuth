using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using System.Security.Claims;

namespace Auth.Host.Services;

/// <summary>
/// Couples browser cookies and OpenIddict grants with our server-side session records.
/// Ensures every interactive login issues an opaque sid reference + a confidential browser secret.
/// </summary>
public sealed class SessionBindingService
{
    private readonly SessionCookieGuard _guard;
    private readonly SessionCookieBinder _binder;

    public SessionBindingService(SessionCookieGuard guard, SessionCookieBinder binder)
    {
        _guard = guard;
        _binder = binder;
    }

    public Task<SessionGuardResult> EnforceCookieSessionOrChallengeAsync(HttpContext http, OpenIddictRequest request)
        => _guard.EnsureCookieSessionOrChallengeAsync(http, request);

    public Task AttachInteractiveSessionAsync(HttpContext http, ClaimsPrincipal principal, UserEntity user, string? clientId)
        => _binder.AttachAsync(http, principal, user, clientId);
}
