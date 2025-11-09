using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Host.Options;
using Auth.Host.Services.Support;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Host.Services.Authorization;

public sealed class SessionCookieWorkflow
{
    private readonly ISessionService _sessions;
    private readonly CustomSignInManager _signInManager;
    private readonly UserManager<UserEntity> _userManager;
    private readonly ILogger<SessionCookieWorkflow> _logger;
    private readonly SessionCookieOptions _options;

    public SessionCookieWorkflow(
        ISessionService sessions,
        CustomSignInManager signInManager,
        UserManager<UserEntity> userManager,
        ILogger<SessionCookieWorkflow> logger,
        IOptions<SessionCookieOptions> options)
    {
        _sessions = sessions;
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
        _options = options.Value ?? new SessionCookieOptions();
    }

    public CookieOptions BuildCookieOptions(TimeSpan lifetime) => new()
    {
        HttpOnly = true,
        Secure = _options.Secure,
        SameSite = _options.SameSite,
        IsEssential = true,
        Domain = string.IsNullOrWhiteSpace(_options.Domain) ? null : _options.Domain,
        Path = string.IsNullOrWhiteSpace(_options.Path) ? "/" : _options.Path,
        Expires = DateTimeOffset.UtcNow.Add(lifetime)
    };

    public void DeleteCookie(HttpContext httpContext)
    {
        if (!httpContext.Request.Cookies.ContainsKey(SessionCookie.Name))
            return;

        httpContext.Response.Cookies.Delete(SessionCookie.Name, new CookieOptions
        {
            Secure = _options.Secure,
            SameSite = _options.SameSite,
            HttpOnly = true,
            Domain = string.IsNullOrWhiteSpace(_options.Domain) ? null : _options.Domain,
            Path = string.IsNullOrWhiteSpace(_options.Path) ? "/" : _options.Path
        });
    }

    public async Task<bool> TryRestoreIdentityAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        if (!httpContext.Request.Cookies.TryGetValue(SessionCookie.Name, out var rawSid) ||
            !SessionCookie.TryUnpack(rawSid, out var reference, out var secret))
        {
            return false;
        }

        var validation = await _sessions.ValidateBrowserSessionAsync(reference, secret, requireActive: true, cancellationToken);
        if (validation is null)
        {
            _logger.LogWarning("Failed to validate sid {Sid} while restoring identity. Clearing cookie.", reference);
            DeleteCookie(httpContext);
            await _signInManager.SignOutAsync();
            return false;
        }

        var user = await _userManager.FindByIdAsync(validation.Value.UserId.ToString());
        if (user is null || !user.IsActive)
        {
            await _sessions.RevokeAsync(reference, reason: "user_missing_or_inactive", by: null, cancellationToken);
            _logger.LogWarning("Revoked sid {Sid} because user {UserId} missing or inactive during restore.", reference, validation.Value.UserId);
            DeleteCookie(httpContext);
            return false;
        }

        var rememberMe = DeterminePersistence(validation.Value);
        await _signInManager.SignInWithSessionPolicyAsync(user, rememberMe);
        _logger.LogInformation("Restored identity from sid {Sid} for user {UserId}. RememberMe={RememberMe}", reference, user.Id, rememberMe);
        return true;
    }

    private static bool DeterminePersistence(SessionValidationResult validation)
    {
        if (validation.ExpiresAt is null) return true;
        var duration = validation.ExpiresAt.Value - validation.CreatedAt;
        return duration >= CustomSignInManager.LongSessionLifetime - TimeSpan.FromMinutes(1);
    }
}
