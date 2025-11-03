using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Host.Services.Support;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace Auth.Host.Services;

public sealed class SessionCookieGuard
{
    private readonly ISessionService _sessions;
    private readonly SignInManager<UserEntity> _signIn;
    private readonly ILogger<SessionCookieGuard> _logger;

    public SessionCookieGuard(ISessionService sessions, SignInManager<UserEntity> signIn, ILogger<SessionCookieGuard> logger)
    {
        _sessions = sessions;
        _signIn = signIn;
        _logger = logger;
    }

    public async Task<SessionGuardResult> EnsureCookieSessionOrChallengeAsync(HttpContext http, OpenIddictRequest request)
    {
        var principal = (await http.AuthenticateAsync(IdentityConstants.ApplicationScheme)).Principal;
        var sid = principal?.FindFirst("sid")?.Value;

        if (string.IsNullOrEmpty(sid))
            return new SessionGuardResult(true, null);

        var cookieValue = http.Request.Cookies[SessionCookie.Name];
        if (!SessionCookie.TryUnpack(cookieValue, out var cookieReference, out var secret))
        {
            if (!string.IsNullOrWhiteSpace(cookieValue) && !string.IsNullOrEmpty(sid))
            {
                var subject = principal?.FindFirstValue(OpenIddictConstants.Claims.Subject);
                _logger.LogWarning("Malformed session cookie detected for user {UserId}.", subject);
                await _sessions.RevokeAsync(sid, reason: "cookie_malformed", by: subject);
            }

            await ClearSessionAsync(http);
            return await ChallengeAsync(http, request);
        }

        var subjectId = principal?.FindFirstValue(OpenIddictConstants.Claims.Subject);
        if (!string.Equals(cookieReference, sid, StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "Session cookie mismatch detected for user {UserId}: sid claim {SidClaim}, cookie {CookieSid}.",
                subjectId,
                sid,
                cookieReference);

            await _sessions.RevokeAsync(cookieReference, reason: "cookie_mismatch", by: subjectId);
            await _sessions.RevokeAsync(sid, reason: "cookie_mismatch", by: subjectId);
            await ClearSessionAsync(http);
            return await ChallengeAsync(http, request);
        }

        var validation = await _sessions.ValidateBrowserSessionAsync(cookieReference, secret, requireActive: true);
        if (validation is not null)
        {
            http.Items["sid"] = cookieReference;
            return new SessionGuardResult(true, null);
        }

        _logger.LogInformation("Inactive session detected for user {UserId}, sid {Sid}. Forcing reauthentication.", subjectId, cookieReference);
        await _sessions.RevokeAsync(cookieReference, reason: "session_inactive", by: subjectId);
        await ClearSessionAsync(http);
        return await ChallengeAsync(http, request);
    }

    private async Task ClearSessionAsync(HttpContext http)
    {
        if (http.Request.Cookies.ContainsKey(SessionCookie.Name))
        {
            http.Response.Cookies.Delete(SessionCookie.Name, new CookieOptions
            {
                Secure = true,
                SameSite = SameSiteMode.Lax,
                HttpOnly = true,
                Path = "/"
            });
        }

        await _signIn.SignOutAsync();
    }

    private static Task<SessionGuardResult> ChallengeAsync(HttpContext http, OpenIddictRequest request)
    {
        if (request.Prompt == "none")
        {
            var props = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.LoginRequired,
                [OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user must re-authenticate."
            });
            return Task.FromResult(new SessionGuardResult(false,
                new ForbidResult(new[] { OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreDefaults.AuthenticationScheme }, props)));
        }

        var parameters = http.Request.HasFormContentType ? [.. http.Request.Form] : http.Request.Query.ToList();
        var chProps = new AuthenticationProperties
        {
            RedirectUri = http.Request.PathBase + http.Request.Path + QueryString.Create(parameters)
        };
        return Task.FromResult(new SessionGuardResult(false, new ChallengeResult(new[] { IdentityConstants.ApplicationScheme }, chProps)));
    }
}
