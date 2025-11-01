using System;
using System.Collections.Generic;
using System.Linq;
using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Host.Services.Support;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace Auth.Host.Services;

public sealed class SessionCookieGuard
{
    private readonly ISessionService _sessions;
    private readonly SignInManager<UserEntity> _signIn;

    public SessionCookieGuard(ISessionService sessions, SignInManager<UserEntity> signIn)
    {
        _sessions = sessions;
        _signIn = signIn;
    }

    public async Task<SessionGuardResult> EnsureCookieSessionOrChallengeAsync(HttpContext http, OpenIddictRequest request)
    {
        var principal = (await http.AuthenticateAsync(IdentityConstants.ApplicationScheme)).Principal;
        var sid = principal?.FindFirst("sid")?.Value;

        if (string.IsNullOrEmpty(sid))
            return new SessionGuardResult(true, null);

        var cookieValue = http.Request.Cookies[SessionCookie.Name];
        if (!SessionCookie.TryUnpack(cookieValue, out var cookieReference, out var secret) ||
            !string.Equals(cookieReference, sid, StringComparison.Ordinal))
        {
            await ClearSessionAsync(http);
            return await ChallengeAsync(http, request);
        }

        var validation = await _sessions.ValidateBrowserSessionAsync(cookieReference, secret, requireActive: true);
        if (validation is not null)
            return new SessionGuardResult(true, null);

        await ClearSessionAsync(http);
        return await ChallengeAsync(http, request);
    }

    private async Task ClearSessionAsync(HttpContext http)
    {
        if (http.Request.Cookies.ContainsKey(SessionCookie.Name))
            http.Response.Cookies.Delete(SessionCookie.Name, new CookieOptions { Secure = true, SameSite = SameSiteMode.Lax });

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
