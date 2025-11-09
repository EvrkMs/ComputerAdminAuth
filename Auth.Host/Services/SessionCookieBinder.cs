using System;
using System.Collections.Generic;
using System.Security.Claims;
using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Host.Extensions;
using Auth.Host.Options;
using Auth.Host.Services.Support;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Auth.Host.Services;

public sealed class SessionCookieBinder
{
    private readonly ISessionService _sessions;
    private readonly SessionCookieOptions _cookieOptions;

    public SessionCookieBinder(ISessionService sessions, IOptions<SessionCookieOptions> cookieOptions)
    {
        _sessions = sessions;
        _cookieOptions = cookieOptions.Value ?? new SessionCookieOptions();
    }

    public async Task AttachAsync(HttpContext http, ClaimsPrincipal principal, UserEntity user, string? clientId)
    {
        var cookieAuth = await http.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        var rememberMe = ResolveRememberMe(cookieAuth);
        var lifetime = rememberMe ? CustomSignInManager.LongSessionLifetime : CustomSignInManager.ShortSessionLifetime;

        var ip = http.GetRealClientIp();
        var ua = http.Request.Headers["User-Agent"].ToString();
        var device = "web";
        var orderedCandidates = new List<string>();
        var knownSids = new HashSet<string>(StringComparer.Ordinal);

        var claimedSid = cookieAuth?.Principal?.FindFirst("sid")?.Value;
        if (!string.IsNullOrEmpty(claimedSid) && knownSids.Add(claimedSid))
            orderedCandidates.Add(claimedSid);

        if (http.Request.Cookies.TryGetValue(SessionCookie.Name, out var rawSid) &&
            SessionCookie.TryUnpack(rawSid, out var cookieReference, out _))
        {
            if (knownSids.Add(cookieReference))
                orderedCandidates.Insert(0, cookieReference);
        }

        SessionIssueResult? reused = null;
        foreach (var candidate in orderedCandidates)
        {
            var refreshed = await _sessions.RefreshBrowserSecretAsync(candidate, user.Id);
            if (refreshed is not null)
            {
                reused = refreshed;
                break;
            }
        }

        SessionIssueResult issued;
        if (reused is not null)
        {
            issued = reused.Value;
        }
        else
        {
            issued = await _sessions.EnsureInteractiveSessionAsync(user.Id, clientId, ip, ua, device, lifetime);

            foreach (var sidToRevoke in knownSids)
            {
                if (!string.Equals(sidToRevoke, issued.ReferenceId, StringComparison.Ordinal))
                {
                    await _sessions.RevokeAsync(sidToRevoke, reason: "superseded", by: user.Id.ToString());
                }
            }
        }

        var sid = issued.ReferenceId;

        var ci = (ClaimsIdentity)principal.Identity!;
        var existingSidClaim = ci.FindFirst("sid");
        if (existingSidClaim is not null) ci.RemoveClaim(existingSidClaim);
        var sidClaim = new Claim("sid", sid);
        sidClaim.SetDestinations(
            OpenIddictConstants.Destinations.IdentityToken,
            OpenIddictConstants.Destinations.AccessToken,
            "authorization_code",
            "refresh_token");
        ci.AddClaim(sidClaim);
        var existingPrincipalPersistence = ci.FindFirst(SessionClaimTypes.Persistence);
        if (existingPrincipalPersistence is not null) ci.RemoveClaim(existingPrincipalPersistence);
        var persistenceClaim = new Claim(SessionClaimTypes.Persistence, rememberMe ? "true" : "false");
        ci.AddClaim(persistenceClaim);
        persistenceClaim.SetDestinations(
            OpenIddictConstants.Destinations.IdentityToken,
            OpenIddictConstants.Destinations.AccessToken,
            "authorization_code",
            "refresh_token");

        var cookieOptions = BuildCookieOptions(lifetime);
        http.Response.Cookies.Append(SessionCookie.Name, SessionCookie.Pack(sid, issued.BrowserSecret), cookieOptions);

        if (cookieAuth?.Succeeded == true && cookieAuth.Principal?.Identity is ClaimsIdentity idCookie)
        {
            var existingSid = idCookie.FindFirst("sid");
            if (existingSid is not null) idCookie.RemoveClaim(existingSid);
            idCookie.AddClaim(new Claim("sid", sid));
            var existingPersistence = idCookie.FindFirst(SessionClaimTypes.Persistence);
            if (existingPersistence is not null) idCookie.RemoveClaim(existingPersistence);
            idCookie.AddClaim(new Claim(SessionClaimTypes.Persistence, rememberMe ? "true" : "false"));
            await http.SignInAsync(IdentityConstants.ApplicationScheme, cookieAuth.Principal, cookieAuth.Properties);
        }
    }

    private static bool ResolveRememberMe(AuthenticateResult? cookieAuth)
    {
        if (cookieAuth?.Properties?.Items is { } items &&
            items.TryGetValue(CustomSignInManager.RememberMePropertyKey, out var raw) &&
            bool.TryParse(raw, out var rememberMe))
        {
            return rememberMe;
        }

        return cookieAuth?.Properties?.IsPersistent ?? true;
    }

    private CookieOptions BuildCookieOptions(TimeSpan lifetime)
    {
        return new CookieOptions
        {
            HttpOnly = true,
            Secure = _cookieOptions.Secure,
            SameSite = _cookieOptions.SameSite,
            IsEssential = true,
            Domain = string.IsNullOrWhiteSpace(_cookieOptions.Domain) ? null : _cookieOptions.Domain,
            Path = string.IsNullOrWhiteSpace(_cookieOptions.Path) ? "/" : _cookieOptions.Path,
            Expires = DateTimeOffset.UtcNow.Add(lifetime)
        };
    }
}
