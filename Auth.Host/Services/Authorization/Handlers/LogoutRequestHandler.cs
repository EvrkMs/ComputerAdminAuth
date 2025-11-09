using Auth.Application.Interfaces;
using Auth.Host.Services.Support;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Auth.Host.Services.Authorization.Handlers;

public sealed class LogoutRequestHandler
{
    private readonly ISessionService _sessions;
    private readonly CustomSignInManager _signInManager;
    private readonly SessionCookieWorkflow _cookieWorkflow;

    public LogoutRequestHandler(
        ISessionService sessions,
        CustomSignInManager signInManager,
        SessionCookieWorkflow cookieWorkflow)
    {
        _sessions = sessions;
        _signInManager = signInManager;
        _cookieWorkflow = cookieWorkflow;
    }

    public async Task<IActionResult> HandleAsync(ControllerBase controller)
    {
        var httpContext = controller.HttpContext ?? throw new InvalidOperationException("HttpContext is unavailable.");
        var request = httpContext.GetOpenIddictServerRequest();

        try
        {
            var oidc = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = oidc?.Principal;
            string? sid = principal?.GetClaim("sid");
            if (string.IsNullOrEmpty(sid) && httpContext.Request.Cookies.TryGetValue(SessionCookie.Name, out var rawSid) &&
                SessionCookie.TryUnpack(rawSid, out var reference, out _))
            {
                sid = reference;
            }
            if (!string.IsNullOrEmpty(sid))
            {
                var by = principal?.GetClaim(OpenIddictConstants.Claims.Subject) ??
                         httpContext.User?.FindFirstValue(OpenIddictConstants.Claims.Subject) ??
                         httpContext.User?.Identity?.Name;
                await _sessions.RevokeAsync(sid!, reason: "logout", by: by);
            }
        }
        catch
        {
            // best effort
        }

        _cookieWorkflow.DeleteCookie(httpContext);

        await _signInManager.SignOutAsync();

        if (!string.IsNullOrEmpty(request?.PostLogoutRedirectUri))
        {
            return controller.SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties { RedirectUri = request.PostLogoutRedirectUri });
        }

        return controller.SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" });
    }
}
