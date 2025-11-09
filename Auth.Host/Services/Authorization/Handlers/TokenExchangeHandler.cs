using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Host.ProfileService;
using Auth.Host.Services.Support;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;

namespace Auth.Host.Services.Authorization.Handlers;

public sealed class TokenExchangeHandler
{
    private readonly ISessionService _sessions;
    private readonly SessionBindingService _sessionBinder;
    private readonly IOpenIddictProfileService _profile;
    private readonly UserManager<UserEntity> _userManager;
    private readonly SessionCookieWorkflow _cookieWorkflow;
    private readonly ILogger<TokenExchangeHandler> _logger;

    public TokenExchangeHandler(
        ISessionService sessions,
        SessionBindingService sessionBinder,
        IOpenIddictProfileService profile,
        UserManager<UserEntity> userManager,
        SessionCookieWorkflow cookieWorkflow,
        ILogger<TokenExchangeHandler> logger)
    {
        _sessions = sessions;
        _sessionBinder = sessionBinder;
        _profile = profile;
        _userManager = userManager;
        _cookieWorkflow = cookieWorkflow;
        _logger = logger;
    }

    public async Task<IActionResult> HandleAsync(ControllerBase controller)
    {
        var httpContext = controller.HttpContext ?? throw new InvalidOperationException("HttpContext is unavailable.");
        var request = OpenIddictRequestAccessor.GetRequiredRequest(httpContext);

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("The specified grant type is not supported.");

        var result = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (!result.Succeeded)
        {
            return controller.Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                }));
        }

        var user = await _userManager.FindByIdAsync(result.Principal!.GetClaim(OpenIddictConstants.Claims.Subject));
        if (user is null || !user.IsActive)
        {
            return controller.Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        user is null ? "The token is no longer valid." : "The user is no longer allowed to sign in."
                }));
        }

        var principal = await _profile.CreateAsync(user, request);
        var sid = result.Principal!.GetClaim("sid");
        var originalAuthId = result.Principal!.GetAuthorizationId();

        if (!string.IsNullOrEmpty(originalAuthId))
        {
            principal.SetAuthorizationId(originalAuthId);
            if (!string.IsNullOrEmpty(sid))
                await _sessions.LinkAuthorizationAsync(sid, originalAuthId, request.ClientId);
        }

        if (string.IsNullOrEmpty(sid))
        {
            if (request.IsRefreshTokenGrantType())
            {
                return controller.Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The session context is missing."
                    }));
            }

            await _sessionBinder.AttachInteractiveSessionAsync(httpContext, principal, user, request.ClientId);
            _logger.LogInformation("Bound new interactive session for user {UserId} client {ClientId} during token exchange.", user.Id, request.ClientId);
        }
        else
        {
            StampSessionClaims(result.Principal!, principal, sid);

            var persistedValue = result.Principal!.GetClaim(SessionClaimTypes.Persistence);
            var isPersistentSession = ParsePersistenceClaim(persistedValue);

            if (isPersistentSession)
            {
                var renewed = await _sessions.RefreshBrowserSecretAsync(sid, user.Id);
                if (renewed is null)
                {
                    return controller.Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The session has been revoked."
                        }));
                }

                httpContext.Response.Cookies.Append(
                    SessionCookie.Name,
                    SessionCookie.Pack(renewed.Value.ReferenceId, renewed.Value.BrowserSecret),
                    _cookieWorkflow.BuildCookieOptions(CustomSignInManager.LongSessionLifetime));
            }
        }

        return controller.SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static void StampSessionClaims(ClaimsPrincipal source, ClaimsPrincipal destination, string sid)
    {
        var ci = (ClaimsIdentity)destination.Identity!;
        foreach (var existingSid in ci.FindAll("sid").ToArray())
            ci.RemoveClaim(existingSid);

        var originalSidClaim = source.Claims.FirstOrDefault(c => c.Type == "sid");
        var sidClaim = AuthorizationHandlerUtilities.CloneClaim(originalSidClaim, "sid", sid);
        ci.AddClaim(sidClaim);
        sidClaim.SetDestinations(
            OpenIddictConstants.Destinations.IdentityToken,
            OpenIddictConstants.Destinations.AccessToken,
            "authorization_code",
            "refresh_token");

        foreach (var existingPersistence in ci.FindAll(SessionClaimTypes.Persistence).ToArray())
            ci.RemoveClaim(existingPersistence);

        var persistenceValue = source.GetClaim(SessionClaimTypes.Persistence);
        var isPersistent = ParsePersistenceClaim(persistenceValue);

        var originalPersistenceClaim = source.Claims.FirstOrDefault(c => c.Type == SessionClaimTypes.Persistence);
        var persistenceClaim = AuthorizationHandlerUtilities.CloneClaim(originalPersistenceClaim, SessionClaimTypes.Persistence, isPersistent ? "true" : "false");
        ci.AddClaim(persistenceClaim);
        persistenceClaim.SetDestinations(
            OpenIddictConstants.Destinations.IdentityToken,
            OpenIddictConstants.Destinations.AccessToken,
            "authorization_code",
            "refresh_token");
    }

    private static bool ParsePersistenceClaim(string? value)
        => bool.TryParse(value, out var parsed) ? parsed : true;
}
